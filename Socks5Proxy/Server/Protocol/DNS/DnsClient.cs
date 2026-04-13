using Serilog;
using Socks5Proxy.Configuration;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Socks5Proxy.Server.Protocol.DNS;

/// <summary>
/// High-performance, production-ready DNS client.
/// 
/// Key features:
/// - UDP queries with automatic TCP fallback on truncation (RFC compliant)
/// - Supports IPv4 (A) and IPv6 (AAAA) resolution
/// - TTL-based caching with negative caching support
/// - Source IP binding for multi-homed environments
/// - Safe DNS parsing with bounds checking and compression loop protection
/// 
/// Designed for low-latency, high-throughput scenarios such as proxies.
/// </summary>
/// <param name="logger">Logger instance.</param>
/// <param name="dnsServer">DNS server IP address (IPv4 or IPv6).</param>
/// <param name="timeout">Optional per-query timeout (default: 5 seconds).</param>
/// <exception cref="ArgumentException">Thrown if DNS server IP is invalid.</exception>
public sealed class DnsClient(ILogger logger, IPAddress dnsServer, TimeSpan? timeout = null)
{
    // DNS cache (domain -> cached result)
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    private const int MaxCacheSize = 10000;             // Maximum number of cached entries before cache reset
    private const int CacheDropSize = 1000;             // Number of any entries to remove when cache exceeds MaxCacheSize
    private const int MaxCompressionJumps = 20;         // Maximum allowed DNS compression pointer jumps to prevent loops
    private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly IPEndPoint _dnsEndpoint = new(dnsServer, 53);           // Target DNS server endpoint
    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(5); // Per-query timeout
    private readonly byte[] _idBuffer = new byte[2];                         // Reusable buffer for DNS transaction ID generation

    /// <summary>
    /// Resolves a domain name to an IP address (IPv4 or IPv6).
    /// 
    /// Behavior:
    /// - Uses cache if available and not expired
    /// - Queries both A and AAAA records if IPv6 is supported
    /// - Returns the fastest successful result
    /// - Falls back to the other query if the first result is empty
    /// </summary>
    /// <param name="domain">Domain name to resolve.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Resolved <see cref="IPAddress"/> or null if not found.</returns>
    public async Task<IPAddress?> ResolveAsync(string domain, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Domain cannot be empty", nameof(domain));

        domain = domain.Trim().ToLowerInvariant();

        // Try cache
        if (_cache.TryGetValue(domain, out var entry) && entry.Expiry > DateTime.UtcNow)
            return entry.Negative ? null : entry.Address;

        _cache.TryRemove(domain, out _);

        DnsResult result;
        if (NetworkConfiguration.OutputIPv6Available)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

            // Parallel A and AAAA resolution
            var aTask = ResolveTypeAsync(domain, 1, cts.Token);
            var aaaaTask = ResolveTypeAsync(domain, 28, cts.Token);

            // Take the fastest result
            var completed = await Task.WhenAny(aTask, aaaaTask).ConfigureAwait(false);

            result = await completed.ConfigureAwait(false);

            // Fallback to the other query if result is empty
            if (result.Address == null)
            {
                var other = completed == aTask ? aaaaTask : aTask;

                try
                {
                    result = await other.ConfigureAwait(false);
                }
                catch
                {
                    // both task dead
                }
            }
        }
        else
        {
            // IPv6 not supported → only IPv4
            result = await ResolveTypeAsync(domain, 1, ct).ConfigureAwait(false);
        }

        Cache(domain, result);
        return result.Address;
    }

    /// <summary>
    /// Stores DNS result in cache using TTL.
    /// Applies negative caching if address is null.
    /// </summary>
    private void Cache(string domain, DnsResult result)
    {
        if (_cache.Count >= MaxCacheSize)
        {
            foreach (var key in _cache.Keys.Take(CacheDropSize))
                _cache.TryRemove(key, out _);
        }

        int ttl = result.Ttl > 0 ? result.Ttl : 30;

        if (result.Address == null) 
            ttl = 5; // short TTL for negative cache

        _cache[domain] = new CacheEntry(result.Address, DateTime.UtcNow.AddSeconds(ttl), result.Address == null);
    }

    /// <summary>
    /// Resolves a specific DNS record type (A or AAAA).
    /// Uses UDP first, then falls back to TCP if response is truncated.
    /// </summary>
    private async Task<DnsResult> ResolveTypeAsync(string domain, ushort type, CancellationToken ct)
    {
        var result = await QueryUdpAsync(domain, type, ct).ConfigureAwait(false);

        if (result.Truncated)
            result = await QueryTcpAsync(domain, type, ct).ConfigureAwait(false);

        return result;
    }

    /// <summary>
    /// Sends a DNS query over UDP.
    /// Handles timeout, response validation, and parsing.
    /// </summary>
    private async Task<DnsResult> QueryUdpAsync(string domain, ushort type, CancellationToken ct)
    {
        using var socket = new Socket(NetworkConfiguration.OutputInterfaceIP.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(NetworkConfiguration.OutputInterfaceIP, 0));

        ushort id = GenerateId();
        var query = BuildQuery(domain, id, type);

        await socket.SendToAsync(query, SocketFlags.None, _dnsEndpoint, ct).ConfigureAwait(false);

        var buffer = ArrayPool<byte>.Shared.Rent(4096);

        try
        {
            using var timeoutCts = new CancellationTokenSource(_timeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

            var remoteEP = new IPEndPoint(IPAddress.Any, 0);
            var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, remoteEP, linked.Token).ConfigureAwait(false);
            var sender = (IPEndPoint)result.RemoteEndPoint!;

            // Validate response source
            if (!sender.Address.Equals(_dnsEndpoint.Address) || sender.Port != 53)
                return DnsResult.Invalid;

            return ParseResponse(buffer.AsSpan(0, result.ReceivedBytes), id, type);
        }
        catch
        {
            return DnsResult.Invalid;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>
    /// Sends a DNS query over TCP (fallback for truncated UDP responses).
    /// Retries up to 2 times.
    /// </summary>
    private async Task<DnsResult> QueryTcpAsync(string domain, ushort type, CancellationToken ct)
    {
        byte[] lenBytes = ArrayPool<byte>.Shared.Rent(2);

        try
        {
            var localEP = new IPEndPoint(NetworkConfiguration.OutputInterfaceIP, 0);

            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    using var client = new TcpClient(localEP);
                    using var timeoutCts = new CancellationTokenSource(_timeout);
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

                    // Socket options
                    client.Client.ReceiveTimeout = NetworkConfiguration.DnsReceiveTimeout;      // 5 seconds
                    client.Client.SendTimeout = NetworkConfiguration.DnsSendTimeout;            // 5 seconds
                    client.Client.NoDelay = NetworkConfiguration.NoDelay;                       // Disable Nagle's algorithm for better latency
                    client.Client.LingerState = NetworkConfiguration.LingerState;               // RST send

                    await client.ConnectAsync(_dnsEndpoint.Address, 53, linked.Token).ConfigureAwait(false);
                    var stream = client.GetStream();

                    ushort id = GenerateId();
                    var query = BuildQuery(domain, id, type);

                    // Write length-prefixed DNS query
                    WriteUInt16BE(lenBytes, (ushort)query.Length);
                    await stream.WriteAsync(lenBytes.AsMemory(0, 2), linked.Token).ConfigureAwait(false);
                    await stream.WriteAsync(query.AsMemory(0, query.Length), linked.Token).ConfigureAwait(false);

                    // Read response length
                    await stream.ReadExactlyAsync(lenBytes.AsMemory(0, 2), linked.Token).ConfigureAwait(false);
                    int length = ReadUInt16BE(lenBytes);

                    byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
                    try
                    {
                        await stream.ReadExactlyAsync(buffer.AsMemory(0, length), linked.Token).ConfigureAwait(false);
                        return ParseResponse(buffer.AsSpan(0, length), id, type);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                    }
                }
                catch
                {
                    if (attempt == 1)
                        return DnsResult.Invalid;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(lenBytes, clearArray: true);
        }

        return DnsResult.Invalid;
    }

    /// <summary>
    /// Builds a raw DNS query packet.
    /// </summary>
    private static byte[] BuildQuery(string domain, ushort id, ushort type)
    {
        using var ms = new MemoryStream(256);
        using var bw = new BinaryWriter(ms);

        WriteUInt16BE(bw, id);
        WriteUInt16BE(bw, 0x0100);
        WriteUInt16BE(bw, 1);
        WriteUInt16BE(bw, 0);
        WriteUInt16BE(bw, 0);
        WriteUInt16BE(bw, 0);

        foreach (var label in domain.Split('.'))
        {
            if (label.Length is 0 or > 63)
                throw new ArgumentException("Invalid domain label");

            bw.Write((byte)label.Length);
            bw.Write(Encoding.ASCII.GetBytes(label));
        }

        bw.Write((byte)0);
        WriteUInt16BE(bw, type);
        WriteUInt16BE(bw, 1);

        return ms.ToArray();
    }

    /// <summary>
    /// Parses a DNS response and extracts the first matching A or AAAA record.
    /// Applies validation and TTL extraction.
    /// </summary>
    private static DnsResult ParseResponse(ReadOnlySpan<byte> buffer, ushort expectedId, ushort expectedType)
    {
        if (buffer.Length < 12) return DnsResult.Invalid;

        ushort id = ReadUInt16BE(buffer);
        if (id != expectedId) return DnsResult.Invalid;

        ushort flags = ReadUInt16BE(buffer[2..]);
        bool truncated = (flags & 0x0200) != 0;
        int rcode = flags & 0xF;
        if (rcode != 0) return new DnsResult(null, 30, truncated);

        ushort qd = ReadUInt16BE(buffer[4..]);
        ushort an = ReadUInt16BE(buffer[6..]);

        int pos = 12;
        for (int i = 0; i < qd; i++)
            pos = SkipName(buffer, pos) + 4;

        int minTtl = int.MaxValue;

        for (int i = 0; i < an; i++)
        {
            pos = SkipName(buffer, pos);
            if (pos + 10 > buffer.Length) return DnsResult.Invalid;

            ushort type = ReadUInt16BE(buffer[pos..]); pos += 2;
            pos += 2;
            uint ttl = ReadUInt32BE(buffer[pos..]); pos += 4;
            ushort len = ReadUInt16BE(buffer[pos..]); pos += 2;

            if (ttl < minTtl) minTtl = (int)ttl;

            if (type == expectedType)
            {
                if (type == 1 && len == 4)
                    return new DnsResult(new IPAddress(buffer.Slice(pos, 4)), minTtl, truncated);
                if (type == 28 && len == 16)
                    return new DnsResult(new IPAddress(buffer.Slice(pos, 16)), minTtl, truncated);
            }

            pos += len;
        }

        return new DnsResult(null, minTtl == int.MaxValue ? 30 : minTtl, truncated);
    }

    /// <summary>
    /// Skips a DNS name (with compression support).
    /// Protects against infinite compression loops.
    /// </summary>
    private static int SkipName(ReadOnlySpan<byte> buffer, int pos)
    {
        int jumps = 0;

        while (true)
        {
            if (pos >= buffer.Length)
                throw new InvalidDataException("Invalid DNS name.");

            byte len = buffer[pos];

            if (len == 0) return pos + 1;

            if ((len & 0xC0) == 0xC0)
            {
                if (++jumps > MaxCompressionJumps)
                    throw new InvalidDataException("Compression loop detected.");
                return pos + 2;
            }

            pos += len + 1;
        }
    }

    /// <summary>
    /// Generates a random DNS transaction ID.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ushort GenerateId()
    {
        RandomNumberGenerator.Fill(_idBuffer);
        return ReadUInt16BE(_idBuffer);
    }

    /// <summary>
    /// Reads UInt16 in big-endian format.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ushort ReadUInt16BE(ReadOnlySpan<byte> buf)
    {
        return (ushort)(buf[0] << 8 | buf[1]);
    }

    /// <summary>
    /// Reads UInt32 in big-endian format.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReadUInt32BE(ReadOnlySpan<byte> buffer)
    {
        return (uint)buffer[0] << 24 | (uint)buffer[1] << 16 | (uint)buffer[2] << 8 | buffer[3];
    }

    /// <summary>
    /// Writes UInt16 using BinaryWriter in big-endian format.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteUInt16BE(byte[] buffer, int val)
    {
        if (buffer.Length < 2)
            throw new ArgumentException("Buffer too small.", nameof(buffer));

        buffer[0] = (byte)(val >> 8);
        buffer[1] = (byte)(val & 0xFF);
    }

    /// <summary>
    /// Writes UInt16 using BinaryWriter in big-endian format.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteUInt16BE(BinaryWriter bw, ushort val)
    {
        bw.Write((byte)(val >> 8));
        bw.Write((byte)(val & 0xFF));
    }
}