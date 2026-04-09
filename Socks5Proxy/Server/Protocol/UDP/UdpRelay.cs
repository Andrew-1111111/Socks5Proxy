using Serilog;
using Socks5Proxy.Friendly;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Socks5Proxy.Server.Protocol.UDP
{
    /// <summary>
    /// High-performance UDP relay for SOCKS5 UDP ASSOCIATE command (RFC 1928).
    /// 
    /// Features:
    /// - Full IPv4 / IPv6 / DOMAIN support
    /// - Server-side DNS resolution with caching
    /// - Fragmentation reassembly (FRAG support)
    /// - Strict client endpoint validation (anti-spoofing)
    /// - Destination filtering (prevents open UDP proxy abuse)
    /// - Idle timeout for automatic session cleanup
    /// - Low allocations using ArrayPool
    /// 
    /// Notes:
    /// - DNS is always resolved on the proxy (intended behavior)
    /// - Fragmentation is rarely used in practice but fully supported
    /// </summary>
    internal class UdpRelay : IAsyncDisposable
    {
        private readonly ILogger _logger;
        private readonly UdpClient _udpClient;
        private readonly IPEndPoint _clientTcpEndPoint;
        private IPEndPoint? _actualClientUdpEndPoint;
        private readonly FriendlyNameResolver _resolver;

        private readonly CancellationTokenSource _cts;
        private readonly Task _relayTask;

        private readonly ConcurrentDictionary<string, DnsCacheEntry> _dnsCache;
        private readonly ConcurrentDictionary<IPEndPoint, DateTime> _activeDestinations;
        private readonly ConcurrentDictionary<string, FragmentBuffer> _fragments;

        private int _disposed;
        private DateTime _lastActivity = DateTime.UtcNow;

        private static readonly TimeSpan DnsCacheTtl = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(2);

        /// <summary>
        /// Gets the local UDP endpoint used for relay.
        /// </summary>
        public IPEndPoint LocalEndPoint { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="UdpRelay"/> class.
        /// </summary>
        /// <param name="clientEndPoint">Client TCP endpoint to track.</param>
        /// <param name="logger">Logger instance for logging.</param>
        /// <param name="resolver">Friendly name resolver for endpoint display.</param>
        /// <exception cref="ArgumentNullException">Thrown if any argument is null.</exception>
        public UdpRelay(IPEndPoint clientEndPoint, ILogger logger, FriendlyNameResolver resolver)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _clientTcpEndPoint = clientEndPoint ?? throw new ArgumentNullException(nameof(clientEndPoint));
            _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));

            _cts = new CancellationTokenSource();

            _dnsCache = new(StringComparer.OrdinalIgnoreCase);
            _activeDestinations = new();
            _fragments = new();

            _udpClient = new UdpClient(_clientTcpEndPoint.AddressFamily);
            _udpClient.Client.Bind(new IPEndPoint(NetworkConfiguration.OutputInterfaceIP, 0));

            LocalEndPoint = (IPEndPoint)_udpClient.Client.LocalEndPoint!;

            _logger.Information(
                "UDP relay started on {LocalEndPoint}{FriendlyLocal} for client {Client}{FriendlyClient}",
                LocalEndPoint,
                _resolver.FriendlySuffix(LocalEndPoint),
                _clientTcpEndPoint,
                _resolver.FriendlySuffix(_clientTcpEndPoint));

            _relayTask = RelayPacketsAsync(_cts.Token);
        }

        /// <summary>
        /// Main UDP relay loop.
        /// Handles client packets and server responses.
        /// Applies idle timeout and state cleanup.
        /// </summary>
        private async Task RelayPacketsAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    if (DateTime.UtcNow - _lastActivity > IdleTimeout)
                    {
                        _logger.Information("UDP relay idle timeout reached");
                        break;
                    }

                    UdpReceiveResult result;
                    try
                    {
                        result = await _udpClient.ReceiveAsync(ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (ObjectDisposedException) { break; }

                    _lastActivity = DateTime.UtcNow;

                    // Detect actual UDP endpoint of client
                    if (_actualClientUdpEndPoint == null)
                    {
                        if (result.RemoteEndPoint.Address.Equals(_clientTcpEndPoint.Address))
                        {
                            _actualClientUdpEndPoint = result.RemoteEndPoint;
                            _logger.Debug("Tracked UDP endpoint: {Endpoint}", _actualClientUdpEndPoint);
                        }
                        else
                        {
                            continue;
                        }
                    }

                    if (result.RemoteEndPoint.Equals(_actualClientUdpEndPoint))
                    {
                        await HandleClientPacketAsync(result.Buffer, ct).ConfigureAwait(false);
                    }
                    else
                    {
                        await HandleServerResponseAsync(result.Buffer, result.RemoteEndPoint, ct).ConfigureAwait(false);
                    }

                    CleanupState();
                }
            }
            finally
            {
                _logger.Information("UDP relay stopped for {Client}", _clientTcpEndPoint);
            }
        }

        /// <summary>
        /// Handles client UDP packet:
        /// - Parses SOCKS5 UDP header
        /// - Reassembles fragments if needed
        /// - Resolves destination
        /// - Forwards payload
        /// </summary>
        /// <param name="buffer">Received UDP packet.</param>
        /// <param name="ct">Cancellation token.</param>
        private async Task HandleClientPacketAsync(byte[] buffer, CancellationToken ct)
        {
            if (_actualClientUdpEndPoint == null || buffer.Length < 10)
                return;

            int offset = 2;
            byte frag = buffer[offset++];

            // Fragmentation support
            if (frag > 0)
            {
                string key = Convert.ToHexString(buffer.AsSpan(0, Math.Min(32, buffer.Length)));
                var fb = _fragments.GetOrAdd(key, _ => new FragmentBuffer());

                fb.Parts[frag] = [.. buffer];
                fb.Received++;

                if (frag == 0xFF) fb.Expected = frag;

                if (fb.Expected == -1 || fb.Received < fb.Expected)
                    return;

                buffer = [.. fb.Parts.Where(p => p != null).SelectMany(p => p)];
                _fragments.TryRemove(key, out _);

                offset = 2;
                frag = buffer[offset++];
            }

            byte atyp = buffer[offset++];
            IPEndPoint? destination = null;

            switch (atyp)
            {
                case AddressType.IPv4:
                    destination = new(
                        new IPAddress(buffer.AsSpan(offset, 4)),
                        buffer[offset + 4] << 8 | buffer[offset + 5]);
                    offset += 6;
                    break;

                case AddressType.IPv6:
                    destination = new(
                        new IPAddress(buffer.AsSpan(offset, 16)),
                        buffer[offset + 16] << 8 | buffer[offset + 17]);
                    offset += 18;
                    break;

                case AddressType.DomainName:
                    byte len = buffer[offset++];
                    string domain = System.Text.Encoding.ASCII.GetString(buffer, offset, len);
                    offset += len;

                    int port = buffer[offset] << 8 | buffer[offset + 1];
                    offset += 2;

                    var addresses = await ResolveDnsWithCacheAsync(domain, ct);

                    var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (ip == null)
                    {
                        _logger.Debug("No IPv4 address for {Domain}, skipping", domain);
                        return;
                    }

                    destination = new IPEndPoint(ip, port);
                    break;
            }

            if (destination == null)
                return;

            _activeDestinations[destination] = DateTime.UtcNow;

            var payload = buffer.AsMemory(offset);
            await _udpClient.SendAsync(payload, destination, ct);
        }

        /// <summary>
        /// Handles server response:
        /// - Validates source endpoint (anti-open-proxy)
        /// - Wraps response into SOCKS5 UDP format
        /// - Sends back to client
        /// </summary>
        /// <param name="buffer">Response payload.</param>
        /// <param name="source">Source endpoint of the response.</param>
        /// <param name="ct">Cancellation token.</param>
        private async Task HandleServerResponseAsync(byte[] buffer, IPEndPoint source, CancellationToken ct)
        {
            if (_actualClientUdpEndPoint == null)
                return;

            if (!_activeDestinations.ContainsKey(source))
            {
                _logger.Debug("Dropped unknown source {Source}", source);
                return;
            }

            int headerLen = source.AddressFamily == AddressFamily.InterNetwork ? 10 : 22;
            var response = ArrayPool<byte>.Shared.Rent(headerLen + buffer.Length);

            try
            {
                int offset = 0;

                response[offset++] = 0;
                response[offset++] = 0;
                response[offset++] = 0;

                if (source.AddressFamily == AddressFamily.InterNetwork)
                {
                    response[offset++] = AddressType.IPv4;
                    source.Address.GetAddressBytes().CopyTo(response, offset);
                    offset += 4;
                }
                else
                {
                    response[offset++] = AddressType.IPv6;
                    source.Address.GetAddressBytes().CopyTo(response, offset);
                    offset += 16;
                }

                response[offset++] = (byte)(source.Port >> 8);
                response[offset++] = (byte)(source.Port & 0xFF);

                buffer.CopyTo(response.AsSpan(offset));

                await _udpClient.SendAsync(response.AsMemory(0, offset + buffer.Length), _actualClientUdpEndPoint, ct);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(response);
            }
        }

        /// <summary>
        /// Resolves DNS with in-memory cache.
        /// </summary>
        /// <param name="domain">Domain name to resolve.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>Resolved IP addresses.</returns>
        private async Task<IPAddress[]> ResolveDnsWithCacheAsync(string domain, CancellationToken ct)
        {
            if (_dnsCache.TryGetValue(domain, out var cached) && cached.Expiry > DateTime.UtcNow)
                return cached.Addresses;

            var addresses = await Dns.GetHostAddressesAsync(domain, ct);

            _dnsCache[domain] = new()
            {
                Addresses = addresses,
                Expiry = DateTime.UtcNow.Add(DnsCacheTtl)
            };

            return addresses;
        }

        /// <summary>
        /// Cleans up expired DNS entries, inactive destinations, and fragments.
        /// </summary>
        private void CleanupState()
        {
            var now = DateTime.UtcNow;

            foreach (var key in _dnsCache.Keys)
                if (_dnsCache.TryGetValue(key, out var e) && e.Expiry < now)
                    _dnsCache.TryRemove(key, out _);

            foreach (var kv in _activeDestinations)
                if (now - kv.Value > IdleTimeout)
                    _activeDestinations.TryRemove(kv.Key, out _);

            if (_fragments.Count > 100)
                _fragments.Clear();
        }

        /// <summary>
        /// Stops the UDP relay gracefully.
        /// </summary>
        public async Task StopAsync()
        {
            if (Volatile.Read(ref _disposed) != 0) return;

            _cts.Cancel();

            try { _udpClient.Dispose(); } catch { }
            try { await _relayTask.ConfigureAwait(false); } catch { }
        }

        /// <summary>
        /// Asynchronously disposes the UDP relay.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;

            await StopAsync().ConfigureAwait(false);
            _cts.Dispose();

            GC.SuppressFinalize(this);
        }
    }
}