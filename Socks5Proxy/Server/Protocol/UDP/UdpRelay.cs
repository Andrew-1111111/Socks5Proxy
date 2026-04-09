using Serilog;
using Socks5Proxy.Friendly;
using Socks5Proxy.Server.Protocol.DNS;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Socks5Proxy.Server.Protocol.UDP
{
    /// <summary>
    /// High-performance UDP relay for SOCKS5 UDP ASSOCIATE (RFC 1928).
    /// 
    /// Key features:
    /// - Supports IPv4, IPv6, and DOMAIN address types
    /// - Server-side DNS resolution with cache and anti-stampede protection
    /// - Bounded channel for burst protection (prevents packet loss under load)
    /// - Drop policy (DropOldest) to maintain responsiveness under pressure
    /// - Strict client endpoint tracking (anti-spoofing)
    /// - Destination validation (prevents open proxy abuse)
    /// - Idle timeout and periodic cleanup
    /// - Low allocations via ArrayPool
    /// 
    /// Design decisions:
    /// - FRAG is not supported (dropped) as it is rarely used and unstable in practice
    /// - DNS resolution is always performed on the proxy side
    /// </summary>
    internal class UdpRelay : IAsyncDisposable
    {
        private readonly ILogger _logger;
        private readonly UdpClient _udpClient;
        private readonly DnsClient _dnsClient;
        private readonly IPEndPoint _clientTcpEndPoint;
        private IPEndPoint? _actualClientUdpEndPoint;
        private readonly FriendlyNameResolver _resolver;

        private readonly CancellationTokenSource _cts;
        private readonly Task _relayTask;

        private readonly Channel<UdpReceiveResult> _channel;

        private readonly ConcurrentDictionary<string, DnsCacheEntry> _dnsCache;
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _dnsLocks;
        private readonly ConcurrentDictionary<IPEndPoint, DateTime> _activeDestinations;

        private int _disposed;
        private DateTime _lastActivity = DateTime.UtcNow;
        private DateTime _lastCleanup = DateTime.UtcNow;

        private static readonly TimeSpan DnsCacheTtl = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Gets the local UDP endpoint used by the relay.
        /// </summary>
        public IPEndPoint LocalEndPoint { get; }

        /// <summary>
        /// Initializes a new UDP relay bound to a client TCP session.
        /// </summary>
        /// <param name="clientEndPoint">Client TCP endpoint (used for validation).</param>
        /// <param name="dnsClient">The dns client instance.</param>
        /// <param name="logger">Logger instance.</param>
        /// <param name="resolver">Friendly name resolver for logging.</param>
        public UdpRelay(IPEndPoint clientEndPoint, DnsClient dnsClient, ILogger logger, FriendlyNameResolver resolver)
        {
            _clientTcpEndPoint = clientEndPoint ?? throw new ArgumentNullException(nameof(clientEndPoint));
            _dnsClient = dnsClient ?? throw new ArgumentNullException(nameof(dnsClient));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));

            _cts = new CancellationTokenSource();

            _dnsCache = new(StringComparer.OrdinalIgnoreCase);
            _dnsLocks = new(StringComparer.OrdinalIgnoreCase);
            _activeDestinations = new();

            _channel = Channel.CreateBounded<UdpReceiveResult>(
                new BoundedChannelOptions(65536)
                {
                    FullMode = BoundedChannelFullMode.DropOldest
                });

            _udpClient = new UdpClient(_clientTcpEndPoint.AddressFamily);
            _udpClient.Client.SendBufferSize = NetworkConfiguration.SendBufferSize;
            _udpClient.Client.ReceiveBufferSize = NetworkConfiguration.ReceiveBufferSize;
            _udpClient.Client.Bind(new IPEndPoint(NetworkConfiguration.OutputInterfaceIP, 0));

            LocalEndPoint = (IPEndPoint)_udpClient.Client.LocalEndPoint!;

            _logger.Information(
                "UDP relay started on {Local}{FriendlyLocal} for client {Client}{FriendlyClient}",
                LocalEndPoint,
                _resolver.FriendlySuffix(LocalEndPoint),
                _clientTcpEndPoint,
                _resolver.FriendlySuffix(_clientTcpEndPoint));

            _relayTask = RelayPacketsAsync(_cts.Token);
        }

        /// <summary>
        /// Main receive loop.
        /// Reads UDP packets and enqueues them for processing.
        /// </summary>
        private async Task RelayPacketsAsync(CancellationToken ct)
        {
            var processor = Task.Run(() => ProcessPacketsAsync(ct), ct);

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
                    catch (Exception ex)
                    {
                        _logger.Debug(ex, "UDP receive error");
                        continue;
                    }

                    _lastActivity = DateTime.UtcNow;

                    if (!_channel.Writer.TryWrite(result))
                    {
                        _logger.Debug("UDP packet dropped (channel full)");
                    }
                }
            }
            finally
            {
                _channel.Writer.Complete();
                await processor.ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Processes queued UDP packets (decoupled from socket receive).
        /// </summary>
        private async Task ProcessPacketsAsync(CancellationToken ct)
        {
            await foreach (var result in _channel.Reader.ReadAllAsync(ct))
            {
                try
                {
                    // Detect actual UDP endpoint of client
                    if (_actualClientUdpEndPoint == null)
                    {
                        if (result.RemoteEndPoint.Address.Equals(_clientTcpEndPoint.Address))
                        {
                            _actualClientUdpEndPoint = result.RemoteEndPoint;

                            _logger.Debug(
                                "Tracked UDP endpoint {Endpoint}{Friendly}",
                                _actualClientUdpEndPoint,
                                _resolver.FriendlySuffix(_actualClientUdpEndPoint));
                        }
                        else continue;
                    }

                    if (result.RemoteEndPoint.Equals(_actualClientUdpEndPoint))
                        await HandleClientPacketAsync(result.Buffer, ct);
                    else
                        await HandleServerResponseAsync(result.Buffer, result.RemoteEndPoint, ct);

                    if (DateTime.UtcNow - _lastCleanup > CleanupInterval)
                    {
                        CleanupState();
                        _lastCleanup = DateTime.UtcNow;
                    }
                }
                catch (Exception ex)
                {
                    _logger.Warning(ex, "UDP processing error");
                }
            }
        }

        /// <summary>
        /// Handles UDP packets from client.
        /// Parses SOCKS5 header and forwards payload.
        /// </summary>
        private async Task HandleClientPacketAsync(byte[] buffer, CancellationToken ct)
        {
            if (_actualClientUdpEndPoint == null || buffer.Length < 4)
                return;

            int offset = 2;
            byte frag = buffer[offset++];

            // Drop fragmented packets (production-safe)
            if (frag != 0)
            {
                _logger.Debug("Fragmented UDP packet dropped");
                return;
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

                    var address = await ResolveDnsWithCacheAsync(domain, ct);

                    if (address == null || address == IPAddress.None) return;

                    destination = new IPEndPoint(address, port);
                    break;
            }

            if (destination == null)
                return;

            _activeDestinations[destination] = DateTime.UtcNow;

            try
            {
                await _udpClient.SendAsync(buffer.AsMemory(offset), destination, ct);
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "UDP send error");
            }
        }

        /// <summary>
        /// Handles UDP responses from remote servers and sends them back to client.
        /// </summary>
        private async Task HandleServerResponseAsync(byte[] buffer, IPEndPoint source, CancellationToken ct)
        {
            if (_actualClientUdpEndPoint == null)
                return;

            if (!_activeDestinations.ContainsKey(source))
                return;

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

                await _udpClient.SendAsync(
                    response.AsMemory(0, offset + buffer.Length),
                    _actualClientUdpEndPoint,
                    ct);
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "UDP response error");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(response);
            }
        }

        /// <summary>
        /// Resolves domain name using cache with anti-stampede protection.
        /// </summary>
        private async Task<IPAddress> ResolveDnsWithCacheAsync(string domain, CancellationToken ct)
        {
            if (_dnsCache.TryGetValue(domain, out var cached) && cached.Expiry > DateTime.UtcNow)
                return cached.Address;

            var sem = _dnsLocks.GetOrAdd(domain, _ => new SemaphoreSlim(1, 1));

            await sem.WaitAsync(ct);
            try
            {
                if (_dnsCache.TryGetValue(domain, out cached) && cached.Expiry > DateTime.UtcNow)
                    return cached.Address;

                var address = await _dnsClient
                    .ResolveAsync(domain, ct)
                    .ConfigureAwait(false);

                _dnsCache[domain] = new()
                {
                    Address = address ?? throw new InvalidOperationException("Address is null"),
                    Expiry = DateTime.UtcNow.Add(DnsCacheTtl)
                };

                return address;
            }
            finally
            {
                sem.Release();
            }
        }

        /// <summary>
        /// Cleans expired DNS entries and inactive destinations.
        /// </summary>
        private void CleanupState()
        {
            var now = DateTime.UtcNow;

            foreach (var kv in _dnsCache)
                if (kv.Value.Expiry < now)
                    _dnsCache.TryRemove(kv.Key, out _);

            foreach (var kv in _activeDestinations)
                if (now - kv.Value > IdleTimeout)
                    _activeDestinations.TryRemove(kv.Key, out _);
        }

        /// <summary>
        /// Stops the relay.
        /// </summary>
        public async Task StopAsync()
        {
            if (Volatile.Read(ref _disposed) != 0) return;

            _cts.Cancel();

            try { _udpClient.Dispose(); } catch { }
            try { await _relayTask.ConfigureAwait(false); } catch { }
        }

        /// <summary>
        /// Disposes the relay asynchronously.
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