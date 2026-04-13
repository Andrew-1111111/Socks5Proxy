using Serilog;
using Socks5Proxy.Configuration;
using Socks5Proxy.Friendly;
using Socks5Proxy.Server.Protocol;
using Socks5Proxy.Server.Protocol.DNS;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Socks5Proxy.Server;

/// <summary>
/// SOCKS5 proxy server that handles incoming client connections.
/// </summary>
/// <param name="logger">The logger instance.</param>
/// <param name="resolver">The friendly name resolver.</param>
internal class ProxyServer(ILogger logger, FriendlyNameResolver resolver) : IAsyncDisposable
{
    private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly FriendlyNameResolver _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
    private TcpListener? _listener;
    private readonly DnsClient _dnsClient = new(logger, NetworkConfiguration.DnsServer);
    private readonly ConcurrentDictionary<int, ConnectionHandler> _activeConnections = new();
    private readonly ConcurrentDictionary<int, Task> _connectionTasks = new();
    private int _connectionIdCounter;
    private int _disposed;

    /// <summary>
    /// Starts the SOCKS5 proxy server.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop the server.</param>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            _listener = new TcpListener(NetworkConfiguration.ListenIPAddress, NetworkConfiguration.ListenPort);
            _listener.Start();

            var localEndPoint = _listener.LocalEndpoint;
            _logger.Information("SOCKS5 proxy server started on: {LocalEndPoint}{Friendly}", localEndPoint,
                _resolver.FriendlySuffix(localEndPoint));

            logger.Information($"------------------------------------------------");

            // Register cancellation callback to stop the listener
            using var registration = cancellationToken.Register(() =>
            {
                try
                {
                    _listener?.Stop();
                }
                catch (Exception ex)
                {
                    _logger.Warning(ex, "Error stopping listener during cancellation");
                }
            });

            // Accept connections loop
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Check max connection limit
                    if (NetworkConfiguration.MaxConnections > 0 && _activeConnections.Count >= NetworkConfiguration.MaxConnections)
                    {
                        _logger.Warning("Max connections ({MaxConnections}) reached, waiting before accepting new connections", 
                            NetworkConfiguration.MaxConnections);
                        await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    // Get TCP client
                    var tcpClient = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);

                    // Handle client connection in background task
                    var connectionId = Interlocked.Increment(ref _connectionIdCounter);
                    var task = Task.Run(async () => 
                        await HandleClientConnectionAsync(tcpClient, connectionId, cancellationToken).ConfigureAwait(false),
                        cancellationToken);
                    _connectionTasks[connectionId] = task;
                }
                catch (OperationCanceledException)
                {
                    // Cancellation requested, exit gracefully
                    break;
                }
                catch (ObjectDisposedException)
                {
                    // Listener has been disposed, exit gracefully
                    break;
                }
                catch (InvalidOperationException)
                {
                    // Listener is not started or has been stopped
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)
                {
                    // Server was stopped, exit gracefully
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error accepting client connection");
                    
                    // Brief delay to prevent tight loop on persistent errors
                    try
                    {
                        await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Fatal error in SOCKS5 proxy server");
            throw;
        }
        finally
        {
            await StopAsync().ConfigureAwait(false);
            _logger.Information("SOCKS5 proxy server stopped");
        }
    }

    /// <summary>
    /// Handles an individual client connection.
    /// </summary>
    /// <param name="tcpClient">The connected TCP client.</param>
    /// <param name="connectionId">The unique connection identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task HandleClientConnectionAsync(TcpClient tcpClient, int connectionId, CancellationToken cancellationToken)
    {
        var clientEndPointObj = tcpClient.Client.RemoteEndPoint;
        var clientEndPoint = clientEndPointObj?.ToString() ?? "Unknown";
        var friendlyClientSuffix = _resolver.FriendlySuffix(clientEndPointObj);
        ConnectionHandler? handler = null;

        try
        {
            // Socket options
            tcpClient.ReceiveTimeout = NetworkConfiguration.ReceiveTimeout;         // 30 seconds
            tcpClient.SendTimeout = NetworkConfiguration.SendTimeout;               // 30 seconds
            tcpClient.SendBufferSize = NetworkConfiguration.SendBufferSize;         // Send buffer size
            tcpClient.ReceiveBufferSize = NetworkConfiguration.ReceiveBufferSize;   // Receive buffer size
            tcpClient.NoDelay = NetworkConfiguration.NoDelay;                       // Disable Nagle's algorithm for better latency
            tcpClient.LingerState = NetworkConfiguration.LingerState;               // RST send

            handler = new ConnectionHandler(tcpClient, _dnsClient, _logger, _resolver);

            // Add to active connections using ConcurrentDictionary
            _activeConnections.TryAdd(connectionId, handler);

            _logger.Debug(
                "Added connection handler for client {ClientEndPoint}{Friendly}, total active: {ActiveCount}",
                clientEndPoint,
                friendlyClientSuffix,
                _activeConnections.Count);

            // Handle the connection
            await handler.HandleConnectionAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling client connection from {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
        }
        finally
        {
            // Remove from active connections and dispose
            if (handler != null)
            {
                _activeConnections.TryRemove(connectionId, out _);

                try
                {
                    await handler.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error disposing connection handler for {ClientEndPoint}", clientEndPoint);
                }

                _logger.Debug(
                    "Removed connection handler for client {ClientEndPoint}{Friendly}, total active: {ActiveCount}",
                    clientEndPoint,
                    friendlyClientSuffix,
                    _activeConnections.Count);
            }

            // Remove task tracking entry
            _connectionTasks.TryRemove(connectionId, out _);

            // Ensure client is properly closed
            try
            {
                tcpClient.Close();
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Error closing TCP client for {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
            }
        }
    }

    /// <summary>
    /// Stops the SOCKS5 proxy server and closes all active connections.
    /// </summary>
    public async Task StopAsync()
    {
        if (Volatile.Read(ref _disposed) != 0)
            return;

        try
        {
            // Stop accepting new connections
            _listener?.Stop();

            // Wait for active connection tasks to complete (they clean up after themselves)
            var tasks = _connectionTasks.Values.ToArray();
            _logger.Information("Waiting for {Count} active connections to finish", tasks.Length);

            try
            {
                await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _logger.Warning("Some connections did not close gracefully within timeout");
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error while waiting for connections to close");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during server shutdown");
        }
    }

    /// <summary>
    /// Gets the current number of active connections.
    /// </summary>
    public int ActiveConnectionCount => _activeConnections.Count;

    /// <summary>
    /// Asynchronously disposes the server and all its resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        try
        {
            await StopAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during async disposal");
        }

        GC.SuppressFinalize(this);
    }
}