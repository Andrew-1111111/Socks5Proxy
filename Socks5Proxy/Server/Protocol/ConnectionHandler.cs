using Serilog;
using Socks5Proxy.Friendly;
using Socks5Proxy.Server.Protocol.Autentification;
using Socks5Proxy.Server.Protocol.DNS;
using Socks5Proxy.Server.Protocol.UDP;
using System;
using System.Buffers;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Socks5Proxy.Server.Protocol;

/// <summary>
/// Handles individual client connections for the SOCKS5 proxy server.
/// </summary>
internal class ConnectionHandler : IAsyncDisposable
{
    private readonly TcpClient _client;
    private readonly DnsClient _dnsClient;
    private readonly ILogger _logger;
    private readonly NetworkStream _clientStream;
    private readonly FriendlyNameResolver _resolver;
    private TcpClient? _destinationClient;
    private NetworkStream? _destinationStream;
    private UdpRelay? _udpRelay;
    private int _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConnectionHandler"/> class.
    /// </summary>
    /// <param name="client">The connected TCP client.</param>
    /// <param name="dnsClient">The dns client instance.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="resolver">The friendly name resolver for log formatting.</param>
    public ConnectionHandler(TcpClient client, DnsClient dnsClient, ILogger logger, FriendlyNameResolver resolver)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _dnsClient = dnsClient ?? throw new ArgumentNullException(nameof(dnsClient)); 
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _clientStream = _client.GetStream();
    }

    /// <summary>
    /// Handles the complete SOCKS5 connection flow.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token to stop processing.</param>
    public async Task HandleConnectionAsync(CancellationToken cancellationToken)
    {
        var clientEpObj = _client.Client.RemoteEndPoint;
        var clientEndPoint = clientEpObj?.ToString() ?? "Unknown";
        var friendlyClientSuffix = _resolver.FriendlySuffix(clientEpObj);

        try
        {
            _logger.Information("New client connection from {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);

            // Use a timeout for the handshake and request phases to prevent slowloris attacks
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(NetworkConfiguration.IdleTimeout);

            // Step 1: SOCKS5 handshake + Autentification
            if (!await PerformHandshakeAsync(handshakeCts.Token).ConfigureAwait(false))
            {
                _logger.Warning("Handshake failed for client {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
                return;
            }

            // Step 2: Handle SOCKS5 request
            if (!await HandleSocks5RequestAsync(handshakeCts.Token).ConfigureAwait(false))
            {
                _logger.Warning("SOCKS5 request handling failed for client {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
                return;
            }

            // Step 3: Data forwarding (only for CONNECT command)
            if (_destinationClient != null && _destinationStream != null)
            {
                await ForwardDataAsync(cancellationToken).ConfigureAwait(false);
            }
            else if (_udpRelay != null)
            {
                // For UDP ASSOCIATE, keep the TCP connection alive until client disconnects
                await WaitForClientDisconnectionAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling connection from {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
        }
        finally
        {
            _logger.Information("Connection closed for client {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
        }
    }

    /// <summary>
    /// Performs the SOCKS5 handshake with the client.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if handshake was successful, otherwise false.</returns>
    private async Task<bool> PerformHandshakeAsync(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(255);
        try
        {
            // Read client's method selection message - need at least 2 bytes for version and method count
            var totalRead = 0;
            while (totalRead < 2)
            {
                var bytesRead = await _clientStream.ReadAsync(buffer.AsMemory(totalRead, 2 - totalRead), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    _logger.Warning("Connection closed during handshake.");
                    return false;
                }
                totalRead += bytesRead;
            }

            // Validate SOCKS version
            if (buffer[0] != Socks5Protocol.Version)
            {
                _logger.Warning("Unsupported SOCKS version: {Version}.", buffer[0]);
                return false;
            }

            byte methodCount = buffer[1];
            if (methodCount == 0)
            {
                _logger.Warning("No authentication methods provided.");
                return false;
            }

            // Read remaining method bytes
            while (totalRead < 2 + methodCount)
            {
                var bytesRead = await _clientStream
                    .ReadAsync(buffer.AsMemory(totalRead, 2 + methodCount - totalRead), cancellationToken)
                    .ConfigureAwait(false);

                if (bytesRead == 0)
                {
                    _logger.Warning("Connection closed during handshake while reading methods.");
                    return false;
                }

                totalRead += bytesRead;
            }

            // Select server autentification method
            var authMethod = AuthMethod.NoAcceptableMethods;

            bool hasCredentials =
                !string.IsNullOrWhiteSpace(NetworkConfiguration.Username) &&
                !string.IsNullOrWhiteSpace(NetworkConfiguration.Password);

            // Get all supported authentication methods
            for (int i = 0; i < methodCount; i++)
            {
                var method = (AuthMethod)buffer[2 + i];

                if (!hasCredentials && method == AuthMethod.NoAuth)
                {
                    authMethod = AuthMethod.NoAuth;
                    break;
                }

                if (hasCredentials && method == AuthMethod.UsernamePassword)
                {
                    authMethod = AuthMethod.UsernamePassword;
                    break;
                }
            }

            // Send method selection response (reuse rented buffer to avoid allocation)
            buffer[0] = Socks5Protocol.Version;
            buffer[1] = (byte)authMethod;
            await _clientStream.WriteAsync(buffer.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);

            if (authMethod == AuthMethod.NoAcceptableMethods)
            {
                _logger.Warning("Client does not support 'NoAuth' and 'Username/Password' methods.");
                return false;
            }

            if (authMethod == AuthMethod.UsernamePassword)
            {
                bool success = await AuthPacketValidator
                    .ValidateUsernamePasswordAsync(_clientStream, buffer, cancellationToken)
                    .ConfigureAwait(false);

                if (!success)
                {
                    _logger.Warning("Username/Password authentication failed for client.");
                    return false;
                }
            }

            _logger.Debug("Handshake completed successfully.");
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during handshake.");
            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Handles the SOCKS5 connection request from the client.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if request was handled successfully, otherwise false.</returns>
    private async Task<bool> HandleSocks5RequestAsync(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4);
        try
        {
            // Read SOCKS5 request header (4 bytes) with proper short-read handling
            var totalRead = 0;
            while (totalRead < 4)
            {
                var bytesRead = await _clientStream.ReadAsync(buffer.AsMemory(totalRead, 4 - totalRead), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    await SendReplyAsync(ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
                    return false;
                }
                totalRead += bytesRead;
            }

            // Validate request format
            if (buffer[0] != Socks5Protocol.Version || buffer[2] != Socks5Protocol.Reserved)
            {
                await SendReplyAsync(ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
                return false;
            }

            byte command = buffer[1];
            byte addressType = buffer[3];

            // Return buffer early since we don't need it anymore
            ArrayPool<byte>.Shared.Return(buffer);
            buffer = null!;

            // Parse destination address and port
            var (address, port, parseResult) = await ParseDestinationAsync(addressType, cancellationToken).ConfigureAwait(false);

            if (parseResult != ReplyCode.Succeeded)
            {
                await SendReplyAsync(parseResult, null, cancellationToken).ConfigureAwait(false);
                return false;
            }

            // Handle different commands
            return command switch
            {
                Command.Connect => await HandleConnectCommandAsync(address!, port, cancellationToken).ConfigureAwait(false),
                Command.UdpAssociate => await HandleUdpAssociateCommandAsync(cancellationToken).ConfigureAwait(false),
                Command.Bind => await HandleUnsupportedCommandAsync(ReplyCode.CommandNotSupported, cancellationToken).ConfigureAwait(false),
                _ => await HandleUnsupportedCommandAsync(ReplyCode.CommandNotSupported, cancellationToken).ConfigureAwait(false)
            };
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling SOCKS5 request");
            await SendReplyAsync(ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
            return false;
        }
        finally
        {
            if (buffer != null)
                ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Reads exact number of bytes from stream, handling short reads.
    /// </summary>
    /// <param name="buffer">The buffer to read into.</param>
    /// <param name="offset">The offset in the buffer to start reading.</param>
    /// <param name="count">The number of bytes to read.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if all bytes were read successfully, otherwise false.</returns>
    private async Task<bool> ReadExactAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var totalRead = 0;

        while (totalRead < count)
        {
            var bytesRead = await _clientStream
                .ReadAsync(buffer.AsMemory(offset + totalRead, count - totalRead), cancellationToken)
                .ConfigureAwait(false);

            if (bytesRead == 0)
                return false;

            totalRead += bytesRead;
        }

        return true;
    }

    /// <summary>
    /// Parses the destination address from the SOCKS5 request.
    /// </summary>
    /// <param name="addressType">The address type.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A tuple containing the address, port, and result code.</returns>
    private async Task<(string? address, int port, byte resultCode)> ParseDestinationAsync(byte addressType, CancellationToken cancellationToken)
    {
        byte[]? buffer = null;
        try
        {
            switch (addressType)
            {
                case AddressType.IPv4:
                    {
                        buffer = ArrayPool<byte>.Shared.Rent(6); // 4 bytes IP + 2 bytes port
                        if (!await ReadExactAsync(buffer, 0, 6, cancellationToken).ConfigureAwait(false))
                            return (null, 0, ReplyCode.GeneralFailure);

                        var ipBytes = new byte[4];
                        Array.Copy(buffer, 0, ipBytes, 0, 4);
                        var ipAddress = new IPAddress(ipBytes);
                        var port = buffer[4] << 8 | buffer[5];

                        return (ipAddress.ToString(), port, ReplyCode.Succeeded);
                    }

                case AddressType.IPv6:
                    {
                        buffer = ArrayPool<byte>.Shared.Rent(18); // 16 bytes IP + 2 bytes port
                        if (!await ReadExactAsync(buffer, 0, 18, cancellationToken).ConfigureAwait(false))
                            return (null, 0, ReplyCode.GeneralFailure);

                        var ipBytes = new byte[16];
                        Array.Copy(buffer, 0, ipBytes, 0, 16);
                        var ipAddress = new IPAddress(ipBytes);
                        var port = buffer[16] << 8 | buffer[17];

                        return (ipAddress.ToString(), port, ReplyCode.Succeeded);
                    }

                case AddressType.DomainName:
                    {
                        buffer = ArrayPool<byte>.Shared.Rent(1);
                        if (!await ReadExactAsync(buffer, 0, 1, cancellationToken).ConfigureAwait(false))
                            return (null, 0, ReplyCode.GeneralFailure);

                        byte domainLength = buffer[0];
                        ArrayPool<byte>.Shared.Return(buffer);

                        buffer = ArrayPool<byte>.Shared.Rent(domainLength + 2); // domain + 2 bytes port
                        if (!await ReadExactAsync(buffer, 0, domainLength + 2, cancellationToken).ConfigureAwait(false))
                            return (null, 0, ReplyCode.GeneralFailure);

                        var domain = Encoding.ASCII.GetString(buffer, 0, domainLength);
                        var port = buffer[domainLength] << 8 | buffer[domainLength + 1];

                        return (domain, port, ReplyCode.Succeeded);
                    }

                default:
                    return (null, 0, ReplyCode.AddressTypeNotSupported);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error parsing destination address");
            return (null, 0, ReplyCode.GeneralFailure);
        }
        finally
        {
            if (buffer != null)
                ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Handles the CONNECT command by establishing a TCP connection to the destination,
    /// explicitly choosing IPv4 or IPv6 based on the resolved address and binding to
    /// the configured output interface.
    /// </summary>
    /// <param name="address">The destination address or domain name.</param>
    /// <param name="port">The destination port.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>True if the connection succeeded, false otherwise.</returns>
    private async Task<bool> HandleConnectCommandAsync(string address, int port, CancellationToken cancellationToken)
    {
        var clientEpObj = _client.Client.RemoteEndPoint;
        var clientEndPoint = clientEpObj?.ToString() ?? "Unknown";
        var friendlyClientSuffix = _resolver.FriendlySuffix(clientEpObj);

        _logger.Information(
            "Connecting to {Address}:{Port} for client {ClientEndPoint}{Friendly}",
            address, port, clientEndPoint, friendlyClientSuffix);

        // Resolve IP if needed
        if (!IPAddress.TryParse(address, out IPAddress? destinationIP))
        {
            try
            {
                destinationIP = await _dnsClient
                    .ResolveAsync(address, cancellationToken)
                    .ConfigureAwait(false);

                if (destinationIP == null)
                {
                    _logger.Error("DNS resolution returned null for {Domain}", address);
                    return false;
                }

                // Check compatibility with output IP family
                if (destinationIP.AddressFamily != NetworkConfiguration.OutputInterfaceIP.AddressFamily)
                {
                    _logger.Warning(
                        "Resolved IP {ResolvedIP} is not compatible with output interface {OutputIP}",
                        destinationIP, NetworkConfiguration.OutputInterfaceIP);
                    await SendReplyAsync(ReplyCode.HostUnreachable, null, cancellationToken).ConfigureAwait(false);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Failed to resolve DNS for {Domain}", address);
                await SendReplyAsync(ReplyCode.HostUnreachable, null, cancellationToken).ConfigureAwait(false);
                return false;
            }
        }

        // Create socket based on destination IP
        Socket socket = destinationIP.AddressFamily switch
        {
            AddressFamily.InterNetwork => new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp),
            AddressFamily.InterNetworkV6 => new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp) { DualMode = true },
            _ => throw new NotSupportedException($"Unsupported AddressFamily: {destinationIP.AddressFamily}")
        };

        try
        {
            // Set socket options
            socket.SendTimeout = NetworkConfiguration.SendTimeout;              // 30 seconds
            socket.ReceiveTimeout = NetworkConfiguration.ReceiveTimeout;        // 30 seconds
            socket.SendBufferSize = NetworkConfiguration.SendBufferSize;        // Send buffer size
            socket.ReceiveBufferSize = NetworkConfiguration.ReceiveBufferSize;  // Receive buffer size
            socket.NoDelay = NetworkConfiguration.NoDelay;                      // Disable Nagle's algorithm for better latency
            socket.LingerState = NetworkConfiguration.LingerState;              // RST send
            socket.Bind(new IPEndPoint(NetworkConfiguration.OutputInterfaceIP, 0));

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(NetworkConfiguration.ConnectTimeout);

            await socket.ConnectAsync(destinationIP, port, connectCts.Token).ConfigureAwait(false);

            _destinationClient = new(new IPEndPoint(NetworkConfiguration.OutputInterfaceIP, 0)) { Client = socket };
            _destinationStream = _destinationClient.GetStream();
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.NetworkUnreachable)
        {
            _logger.Warning("Network unreachable for {Address}:{Port} from interface {OutputIP}", 
                address, 
                port, 
                NetworkConfiguration.OutputInterfaceIP);
            socket.Dispose();
            await SendReplyAsync(ReplyCode.NetworkUnreachable, null, cancellationToken).ConfigureAwait(false);
            return false;
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Failed to connect to {Address}:{Port}", address, port);
            socket.Dispose();
            await SendReplyAsync(ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
            return false;
        }

        var localEndPoint = (IPEndPoint)socket.LocalEndPoint!;
        await SendReplyAsync(ReplyCode.Succeeded, localEndPoint, cancellationToken).ConfigureAwait(false);

        _logger.Information(
            "Connected to {Address}:{Port} ({ResolvedIP}) for client {ClientEndPoint}{Friendly}",
            address, port, destinationIP, clientEndPoint, friendlyClientSuffix);

        return true;
    }

    /// <summary>
    /// Handles the UDP ASSOCIATE command by setting up a UDP relay.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if successful, otherwise false.</returns>
    private async Task<bool> HandleUdpAssociateCommandAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.Information("Setting up UDP ASSOCIATE");

            var clientEndPoint = (IPEndPoint)_client.Client.RemoteEndPoint!;
            _udpRelay = new UdpRelay(clientEndPoint, _dnsClient, _logger, _resolver);

            // Send success reply with UDP relay endpoint
            await SendReplyAsync(ReplyCode.Succeeded, _udpRelay.LocalEndPoint, cancellationToken).ConfigureAwait(false);

            _logger.Information("UDP ASSOCIATE setup completed, relay listening on {UdpEndPoint}{Friendly}",
                _udpRelay.LocalEndPoint,
                _resolver.FriendlySuffix(_udpRelay.LocalEndPoint));
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling UDP ASSOCIATE command");
            await SendReplyAsync(ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
            return false;
        }
    }

    /// <summary>
    /// Handles unsupported commands.
    /// </summary>
    /// <param name="replyCode">The reply code to send.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Always returns false since the command is not supported.</returns>
    private async Task<bool> HandleUnsupportedCommandAsync(byte replyCode, CancellationToken cancellationToken)
    {
        await SendReplyAsync(replyCode, null, cancellationToken).ConfigureAwait(false);
        return false;
    }

    /// <summary>
    /// Sends a SOCKS5 reply to the client.
    /// </summary>
    /// <param name="replyCode">The reply code.</param>
    /// <param name="boundEndPoint">The bound endpoint (optional).</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    private async Task SendReplyAsync(byte replyCode, IPEndPoint? boundEndPoint = null, CancellationToken cancellationToken = default)
    {
        // Max response size: 1 (ver) + 1 (rep) + 1 (rsv) + 1 (atyp) + 16 (IPv6) + 2 (port) = 22 bytes
        var buffer = ArrayPool<byte>.Shared.Rent(22);
        try
        {
            int offset = 0;
            buffer[offset++] = Socks5Protocol.Version;
            buffer[offset++] = replyCode;
            buffer[offset++] = Socks5Protocol.Reserved;

            if (boundEndPoint == null)
            {
                // Use IPv4 zero address if no bound endpoint provided
                buffer[offset++] = AddressType.IPv4;
                buffer[offset++] = 0; // 0.0.0.0
                buffer[offset++] = 0;
                buffer[offset++] = 0;
                buffer[offset++] = 0;
                buffer[offset++] = 0; // Port 0
                buffer[offset++] = 0;
            }
            else
            {
                if (boundEndPoint.AddressFamily == AddressFamily.InterNetwork)
                {
                    buffer[offset++] = AddressType.IPv4;
                    var addressBytes = boundEndPoint.Address.GetAddressBytes();
                    Array.Copy(addressBytes, 0, buffer, offset, 4);
                    offset += 4;
                }
                else if (boundEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    buffer[offset++] = AddressType.IPv6;
                    var addressBytes = boundEndPoint.Address.GetAddressBytes();
                    Array.Copy(addressBytes, 0, buffer, offset, 16);
                    offset += 16;
                }

                buffer[offset++] = (byte)(boundEndPoint.Port >> 8);
                buffer[offset++] = (byte)(boundEndPoint.Port & 0xFF);
            }

            await _clientStream.WriteAsync(buffer.AsMemory(0, offset), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error sending SOCKS5 reply");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Forwards data between client and destination using high-performance pipelines.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    private async Task ForwardDataAsync(CancellationToken cancellationToken)
    {
        if (_destinationStream == null)
            return;

        // Create a linked cancellation token to coordinate shutdown when one direction fails
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var linkedToken = linkedCts.Token;

        try
        {
            _logger.Debug("Starting data forwarding");

            // Configure pipe options for better network I/O performance
            var pipeOptions = new PipeOptions(
                pool: MemoryPool<byte>.Shared,
                minimumSegmentSize: NetworkConfiguration.MinimumSegmentSize,
                pauseWriterThreshold: NetworkConfiguration.PauseWriterSize,
                resumeWriterThreshold: NetworkConfiguration.ResumeWriterSize);

            // Create pipes for bidirectional data flow
            var clientToDestinationPipe = new Pipe(pipeOptions);
            var destinationToClientPipe = new Pipe(pipeOptions);

            // Start forwarding tasks
            var tasks = new[]
            {
                ForwardStreamToPipeAsync(_clientStream, clientToDestinationPipe.Writer, "Client->Destination", linkedToken),
                ForwardPipeToStreamAsync(clientToDestinationPipe.Reader, _destinationStream, "Client->Destination", linkedToken),
                ForwardStreamToPipeAsync(_destinationStream, destinationToClientPipe.Writer, "Destination->Client", linkedToken),
                ForwardPipeToStreamAsync(destinationToClientPipe.Reader, _clientStream, "Destination->Client", linkedToken)
            };

            // Wait for any task to complete (indicating one side closed)
            await Task.WhenAny(tasks).ConfigureAwait(false);

            // Cancel remaining tasks to ensure clean shutdown
            linkedCts.Cancel();

            // Wait for all tasks to complete with a timeout to ensure proper cleanup
            try
            {
                await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected when tasks are cancelled
            }
            catch (TimeoutException)
            {
                _logger.Warning("Timeout waiting for forwarding tasks to complete");
            }

            _logger.Debug("Data forwarding completed");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during data forwarding");
        }
    }

    /// <summary>
    /// Forwards data from a stream to a pipe writer.
    /// </summary>
    /// <param name="stream">The source stream.</param>
    /// <param name="writer">The destination pipe writer.</param>
    /// <param name="direction">The direction description for logging.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    private async Task ForwardStreamToPipeAsync(Stream stream, PipeWriter writer, string direction, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var memory = writer.GetMemory(NetworkConfiguration.GetMemoryСhunk);
                var bytesRead = await stream.ReadAsync(memory, cancellationToken).ConfigureAwait(false);

                if (bytesRead == 0)
                    break;

                writer.Advance(bytesRead);
                var result = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);

                if (result.IsCompleted)
                    break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug(ex, "Stream to pipe forwarding ended ({Direction})", direction);
        }
        finally
        {
            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Forwards data from a pipe reader to a stream.
    /// </summary>
    /// <param name="reader">The source pipe reader.</param>
    /// <param name="stream">The destination stream.</param>
    /// <param name="direction">The direction description for logging.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    private async Task ForwardPipeToStreamAsync(PipeReader reader, Stream stream, string direction, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                var buffer = result.Buffer;

                if (buffer.IsEmpty && result.IsCompleted)
                    break;

                if (buffer.IsSingleSegment)
                {
                    await stream.WriteAsync(buffer.First, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    foreach (var segment in buffer)
                    {
                        await stream.WriteAsync(segment, cancellationToken).ConfigureAwait(false);
                    }
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                    break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug(ex, "Pipe to stream forwarding ended ({Direction})", direction);
        }
        finally
        {
            await reader.CompleteAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Waits for client disconnection (used for UDP ASSOCIATE).
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    private async Task WaitForClientDisconnectionAsync(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(1);
        try
        {
            while (!cancellationToken.IsCancellationRequested && _client.Connected)
            {
                var bytesRead = await _clientStream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                    break; // Client disconnected
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug(ex, "Client disconnection detected");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Asynchronously disposes the connection handler and all associated resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        try
        {
            if (_udpRelay != null)
            {
                await _udpRelay.StopAsync().ConfigureAwait(false);
                await _udpRelay.DisposeAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error stopping UDP relay during async disposal");
        }

        try
        {
            if (_destinationStream != null)
                await _destinationStream.DisposeAsync().ConfigureAwait(false);

            _destinationClient?.Close();

            // Note: _clientStream is owned by _client, disposing _client will dispose the stream
            _client?.Close();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error disposing connection resources during async disposal");
        }

        GC.SuppressFinalize(this);
    }
}