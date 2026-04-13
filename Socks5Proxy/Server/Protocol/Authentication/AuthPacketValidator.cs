using Socks5Proxy.Configuration;
using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Socks5Proxy.Server.Protocol.Authentication;

internal static class AuthPacketValidator
{
    /// <summary>
    /// Validates SOCKS5 Username/Password authentication packet (RFC 1929).
    /// </summary>
    /// <param name="clientStream">The network stream representing the client connection.</param>
    /// <param name="buffer">Reusable buffer used for reading packet data.</param>
    /// <param name="ct">Cancellation token for aborting the operation.</param>
    /// <returns>
    /// <c>true</c> if authentication succeeds; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method parses the SOCKS5 authentication sub-negotiation packet:
    /// VER | ULEN | UNAME | PLEN | PASSWD.
    /// All fields are byte-based and must be read exactly from the TCP stream.
    /// </remarks>
    internal static async Task<bool> ValidateUsernamePasswordAsync(NetworkStream clientStream, byte[] buffer, CancellationToken ct)
    {
        var success = false;

        // Read auth version
        await ReadExactAsync(clientStream, buffer, 1, ct);
        if (buffer[0] != AuthProtocol.Version)
            return success;

        // Read username length
        await ReadExactAsync(clientStream, buffer, 1, ct);
        int ulen = buffer[0];

        if (ulen <= 0 || ulen > buffer.Length)
            return success;

        // Read username
        await ReadExactAsync(clientStream, buffer, ulen, ct);
        var username = Encoding.ASCII.GetString(buffer, 0, ulen);

        // Read password length
        await ReadExactAsync(clientStream, buffer, 1, ct);
        int plen = buffer[0];

        if (plen <= 0 || plen > buffer.Length)
            return success;

        // Read password
        await ReadExactAsync(clientStream, buffer, plen, ct);
        var password = Encoding.ASCII.GetString(buffer, 0, plen);

        // Validate credentials
        if (username == NetworkConfiguration.Username && password == NetworkConfiguration.Password)
        {
            success = true;

            byte[] response = success
                ? [AuthProtocol.Version, AuthProtocol.Status.Success]
                : [AuthProtocol.Version, AuthProtocol.Status.Failure];

            await clientStream.WriteAsync(response, ct).ConfigureAwait(false);
        }

        return success;
    }

    /// <summary>
    /// Reads an exact number of bytes from a network stream.
    /// </summary>
    /// <param name="stream">The network stream to read from.</param>
    /// <param name="buffer">The buffer to store read data.</param>
    /// <param name="size">The exact number of bytes to read.</param>
    /// <param name="ct">Cancellation token for aborting the operation.</param>
    /// <exception cref="Exception">
    /// Thrown when the client disconnects before the required number of bytes is received.
    /// </exception>
    /// <remarks>
    /// TCP is a stream protocol and does not preserve message boundaries.
    /// This method ensures that exactly <paramref name="size"/> bytes are read.
    /// </remarks>
    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, int size, CancellationToken ct)
    {
        int offset = 0;

        while (offset < size)
        {
            int read = await stream
                .ReadAsync(buffer.AsMemory(offset, size - offset), ct)
                .ConfigureAwait(false);

            if (read == 0)
                throw new Exception("Client disconnected during auth packet.");

            offset += read;
        }
    }
}