using System;
using System.Net;
using System.Net.Sockets;

namespace Socks5Proxy.Helper;

internal static class NetworkUtils
{
    /// <summary>
    /// Checks if the given IPv6 address is operational by trying to bind a UDP socket to it.
    /// </summary>
    /// <param name="ip">IPv6 address to check. Must not be null.</param>
    /// <returns>True if IPv6 is operational on this address, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown if ip is null or not IPv6.</exception>
    public static bool IsIPv6Avaliable(IPAddress ip)
    {
        ArgumentNullException.ThrowIfNull(ip);

        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("Address must be IPv6", nameof(ip));

        // Ignore link-local addresses without scope ID
        if (ip.IsIPv6LinkLocal && ip.ScopeId == 0)
            return false;

        try
        {
            using var sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            sock.Bind(new IPEndPoint(ip, 0));
            return true;
        }
        catch
        {
            return false;
        }
    }
}