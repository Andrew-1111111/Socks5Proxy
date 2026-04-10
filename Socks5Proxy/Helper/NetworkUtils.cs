using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
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

    /// <summary>
    /// Checks if the given IP address is operational by attempting to bind a UDP socket to it.
    /// Supports both IPv4 and IPv6.
    /// </summary>
    /// <param name="ip">IP address to check. Must not be null.</param>
    /// <returns>
    /// True if the IP address is available for binding; otherwise, false.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if ip is null.</exception>
    /// <exception cref="ArgumentException">Thrown if address family is not supported.</exception>
    public static bool IsIPAddressAvailable(IPAddress ip)
    {
        ArgumentNullException.ThrowIfNull(ip);

        // Handle IPv6 specifics
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // Ignore link-local addresses without scope ID
            if (ip.IsIPv6LinkLocal && ip.ScopeId == 0)
                return false;
        }
        else if (ip.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Address must be IPv4 or IPv6", nameof(ip));
        }

        try
        {
            using var socket = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(ip, 0));
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks whether a TCP port is available (not in use) on the local machine.
    /// </summary>
    /// <param name="port">Port number to check.</param>
    /// <returns>
    /// True if the port is free and can be bound; otherwise, false.
    /// </returns>
    public static bool IsPortAvailable(int port)
    {
        try
        {
            using var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>
    /// Retrieves the IP address of a network interface by its name.
    /// </summary>
    /// <param name="interfaceName">
    /// The name of the network interface (e.g., "Ethernet", "Wi-Fi").
    /// </param>
    /// <returns>
    /// The first available IP address assigned to the specified interface.
    /// Prefers IPv4 over IPv6. Returns <see cref="IPAddress.None"/> if:
    /// <list type="bullet">
    /// <item><description>The interface is not found.</description></item>
    /// <item><description>The interface has no assigned IP addresses.</description></item>
    /// <item><description>The interface is not operational (optional check).</description></item>
    /// </list>
    /// </returns>
    public static IPAddress GetIPAddressFromName(string interfaceName)
    {
        var networkInterface = NetworkInterface
            .GetAllNetworkInterfaces()
            .FirstOrDefault(ni =>
                ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase) &&
                ni.OperationalStatus == OperationalStatus.Up);

        if (networkInterface == null)
        {
            return IPAddress.None;
        }

        var addresses = networkInterface
            .GetIPProperties()
            .UnicastAddresses
            .Select(a => a.Address)
            .ToList();

        // Prefer IPv4
        var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        if (ipv4 != null)
        {
            return ipv4;
        }

        // Fallback to IPv6
        var ipv6 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
        if (ipv6 != null)
        {
            return ipv6;
        }

        return IPAddress.None;
    }
}