using Socks5Proxy.Helper;
using System;
using System.Net;
using System.Net.Sockets;

internal static class NetworkConfiguration
{
    #region Properties

    /// <summary>
    /// The IP address the server listens on.
    /// </summary>
    internal static IPAddress ListenIPAddress { get; set; } = IPAddress.Any;

    /// <summary>
    /// The port the server listens on.
    /// </summary>
    internal static int ListenPort { get; set; }

    /// <summary>
    /// Indicates whether IPv6 is usable on the selected interface IP.
    /// </summary>
    internal static bool OutputIPv6Available { get; private set; }

    /// <summary>
    /// The IP address of the output interface to check for IPv6 support.
    /// </summary>
    internal static IPAddress OutputInterfaceIP { get; private set; } = IPAddress.Any;

    /// <summary>
    /// The IP address of the DNS server.
    /// </summary>
    internal static IPAddress DnsServer { get; private set; } = IPAddress.Any;

    /// <summary>
    /// Maximum number of simultaneous connections allowed.
    /// </summary>
    internal static int MaxConnections { get; set; } = 1000;

    #endregion

    #region Socket Options

    // The send timeout for sockets in milliseconds.
    internal static int SendTimeout { get; set; } = 120_000;

    // The receive timeout for sockets in milliseconds.
    internal static int ReceiveTimeout { get; set; } = 120_000;

    // Send buffer size in bytes (default: 1 MB).
    internal static int SendBufferSize = 1024 * 1024;

    // Receive buffer size in bytes (default: 1 MB).
    internal static int ReceiveBufferSize = 1024 * 1024;

    // The linger state for TCP sockets.
    internal static LingerOption LingerState { get; set; } = new LingerOption(true, 0);

    // Disables the Nagle algorithm if true. Default: true (NoDelay enabled).
    internal static bool NoDelay { get; set; } = true;

    #endregion

    /// <summary>
    /// Sets the server interface IP and port.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="ipString">The IP address to listen on as string.</param>
    /// <param name="port">The port to listen on.</param>
    /// <exception cref="ArgumentNullException">Thrown if ipString is null or empty.</exception>
    /// <exception cref="FormatException">Thrown if ipString is not a valid IP address.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if port is out of valid range.</exception>
    /// <exception cref="NotSupportedException">Thrown if IP address family is not IPv4 or IPv6.</exception>
    internal static void SetServerInterfaceIP(string ipString, int port)
    {
        if (string.IsNullOrWhiteSpace(ipString))
            throw new ArgumentNullException(nameof(ipString), "Interface IP string cannot be null or empty.");

        if (!IPAddress.TryParse(ipString, out var ip))
            throw new FormatException($"'{ipString}' is not a valid IP address.");

        if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
            throw new ArgumentOutOfRangeException(nameof(port), port, $"Port must be between {IPEndPoint.MinPort} and {IPEndPoint.MaxPort}.");

        if (ip.AddressFamily != AddressFamily.InterNetwork && ip.AddressFamily != AddressFamily.InterNetworkV6)
            throw new NotSupportedException($"IP address family '{ip.AddressFamily}' is not supported.");

        ListenIPAddress = ip;
        ListenPort = port;
    }

    /// <summary>
    /// Sets the output interface IP from a string and updates IPv6 availability.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="ipString">Interface IP as string (IPv4 or IPv6).</param>
    /// <exception cref="ArgumentNullException">Thrown if ipString is null or empty.</exception>
    /// <exception cref="FormatException">Thrown if ipString is not a valid IP address.</exception>
    internal static void SetOutputInterfaceIP(string ipString)
    {
        if (string.IsNullOrWhiteSpace(ipString))
            throw new ArgumentNullException(nameof(ipString), "Interface IP string cannot be null or empty.");

        if (!IPAddress.TryParse(ipString, out var ip))
            throw new FormatException($"'{ipString}' is not a valid IP address.");

        OutputInterfaceIP = ip;

        try
        {
            OutputIPv6Available = NetworkUtils.IsIPv6Avaliable(OutputInterfaceIP);
        }
        catch (Exception)
        {
            // Failed to check IPv6 availability on this interface; default to false
            OutputIPv6Available = false;
        }
    }

    /// <summary>
    /// Sets the DNS server IP.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="ipString">DNS server IP as string (IPv4 or IPv6).</param>
    /// <exception cref="ArgumentNullException">Thrown if ipString is null or empty.</exception>
    /// <exception cref="FormatException">Thrown if ipString is not a valid IP address.</exception>
    /// <exception cref="NotSupportedException">Thrown if IP address family is not IPv4 or IPv6.</exception>
    internal static void SetDnsIP(string ipString)
    {
        if (string.IsNullOrWhiteSpace(ipString))
            throw new ArgumentNullException(nameof(ipString), "Dns IP string cannot be null or empty.");

        if (!IPAddress.TryParse(ipString, out var ip))
            throw new FormatException($"'{ipString}' is not a valid IP address.");

        if (ip.AddressFamily != AddressFamily.InterNetwork && ip.AddressFamily != AddressFamily.InterNetworkV6)
            throw new NotSupportedException($"IP address family '{ip.AddressFamily}' is not supported.");

        DnsServer = ip;
    }

    /// <summary>
    /// Sets the maximum number of allowed connections.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="connections">Maximum number of connections.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if connections is less than 1 or exceeds ushort.MaxValue.</exception>
    internal static void SetMaxConnections(int connections)
    {
        if (connections <= 0)
            throw new ArgumentOutOfRangeException(nameof(connections), connections, "Max connections must be greater than zero.");

        if (connections > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(connections), connections, $"Max connections cannot exceed {ushort.MaxValue}.");

        MaxConnections = connections;
    }
}