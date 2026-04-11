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
    internal static int ListenPort { get; set; } = 1080;

    /// <summary>
    /// Indicates whether IPv6 is usable on the selected interface IP.
    /// </summary>
    internal static bool OutputIPv6Available { get; private set; } = false;

    /// <summary>
    /// The IP address of the output interface to check for IPv6 support.
    /// </summary>
    internal static IPAddress OutputInterfaceIP { get; private set; } = IPAddress.Any;

    /// <summary>
    /// The IP address of the DNS server.
    /// </summary>
    internal static IPAddress DnsServer { get; private set; } = IPAddress.Parse("8.8.8.8");

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
    /// <param name="errorMessage">Error message text.</param>
    internal static bool SetServerInterfaceIP(string ipString, int port, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(ipString))
        {
            errorMessage = "Interface IP string cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(ipString, out var ip))
        {
            errorMessage = $"'{ipString}' is not a valid IP address.";
            return false;
        }

        if (ip.AddressFamily != AddressFamily.InterNetwork && ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            errorMessage = $"IP address family '{ip.AddressFamily}' is not supported.";
            return false;
        }

        if (!NetworkUtils.IsIPAddressAvailable(ip))
        {
            errorMessage = $"IP address {ip} is not available for binding.";
            return false;
        }

        if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
        {
            errorMessage = $"Port must be between {IPEndPoint.MinPort} and {IPEndPoint.MaxPort}.";
            return false;
        }

        if (!NetworkUtils.IsPortAvailable(port))
        {
            errorMessage = $"Port {port} is already in use.";
            return false;
        }

        ListenIPAddress = ip;
        ListenPort = port;
        return true;
    }

    /// <summary>
    /// Sets the output interface IP from a string and updates IPv6 availability.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="ipString">Interface IP as string (IPv4 or IPv6).</param>
    /// <param name="errorMessage">Error message text.</param>
    internal static bool SetOutputInterfaceIP(string ipString, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(ipString))
        {
            errorMessage = "Interface IP string cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(ipString, out var ip))
        {
            errorMessage = $"'{ipString}' is not a valid IP address.";
            return false;
        }

        if (!NetworkUtils.IsIPAddressAvailable(ip))
        {
            errorMessage = $"IP address {ip} is not available for binding.";
            return false;
        }

        OutputInterfaceIP = ip;

        try
        {
            OutputIPv6Available = NetworkUtils.IsIPv6Avaliable(OutputInterfaceIP);
        }
        catch (Exception)
        {
            // Failed to check IPv6 availability on this interface
            OutputIPv6Available = false;
        }

        return true;
    }

    /// <summary>
    /// Sets the maximum number of allowed connections.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="connections">Maximum number of connections.</param>
    /// <param name="errorMessage">Error message text.</param>
    internal static bool SetOutputInterfaceName(string interfaceName, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(interfaceName))
        {
            errorMessage = "Network interface name cannot be null or empty.";
            return false;
        }

        var address = NetworkUtils.GetIPAddressFromName(interfaceName);

        if (address == IPAddress.None)
        {
            errorMessage = $"'{interfaceName}' is not a valid network interface name.";
            return false;
        }

        OutputInterfaceIP = address;

        try
        {
            OutputIPv6Available = NetworkUtils.IsIPv6Avaliable(OutputInterfaceIP);
        }
        catch (Exception)
        {
            // Failed to check IPv6 availability on this interface
            OutputIPv6Available = false;
        }

        return true;
    }

    /// <summary>
    /// Sets the DNS server IP.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="ipString">DNS server IP as string (IPv4 or IPv6).</param>
    /// <param name="errorMessage">Error message text.</param>
    internal static bool SetDnsIP(string ipString, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(ipString))
        {
            errorMessage = "Dns server address cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(ipString, out var ip))
        {
            errorMessage = $"Dns: '{ipString}' is not a valid IP address.";
            return false;
        }

        if (ip.AddressFamily != AddressFamily.InterNetwork && ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            errorMessage = $"Dns IP address family '{ip.AddressFamily}' is not supported.";
        }

        if (!NetworkUtils.CheckDns(ip))
        {
            errorMessage = $"DNS server '{ip}' is unreachable or not responding (timeout).";
        }

        DnsServer = ip;
        return true;
    }

    /// <summary>
    /// Sets the maximum number of allowed connections.
    /// Throws exceptions if input is invalid.
    /// </summary>
    /// <param name="connections">Maximum number of connections.</param>
    /// <param name="errorMessage">Error message text.</param>
    internal static bool SetMaxConnections(int connections, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (connections < IPEndPoint.MinPort)
        {
            errorMessage = "The maximum number of connections must be greater than or equal to zero.";
            return false;
        }

        if (connections > IPEndPoint.MaxPort)
        {
            errorMessage = $"Max connections cannot exceed {ushort.MaxValue}.";
            return false;
        }

        MaxConnections = connections;
        return true;
    }
}