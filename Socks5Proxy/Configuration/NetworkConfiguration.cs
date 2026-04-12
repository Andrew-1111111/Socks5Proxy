using Socks5Proxy.Helper;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

internal static class NetworkConfiguration
{
    #region Properties

    /// <summary>
    /// Gets or sets the IP address the SOCKS5 server listens on.
    /// </summary>
    internal static IPAddress ListenIPAddress { get; private set; } = IPAddress.Any;

    /// <summary>
    /// Gets or sets the port the SOCKS5 server listens on.
    /// </summary>
    internal static int ListenPort { get; private set; } = 1080;

    /// <summary>
    /// Gets a value indicating whether IPv6 is available on the selected output interface.
    /// </summary>
    internal static bool OutputIPv6Available { get; private set; } = false;

    /// <summary>
    /// Gets the IP address of the selected output network interface.
    /// </summary>
    internal static IPAddress OutputInterfaceIP { get; private set; } = IPAddress.Any;

    /// <summary>
    /// Gets the configured DNS server IP address.
    /// </summary>
    internal static IPAddress DnsServer { get; private set; } = IPAddress.Parse("8.8.8.8");

    /// <summary>
    /// Gets or sets the maximum number of simultaneous connections allowed.
    /// </summary>
    internal static int MaxConnections { get; private set; } = 1000;

    /// <summary>
    /// Gets or sets the username used for SOCKS5 Username/Password authentication.
    /// </summary>
    internal static string? Username { get; private set; }

    /// <summary>
    /// Gets or sets the password used for SOCKS5 Username/Password authentication.
    /// </summary>
    internal static string? Password { get; private set; }

    #endregion

    #region Socket Options

    internal static int IdleTimeout { get; private set; } = 60_000;

    internal static int ConnectTimeout { get; private set; } = 15_000;

    internal static int SendTimeout { get; private set; } = 30_000;

    internal static int ReceiveTimeout { get; private set; } = 30_000;

    internal static int DnsSendTimeout { get; private set; } = 5000;

    internal static int DnsReceiveTimeout { get; private set; } = 5000;

    internal static int SendBufferSize { get; private set; } = 1024 * 1024;

    internal static int ReceiveBufferSize { get; private set; } = 1024 * 1024;

    internal static LingerOption LingerState { get; private set; } = new LingerOption(true, 0);

    internal static bool NoDelay { get; private set; } = true;

    #endregion

    #region Pipe Options

    internal static int MinimumSegmentSize { get; private set; } = 16 * 1024;       // 16 KB

    internal static int PauseWriterSize { get; private set; } = 4 * 1024 * 1024;    // 4 MB

    internal static int ResumeWriterSize { get; private set; } = 2 * 1024 * 1024;   // 2 MB

    internal static int GetMemoryСhunk { get; private set; } = 64 * 1024;           // 64 KB

    #endregion

    /// <summary>
    /// Sets the SOCKS5 server listening interface and port.
    /// </summary>
    /// <param name="ipString">The IP address to bind the server to.</param>
    /// <param name="port">The TCP port to listen on.</param>
    /// <param name="errorMessage">When the method returns false, contains a description of the validation error.</param>
    /// <returns>
    /// <c>true</c> if the configuration was successfully applied; otherwise, <c>false</c>.
    /// </returns>
    internal static bool SetServerInterfaceIP(string ipString, int port, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(ipString))
        {
            errorMessage = "The IP address cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(ipString, out var ip))
        {
            errorMessage = $"'{ipString}' is not a valid IP address.";
            return false;
        }

        if (ip.AddressFamily != AddressFamily.InterNetwork &&
            ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            errorMessage = "Only IPv4 and IPv6 addresses are supported.";
            return false;
        }

        if (!NetworkUtils.IsIPAddressAvailable(ip))
        {
            errorMessage = $"The IP address {ip} is not available for binding.";
            return false;
        }

        if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
        {
            errorMessage = $"The port must be in the range {IPEndPoint.MinPort}-{IPEndPoint.MaxPort}.";
            return false;
        }

        if (!NetworkUtils.IsPortAvailable(port))
        {
            errorMessage = $"The port {port} is already in use.";
            return false;
        }

        ListenIPAddress = ip;
        ListenPort = port;
        return true;
    }

    /// <summary>
    /// Sets the output network interface IP address used for outbound connections.
    /// </summary>
    /// <param name="ipString">The IP address of the network interface.</param>
    /// <param name="errorMessage">When the method returns false, contains a description of the validation error.</param>
    /// <returns>
    /// <c>true</c> if the interface was successfully set; otherwise, <c>false</c>.
    /// </returns>
    internal static bool SetOutputInterfaceIP(string ipString, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(ipString))
        {
            errorMessage = "The interface IP cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(ipString, out var ip))
        {
            errorMessage = $"'{ipString}' is not a valid IP address.";
            return false;
        }

        if (!NetworkUtils.IsIPAddressAvailable(ip))
        {
            errorMessage = $"The IP address {ip} is not available for binding.";
            return false;
        }

        OutputInterfaceIP = ip;

        try
        {
            OutputIPv6Available = NetworkUtils.IsIPv6Avaliable(OutputInterfaceIP);
        }
        catch
        {
            OutputIPv6Available = false;
        }

        return true;
    }

    /// <summary>
    /// Sets the output network interface by its system name.
    /// </summary>
    /// <param name="interfaceName">The name of the network interface.</param>
    /// <param name="errorMessage">When the method returns false, contains a description of the validation error.</param>
    /// <returns>
    /// <c>true</c> if the interface was successfully resolved and applied; otherwise, <c>false</c>.
    /// </returns>
    internal static bool SetOutputInterfaceName(string interfaceName, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(interfaceName))
        {
            errorMessage = "The network interface name cannot be null or empty.";
            return false;
        }

        var address = NetworkUtils.GetIPAddressFromName(interfaceName);

        if (address == IPAddress.None)
        {
            errorMessage = $"The interface '{interfaceName}' is not valid or not found.";
            return false;
        }

        OutputInterfaceIP = address;

        try
        {
            OutputIPv6Available = NetworkUtils.IsIPv6Avaliable(OutputInterfaceIP);
        }
        catch
        {
            OutputIPv6Available = false;
        }

        return true;
    }

    /// <summary>
    /// Sets the DNS server IP address.
    /// </summary>
    /// <param name="ipString">The DNS server IP address.</param>
    /// <param name="errorMessage">When the method returns false, contains a description of the validation error.</param>
    /// <returns>
    /// <c>true</c> if the DNS server was successfully set; otherwise, <c>false</c>.
    /// </returns>
    internal static bool SetDnsIP(string ipString, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(ipString))
        {
            errorMessage = "The DNS server address cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(ipString, out var ip))
        {
            errorMessage = $"'{ipString}' is not a valid IP address.";
            return false;
        }

        if (ip.AddressFamily != AddressFamily.InterNetwork &&
            ip.AddressFamily != AddressFamily.InterNetworkV6)
        {
            errorMessage = "Only IPv4 and IPv6 DNS servers are supported.";
            return false;
        }

        if (!NetworkUtils.CheckDns(ip))
        {
            errorMessage = $"The DNS server '{ip}' is unreachable or not responding.";
            return false;
        }

        DnsServer = ip;
        return true;
    }

    /// <summary>
    /// Sets the maximum number of simultaneous connections allowed.
    /// </summary>
    /// <param name="connections">The maximum number of connections.</param>
    /// <param name="errorMessage">When the method returns false, contains a description of the validation error.</param>
    /// <returns>
    /// <c>true</c> if the value was successfully applied; otherwise, <c>false</c>.
    /// </returns>
    internal static bool SetMaxConnections(int connections, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (connections < 0)
        {
            errorMessage = "The number of connections must be greater than or equal to zero.";
            return false;
        }

        MaxConnections = connections;
        return true;
    }

    /// <summary>
    /// Sets the username and password used for SOCKS5 Username/Password authentication.
    /// </summary>
    /// <param name="username">The username used for authentication. Must be non-null, non-empty, ASCII-only, and up to 255 bytes when encoded in ASCII.</param>
    /// <param name="password">The password used for authentication. Must be non-null, non-empty, ASCII-only, and up to 255 bytes when encoded in ASCII.</param>
    /// <param name="errorMessage">When the method returns false, contains a description of the validation error.</param>
    /// <returns>
    /// <c>true</c> if the credentials were successfully set; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// SOCKS5 Username/Password authentication (RFC 1929) uses byte-oriented fields.
    /// This implementation enforces ASCII encoding and a maximum size of 255 bytes per field.
    /// </remarks>
    internal static bool SetUsernamePassword(string? username, string? password, out string errorMessage)
    {
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(username))
        {
            errorMessage = "Username cannot be null, empty, or whitespace.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            errorMessage = "Password cannot be null, empty, or whitespace.";
            return false;
        }

        int usernameBytes = Encoding.ASCII.GetByteCount(username);
        if (usernameBytes > 255)
        {
            errorMessage = "Username exceeds maximum allowed length of 255 bytes.";
            return false;
        }

        int passwordBytes = Encoding.ASCII.GetByteCount(password);
        if (passwordBytes > 255)
        {
            errorMessage = "Password exceeds maximum allowed length of 255 bytes.";
            return false;
        }

        Username = username.Trim();
        Password = password.Trim();

        return true;
    }
}