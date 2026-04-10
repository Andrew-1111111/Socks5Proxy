using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Threading;

namespace Socks5Proxy.Configuration;

/// <summary>
/// Configuration model for the SOCKS5 proxy server with validation attributes.
/// </summary>
internal class ProxyConfiguration
{
    /// <summary>
    /// The IP address to listen on. Can be IPv4, IPv6, or "0.0.0.0" for all interfaces.
    /// </summary>
    [Required(ErrorMessage = "ListenIPAddress is required.")]
    public string ListenIPAddress { get; set; } = string.Empty;

    /// <summary>
    /// The port to listen on. Must be between 1 and 65535.
    /// </summary>
    [Range(1, 65535, ErrorMessage = "ListenPort must be between 1 and 65535.")]
    public int ListenPort { get; set; }

    /// <summary>
    /// The output IP address to destination connections. Can be IPv4, IPv6, or "0.0.0.0" for all interfaces.
    /// </summary>
    public string? OutputIPAddress { get; set; }

    /// <summary>
    /// The output network interface name to destination connections.
    /// </summary>
    public string? OutputInterfaceName { get; set; }

    /// <summary>
    /// DNS server address. Can be IPv4, IPv6.
    /// </summary>
    public string DnsServer { get; set; } = string.Empty;

    /// <summary>
    /// Optional mappings of IP addresses to friendly names for log output.
    /// </summary>
    public List<IPAddressMapping> IPAddressMappings { get; set; } = [];

    /// <summary>
    /// Maximum number of concurrent connections. 0 means unlimited. Default: 1000.
    /// </summary>
    [Range(0, int.MaxValue, ErrorMessage = "MaxConnections must be 0 (unlimited) or a positive number.")]
    public int MaxConnections { get; set; } = 1000;

    /// <summary>
    /// Delay before execution in seconds (0 - no delay). Default: 0.
    /// </summary>
    [Range(0, int.MaxValue, ErrorMessage = "RunDelayS must be 0 or a positive number.")]
    public int RunDelayS { get; set; } = 0;

    /// <summary>
    /// Validates that the IP address is valid.
    /// </summary>
    /// <returns>True if the configuration is valid, otherwise false.</returns>
    public bool IsValid(out string errorMessage)
    {
        // Wait N second before run application
        if (RunDelayS > 0)
        {
            Thread.Sleep(TimeSpan.FromSeconds(RunDelayS));
        }

        // Set listen address and port
        if (!NetworkConfiguration.SetServerInterfaceIP(ListenIPAddress, ListenPort, out errorMessage)) 
            return false;

        // Validate and set output IP address and port
        if (!string.IsNullOrWhiteSpace(OutputIPAddress))
        {
            if (!NetworkConfiguration.SetOutputInterfaceIP(OutputIPAddress, out errorMessage)) 
                return false;
        }

        // Validate and set output network interface name
        if (!string.IsNullOrWhiteSpace(OutputInterfaceName))
        {
            if (!NetworkConfiguration.SetOutputInterfaceName(OutputInterfaceName, out errorMessage)) 
                return false;
        }

        // Validate and set Dns server
        if (!string.IsNullOrWhiteSpace(DnsServer))
        {
            if (!NetworkConfiguration.SetDnsIP(DnsServer, out errorMessage))
                return false;
        }

        // Set Max connections
        if (!NetworkConfiguration.SetMaxConnections(MaxConnections, out errorMessage))
            return false;

        return true;
    }
}