using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net;

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
    [Required(ErrorMessage = "OutputIPAddress is required.")]
    public string OutputIPAddress { get; set; } = string.Empty;

    /// <summary>
    /// DNS server address. Can be IPv4, IPv6.
    /// </summary>
    [Required(ErrorMessage = "DNS server is required.")]
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
    /// Validates that the IP address is valid.
    /// </summary>
    /// <returns>True if the configuration is valid, otherwise false.</returns>
    public bool IsValid(out string errorMessage)
    {
        errorMessage = string.Empty;

        // Validate IP address
        if (string.IsNullOrWhiteSpace(ListenIPAddress))
        {
            errorMessage = "ListenIPAddress cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(ListenIPAddress, out _))
        {
            errorMessage = $"Invalid IP address: {ListenIPAddress}";
            return false;
        }

        // Validate port range
        if (ListenPort < 1 || ListenPort > 65535)
        {
            errorMessage = $"Invalid port: {ListenPort}. Port must be between 1 and 65535.";
            return false;
        }

        // Validate output IP address
        if (string.IsNullOrWhiteSpace(OutputIPAddress))
        {
            errorMessage = "OutputIPAddress cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(OutputIPAddress, out _))
        {
            errorMessage = $"Invalid output IP address: {OutputIPAddress}";
            return false;
        }

        // Validate DNS
        if (string.IsNullOrWhiteSpace(DnsServer))
        {
            errorMessage = "DNS server cannot be null or empty.";
            return false;
        }

        if (!IPAddress.TryParse(DnsServer, out _))
        {
            errorMessage = $"Invalid DNS server address: {DnsServer}";
            return false;
        }

        return true;
    }
}