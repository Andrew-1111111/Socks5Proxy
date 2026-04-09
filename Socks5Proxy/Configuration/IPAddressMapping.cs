namespace Socks5Proxy.Configuration;

/// <summary>
/// A single mapping from literal IP address to a friendly name for logging.
/// </summary>
public class IPAddressMapping
{
    public string IPAddress { get; set; } = string.Empty;
    public string FriendlyName { get; set; } = string.Empty;
}