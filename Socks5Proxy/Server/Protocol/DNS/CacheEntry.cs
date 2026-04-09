using System;
using System.Net;

namespace Socks5Proxy.Server.Protocol.DNS;

/// <summary>
/// Internal cache entry.
/// </summary>
/// <param name="Address">Resolved IP address or null.</param>
/// <param name="Expiry">Expiration timestamp.</param>
/// <param name="Negative">Indicates negative cache (NXDOMAIN / no result).</param>
internal record CacheEntry(IPAddress? Address, DateTime Expiry, bool Negative);