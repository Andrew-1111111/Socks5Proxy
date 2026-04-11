using Socks5Proxy.Helper.Firewall.Windows.Enums;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Socks5Proxy.Helper.Firewall.Windows;

/// <summary>
/// Windows Firewall helper (Windows 10+ only).
/// SAFE MODE: never throws exceptions outside, returns only true/false.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsFirewallHelper
{
    /// <summary>
    /// Adds inbound/outbound allow rules for application.
    /// </summary>
    /// <returns>
    /// True if rules were successfully created, otherwise false.
    /// </returns>
    public static bool AllowApplication(
        string appPath,
        string ruleBaseName,
        string protocol = "Any",
        int? port = null,
        bool overwrite = true)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10))
        {
            return false;
        }

        try
        {
            if (string.IsNullOrWhiteSpace(appPath) || string.IsNullOrWhiteSpace(ruleBaseName))
                return false;

            if (!File.Exists(appPath))
                return false;

            object? policyObj = CreatePolicy();
            if (policyObj is null)
                return false;

            dynamic policy = policyObj;

            var proto = ParseProtocol(protocol);

            if (!AddOrUpdate(policy, appPath, $"{ruleBaseName} (Inbound)", Direction.Inbound, proto, port, overwrite))
                return false;

            if (!AddOrUpdate(policy, appPath, $"{ruleBaseName} (Outbound)", Direction.Outbound, proto, port, overwrite))
                return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Removes firewall rules by base name.
    /// </summary>
    public static bool RemoveRules(string ruleBaseName)
    {
        try
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return false;

            if (string.IsNullOrWhiteSpace(ruleBaseName))
                return false;

            object? policyObj = CreatePolicy();
            if (policyObj is null)
                return false;

            dynamic policy = policyObj;

            foreach (var rule in policy.Rules)
            {
                try
                {
                    string? name = rule.Name as string;

                    if (!string.IsNullOrEmpty(name) &&
                        name.StartsWith(ruleBaseName, StringComparison.Ordinal))
                    {
                        policy.Rules.Remove(name);
                    }
                }
                catch
                {
                    // ignore single rule failure
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    #region Core safe COM

    private static object? CreatePolicy()
    {
        try
        {
            Type? type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (type is null) return null;

            return Activator.CreateInstance(type);
        }
        catch
        {
            return null;
        }
    }

    private static bool AddOrUpdate(
        dynamic policy,
        string appPath,
        string name,
        Direction direction,
        Protocol protocol,
        int? port,
        bool overwrite)
    {
        try
        {
            var rules = policy.Rules;

            if (overwrite)
            {
                try { rules.Remove(name); } catch { }
            }
            else
            {
                try
                {
                    foreach (var r in rules)
                    {
                        if ((string?)r.Name == name)
                            return true;
                    }
                }
                catch
                {
                    return false;
                }
            }

            Type? ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
            if (ruleType is null)
                return false;

            object? ruleObj = Activator.CreateInstance(ruleType);
            if (ruleObj is null)
                return false;
            dynamic rule = ruleObj;

            rule.Name = name;
            rule.ApplicationName = appPath;
            rule.Action = 1;
            rule.Direction = (int)direction;
            rule.Enabled = true;
            rule.InterfaceTypes = "All";
            rule.Protocol = (int)protocol;

            if (port.HasValue && protocol != Protocol.Any)
            {
                string p = port.Value.ToString();

                if (direction == Direction.Inbound)
                    rule.LocalPorts = p;
                else
                    rule.RemotePorts = p;
            }

            rules.Add(rule);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static Protocol ParseProtocol(string protocol)
    {
        try
        {
            return protocol?.Trim().ToUpperInvariant() switch
            {
                "TCP" => Protocol.TCP,
                "UDP" => Protocol.UDP,
                _ => Protocol.Any
            };
        }
        catch
        {
            return Protocol.Any;
        }
    }

    #endregion
}