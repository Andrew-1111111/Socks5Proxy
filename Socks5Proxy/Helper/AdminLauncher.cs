using Serilog;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Socks5Proxy.Helper;

/// <summary>
/// Handles application startup with elevated privileges across platforms.
/// Attempts to relaunch with admin/root rights if needed.
/// Logs warning if elevation is not granted.
/// </summary>
public static partial class AdminLauncher
{
    /// <summary>
    /// Gets the effective user ID on Linux/macOS.
    /// Generated at compile-time by LibraryImport.
    /// </summary>
    [LibraryImport("libc")]
    [return: MarshalAs(UnmanagedType.U4)]
    private static partial uint geteuid();

    /// <summary>
    /// Ensures the application is running with administrator/root privileges.
    /// Attempts relaunch if needed. Logs warning if not granted.
    /// Returns true if the current process has elevated rights.
    /// </summary>
    public static bool EnsureElevatedOrRelaunch(ILogger logger)
    {
        if (IsElevated())
            return true;

        try
        {
            var exePath = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot determine current process path.");

            var startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true
            };

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                startInfo.Verb = "runas"; // triggers UAC
            }
            else
            {
                // Linux/macOS: prefix with sudo
                startInfo.FileName = "sudo";
                startInfo.ArgumentList.Add(exePath);
            }

            Process.Start(startInfo);
            return false; // exit current instance; elevated one will start
        }
        catch (Exception ex)
        {
            logger.Warning("Failed to relaunch with elevated rights: {Message}.", ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Forcefully restarts the current application. Can optionally request elevation.
    /// </summary>
    public static void RestartApplication(bool requestElevation = false)
    {
        var exePath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine current process path.");

        var startInfo = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            if (requestElevation)
                startInfo.Verb = "runas";
        }
        else
        {
            if (requestElevation)
            {
                startInfo.FileName = "sudo";
                startInfo.ArgumentList.Add(exePath);
            }
        }

        Process.Start(startInfo);

        // Gracefully exit current process
        Environment.Exit(0);
    }

    /// <summary>
    /// Checks whether the current process is running as administrator/root.
    /// </summary>
    private static bool IsElevated()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
#if NET6_0_OR_GREATER
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
#else
            return false;
#endif
        }
        else
        {
            // Linux/macOS
            return Environment.UserName == "root" || geteuid() == 0;
        }
    }
}