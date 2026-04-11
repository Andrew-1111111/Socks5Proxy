using Microsoft.Extensions.Configuration;
using Serilog;
using Socks5Proxy.Configuration;
using Socks5Proxy.Friendly;
using Socks5Proxy.Helper;
using Socks5Proxy.Helper.Firewall.Windows;
using Socks5Proxy.Server;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Socks5Proxy;

/// <summary>
/// Main program entry point for the SOCKS5 proxy server.
/// </summary>
internal class Program
{
    /// <summary>
    /// Main entry point of the application.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code (0 for success, non-zero for error).</returns>
    public static async Task<int> Main(string[] args)
    {
        ILogger? logger = null;
        ProxyServer? server = null;

        try
        {
            // Create a guard with a unique app ID
            using var guard = new SingleInstanceGuard("Socks5Proxy_12345");

            if (guard.IsRunning)
            {
                Console.WriteLine($"Another instance is already running.");
                return 1;
            }

            // Build configuration
            var configuration = BuildConfiguration(args);

            // Configure logging
            logger = ConfigureLogging(configuration);
            logger.Information("SOCKS5 Proxy Server starting...");

            // Load and validate proxy configuration
            var proxyConfig = LoadProxyConfiguration(configuration, logger);
            if (proxyConfig == null)
            {
                logger.Error("Failed to load configuration..");
                return 2; // Error configuration loading
            }

            // Ensure elevated privileges
            if (!AdminLauncher.EnsureElevatedOrRelaunch(logger))
            {
                logger.Error("Application requires administrator/root privileges to run.");
                return 3; // Terminate current instance, elevated one may have started
            }

            // Add Firewall rules (ONLY FOR WINDOWS)
            if (OperatingSystem.IsWindows())
            {
                if (!WindowsFirewallHelper.AllowApplication(Environment.ProcessPath!,
                    Path.GetFileNameWithoutExtension(Environment.ProcessPath!)))
                {
                    logger.Error("Failed to apply Windows Firewall rules for this application. " +
                        "The application may not work correctly without network access.");
                }
            }

            // Create friendly name resolver (safe even if no mappings)
            var resolver = new FriendlyNameResolver(proxyConfig.IPAddressMappings, logger);

            // Setup cancellation token for graceful shutdown
            using var cancellationTokenSource = new CancellationTokenSource();

            // Handle Ctrl+C gracefully
            Console.CancelKeyPress += (sender, e) =>
            {
                logger.Information("Shutdown signal received, stopping server...");
                e.Cancel = true; // Prevent immediate termination
                cancellationTokenSource.Cancel();
            };

            // Create and start the server
            server = new ProxyServer(logger, resolver);

            logger.Information("Listen IP address: {Address}", NetworkConfiguration.ListenIPAddress);
            logger.Information("Listen port: {Port}", NetworkConfiguration.ListenPort);
            logger.Information("Output IP address: {Address}", NetworkConfiguration.OutputInterfaceIP);
            logger.Information("DNS address: {Address}", NetworkConfiguration.DnsServer);
            logger.Information("Starting SOCKS5 proxy server on: {Address}:{Port}",
                NetworkConfiguration.ListenIPAddress, NetworkConfiguration.ListenPort);

            await server.StartAsync(cancellationTokenSource.Token).ConfigureAwait(false);

            logger.Information("SOCKS5 proxy server stopped gracefully.");
            return 0;
        }
        catch (OperationCanceledException)
        {
            if (logger != null)
            {
                logger.Information("Server operation was cancelled.");
            }
            else Console.WriteLine("Server operation was cancelled.");

            return 0;
        }
        catch (FileNotFoundException ex)
        {
            if (logger != null)
            {
                logger.Error(ex, "Failed to load configuration.");
            }
            else Console.WriteLine(ex.Message);

            return 4;
        }
        catch (Exception ex)
        {
            if (logger != null)
            {
                logger.Error(ex, "Fatal error occurred.");
            }
            else Console.WriteLine(ex);

            return 5;
        }
        finally
        {
            try
            {
                if (server != null)
                    await server.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (logger != null)
                {
                    logger?.Error(ex, "Error disposing server.");
                }
                else Console.WriteLine(ex);
            }

            Console.WriteLine($"{Environment.NewLine}Press any key for exit...");
            Console.ReadKey();

            Log.CloseAndFlush(); // Ensure all logs are flushed
        }
    }

    /// <summary>
    /// Builds the configuration from appsettings.json, proxy.json, and command line arguments.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>The built configuration.</returns>
    private static IConfiguration BuildConfiguration(string[] args)
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

        // Check for custom proxy configuration file path from command line
        string proxyConfigPath = "proxy.json";
        
        if (args.Length >= 2 && args[0].Equals("--config", StringComparison.OrdinalIgnoreCase))
        {
            proxyConfigPath = args[1];
        }

        // Check if proxy configuration file exists and provide friendly error message
        var fullProxyConfigPath = Path.IsPathRooted(proxyConfigPath) 
            ? proxyConfigPath 
            : Path.Combine(Directory.GetCurrentDirectory(), proxyConfigPath);

        if (!File.Exists(fullProxyConfigPath))
        {
            throw new FileNotFoundException(
                $"Proxy configuration file not found: '{fullProxyConfigPath}'. " +
                $"Please create the configuration file or specify a valid path using --config <path>.",
                fullProxyConfigPath);
        }

        // Add proxy configuration file
        builder.AddJsonFile(proxyConfigPath, optional: false, reloadOnChange: false);

        // Add command line arguments
        builder.AddCommandLine(args);

        return builder.Build();
    }

    /// <summary>
    /// Configures Serilog logging based on the configuration.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <returns>The configured logger.</returns>
    private static ILogger ConfigureLogging(IConfiguration configuration)
    {
        var loggerConfiguration = new LoggerConfiguration()
            .ReadFrom.Configuration(configuration);

        Log.Logger = loggerConfiguration.CreateLogger();
        return Log.Logger;
    }

    /// <summary>
    /// Loads and validates the proxy configuration.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <param name="logger">The logger instance.</param>
    /// <returns>The proxy configuration or null if invalid.</returns>
    private static ProxyConfiguration? LoadProxyConfiguration(IConfiguration configuration, ILogger logger)
    {
        try
        {
            var proxyConfig = new ProxyConfiguration();
            configuration.Bind(proxyConfig);

            // Validate configuration
            if (!proxyConfig.IsValid(out string errorMessage))
            {
                logger.Error("Invalid proxy configuration: {ErrorMessage}", errorMessage);
                return null;
            }

            logger.Information("Proxy configuration loaded successfully");
            logger.Debug("Listen Address: {Address}, Listen Port: {Port}", 
                proxyConfig.ListenIPAddress, proxyConfig.ListenPort);

            return proxyConfig;
        }
        catch (Exception ex)
        {
            logger.Error(ex, "Error loading proxy configuration");
            return null;
        }
    }
}
