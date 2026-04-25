using Serilog;
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace Socks5Proxy.Helper;

/// <summary>
/// Provides asynchronous monitoring of two network interfaces:
/// one for listener traffic and one for output traffic.
/// </summary>
/// <param name="logger">Logger instance used for writing diagnostics and alerts.</param>
internal class NetworkMonitoring(ILogger logger)
{
    private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    private readonly TimeSpan _intervalMs = TimeSpan.FromSeconds(5);
    private int _currentNetworkCheck = 0;
    private const int MaxNetworkCheckRetry = 3;

    /// <summary>
    /// Starts monitoring the specified network interfaces.
    /// Performs initial validation and then continuously checks interface health
    /// until the operation is cancelled.
    /// </summary>
    /// <param name="listenerAddress">IP address of the network interface used for incoming (listener) traffic.</param>
    /// <param name="outputAddress">IP address of the network interface used for outgoing (output) traffic.</param>
    /// <param name="cancellationToken">Token used to stop the monitoring loop.</param>
    public async Task Run(
       IPAddress listenerAddress,
       IPAddress outputAddress,
       CancellationToken cancellationToken = default)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var allSuccess = 0;
            var currentListener = NetworkUtils.ResolveInterface(listenerAddress);
            var currentOutput = NetworkUtils.ResolveInterface(outputAddress);

            if (!ValidateInterface(currentListener, "Listener", listenerAddress))
            {
                _currentNetworkCheck++;
            }
            else { allSuccess++; }

            if (!ValidateInterface(currentOutput, "Output", outputAddress))
            {
                _currentNetworkCheck++;
            }
            else { allSuccess++; }

            if (allSuccess >= 2)
            {
                _currentNetworkCheck = 0;
            }
            else if (_currentNetworkCheck >= MaxNetworkCheckRetry)
            {
                // Restart application
                AdminLauncher.RestartApplication();
            }

            await Task.Delay(_intervalMs, cancellationToken);
        }
    }

    /// <summary>
    /// Validates a network interface and logs an error if it is missing or not operational.
    /// </summary>
    /// <param name="ni">Network interface instance to validate.</param>
    /// <param name="tag">Label used in logs to identify whether this is Listener or Output.</param>
    /// <param name="address">IP address associated with the interface lookup.</param>
    /// 
    private bool ValidateInterface(NetworkInterface? ni, string tag, IPAddress address)
    {
        if (ni == null)
        {
            _logger.Error("{Tag} interface not found for IP: {IP}", tag, address);
            return false;
        }

        if (ni.OperationalStatus != OperationalStatus.Up)
        {
            _logger.Error("{Tag} interface is not UP: {Name} ({Status})", tag, ni.Name, ni.OperationalStatus);
            return false;
        }

        return true;
    }
}