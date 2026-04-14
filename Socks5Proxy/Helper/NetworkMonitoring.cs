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
    private const int IntervalMs = 5000;

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
        var listener = NetworkUtils.ResolveInterface(listenerAddress);
        var output = NetworkUtils.ResolveInterface(outputAddress);

        if (listener == null) 
            _logger.Fatal("Listener interface could not be resolved.");
        

        if (output == null)
            _logger.Fatal("Output interface could not be resolved.");
        
        while (!cancellationToken.IsCancellationRequested)
        {
            var currentListener = NetworkUtils.ResolveInterface(listenerAddress);
            var currentOutput = NetworkUtils.ResolveInterface(outputAddress);

            ValidateInterface(currentListener, "Listener", listenerAddress);
            ValidateInterface(currentOutput, "Output", outputAddress);

            await Task.Delay(IntervalMs, cancellationToken);
        }
    }

    /// <summary>
    /// Validates a network interface and logs an error if it is missing or not operational.
    /// </summary>
    /// <param name="ni">Network interface instance to validate.</param>
    /// <param name="tag">Label used in logs to identify whether this is Listener or Output.</param>
    /// <param name="address">IP address associated with the interface lookup.</param>
    private void ValidateInterface(NetworkInterface? ni, string tag, IPAddress address)
    {
        if (ni == null)
        {
            _logger.Error("{Tag} interface not found for IP: {IP}", tag, address);
            return;
        }

        if (ni.OperationalStatus != OperationalStatus.Up)
        {
            _logger.Error("{Tag} interface is not UP: {Name} ({Status})",
                tag, ni.Name, ni.OperationalStatus);
        }
    }
}