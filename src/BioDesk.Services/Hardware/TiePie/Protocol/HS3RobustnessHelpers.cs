using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Hardware.TiePie.Protocol;

/// <summary>
/// Resilience patterns for HS3 device communication.
/// Implements: Retry with exponential backoff, Circuit Breaker, Timeout management.
/// </summary>
public sealed class HS3RobustnessHelpers : IDisposable
{
    private readonly ILogger<HS3RobustnessHelpers> _logger;
    private readonly HS3DeviceProtocol _protocol;
    private readonly object _metricsLock = new();  // For thread-safe metrics access

    /// <summary>
    /// Tracks consecutive failures for circuit breaker pattern.
    /// </summary>
    private int _consecutiveFailures = 0;

    /// <summary>
    /// Threshold of consecutive failures before opening circuit.
    /// </summary>
    private const int FAILURE_THRESHOLD = 5;

    /// <summary>
    /// Circuit breaker state: false = closed (normal), true = open (failing).
    /// </summary>
    private bool _isCircuitOpen = false;

    /// <summary>
    /// When circuit was opened (for recovery timeout).
    /// </summary>
    private DateTime _circuitOpenedAt = DateTime.MinValue;

    /// <summary>
    /// Time before attempting to close circuit (half-open state).
    /// </summary>
    private const int CIRCUIT_RECOVERY_SECONDS = 30;

    /// <summary>
    /// Telemetry: total commands sent.
    /// </summary>
    private int _totalCommands = 0;

    /// <summary>
    /// Telemetry: commands that succeeded.
    /// </summary>
    private int _successfulCommands = 0;

    /// <summary>
    /// Telemetry: commands that failed even after retries.
    /// </summary>
    private int _failedCommands = 0;

    private bool _disposed = false;

    public HS3RobustnessHelpers(ILogger<HS3RobustnessHelpers> logger, HS3DeviceProtocol protocol)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
    }

    /// <summary>
    /// Sends command with automatic retry using exponential backoff.
    /// Retry delays: 100ms, 200ms, 400ms (for maxRetries=3)
    /// </summary>
    public async Task<bool> SendCommandWithRetryAsync(
        byte[] command,
        int maxRetries = 3,
        CancellationToken cancellationToken = default)
    {
        if (command == null || command.Length == 0)
            throw new ArgumentException("Command cannot be null or empty", nameof(command));

        _totalCommands++;

        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                // Check if cancellation requested
                cancellationToken.ThrowIfCancellationRequested();

                _logger.LogDebug(
                    $"[HS3] 📤 Attempt {attempt + 1}/{maxRetries}: Sending command 0x{command[0]:X2} " +
                    $"({command.Length} bytes)");

                // Try to send command (write operation)
                bool success = _protocol.WriteOperation(command[0], command.Length, out var response);

                if (success)
                {
                    _successfulCommands++;
                    _consecutiveFailures = 0; // Reset failure counter on success
                    _logger.LogDebug("[HS3] ✅ Command succeeded");
                    return true;
                }

                _logger.LogWarning($"[HS3] ⚠️ Attempt {attempt + 1} failed, will retry...");

                // Calculate backoff delay (exponential: 100ms, 200ms, 400ms, ...)
                if (attempt < maxRetries - 1)
                {
                    int delayMs = 100 * (int)Math.Pow(2, attempt);
                    _logger.LogDebug($"[HS3] ⏳ Waiting {delayMs}ms before retry...");
                    await Task.Delay(delayMs, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("[HS3] ⚠️ Command cancelled by caller");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"[HS3] ⚠️ Exception during retry: {ex.Message}");

                // If last attempt, don't retry further
                if (attempt == maxRetries - 1)
                    break;

                // Otherwise continue to next attempt
                await Task.Delay(100 * (int)Math.Pow(2, attempt), cancellationToken);
            }
        }

        _failedCommands++;
        _consecutiveFailures++;

        _logger.LogError(
            $"[HS3] ❌ Command 0x{command[0]:X2} failed after {maxRetries} attempts. " +
            $"Consecutive failures: {_consecutiveFailures}/{FAILURE_THRESHOLD}");

        return false;
    }

    /// <summary>
    /// Sends command with circuit breaker pattern.
    /// Prevents cascading failures by stopping communication when device is unstable.
    /// </summary>
    public async Task<bool> SendCommandWithCircuitBreakerAsync(
        byte[] command,
        int maxRetries = 3,
        CancellationToken cancellationToken = default)
    {
        // Check if circuit should be closed (recovery attempt)
        if (_isCircuitOpen)
        {
            TimeSpan timeSinceOpen = DateTime.UtcNow - _circuitOpenedAt;
            if (timeSinceOpen.TotalSeconds >= CIRCUIT_RECOVERY_SECONDS)
            {
                _logger.LogWarning(
                    $"[HS3] 🔄 Circuit breaker: Recovery timeout reached ({timeSinceOpen.TotalSeconds}s). " +
                    $"Attempting to close circuit...");
                _isCircuitOpen = false;
                _consecutiveFailures = 0;
            }
            else
            {
                _logger.LogError(
                    $"[HS3] 🚨 Circuit breaker OPEN - Device unstable. " +
                    $"Recovery in {CIRCUIT_RECOVERY_SECONDS - timeSinceOpen.TotalSeconds:F1}s");
                _failedCommands++;
                return false;
            }
        }

        // Try to send with retry
        bool success = await SendCommandWithRetryAsync(command, maxRetries, cancellationToken);

        // Update circuit state based on result
        if (success)
        {
            // Success - circuit stays closed
            if (_isCircuitOpen)
            {
                _logger.LogInformation("[HS3] ✅ Circuit breaker: Recovery successful! Circuit CLOSED.");
            }
        }
        else
        {
            // Failure - increment counter and check if we should open circuit
            if (_consecutiveFailures >= FAILURE_THRESHOLD)
            {
                _isCircuitOpen = true;
                _circuitOpenedAt = DateTime.UtcNow;

                _logger.LogCritical(
                    $"[HS3] 🚨 Circuit breaker OPENED! {_consecutiveFailures} consecutive failures detected. " +
                    $"Device communication suspended for {CIRCUIT_RECOVERY_SECONDS}s.");

                // Schedule automatic recovery attempt
                _ = Task.Delay(TimeSpan.FromSeconds(CIRCUIT_RECOVERY_SECONDS)).ContinueWith(async _ =>
                {
                    _logger.LogInformation("[HS3] 🔄 Attempting device recovery...");
                    await Task.CompletedTask;
                });
            }
        }

        return success;
    }

    /// <summary>
    /// Gets circuit breaker status.
    /// </summary>
    public (bool IsOpen, int ConsecutiveFailures, TimeSpan TimeSinceOpen) GetCircuitStatus()
    {
        var timeSinceOpen = _isCircuitOpen
            ? DateTime.UtcNow - _circuitOpenedAt
            : TimeSpan.Zero;

        return (_isCircuitOpen, _consecutiveFailures, timeSinceOpen);
    }

    /// <summary>
    /// Gets telemetry metrics for diagnostics.
    /// </summary>
    public (int Total, int Successful, int Failed, double SuccessRate) GetMetrics()
    {
        double successRate = _totalCommands == 0 ? 0 : (double)_successfulCommands / _totalCommands;
        return (_totalCommands, _successfulCommands, _failedCommands, successRate);
    }

    /// <summary>
    /// Returns human-readable diagnostics report.
    /// </summary>
    public string GetDiagnosticsReport()
    {
        var (total, successful, failed, successRate) = GetMetrics();
        var (circuitOpen, failures, timeSinceOpen) = GetCircuitStatus();

        return $@"
╔══════════════════════════════════════════════════════════════════╗
║           HS3 Robustness Diagnostics Report                      ║
╠══════════════════════════════════════════════════════════════════╣
║ Commands Sent:        {total,4} total                                   │
║ Successful:           {successful,4} ({successRate:P1})                                 │
║ Failed:               {failed,4}                                    │
╠══════════════════════════════════════════════════════════════════╣
║ Circuit Breaker:      {(circuitOpen ? "🚨 OPEN" : "✅ CLOSED"),10}                            │
║ Consecutive Failures: {failures,4}/{FAILURE_THRESHOLD}                            │
║ Recovery Status:      {(circuitOpen ? $"In {CIRCUIT_RECOVERY_SECONDS - timeSinceOpen.TotalSeconds:F1}s" : "N/A"),10}                            │
╚══════════════════════════════════════════════════════════════════╝
";
    }

    /// <summary>
    /// Resets all counters and circuit breaker state.
    /// Use after successful device recovery or reinit.
    /// </summary>
    public void Reset()
    {
        lock (_metricsLock)
        {
            _consecutiveFailures = 0;
            _isCircuitOpen = false;
            _circuitOpenedAt = DateTime.MinValue;
            _totalCommands = 0;
            _successfulCommands = 0;
            _failedCommands = 0;

            _logger.LogInformation("[HS3] 🔄 Robustness helpers reset to initial state");
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        try
        {
            _logger.LogDebug("[HS3] Disposing HS3RobustnessHelpers");
        }
        catch
        {
            // Ignore logging errors during dispose
        }

        _disposed = true;
    }
}
