using System;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Hardware.TiePie;

namespace BioDesk.Services.Hardware;

/// <summary>
/// Testador de funções ocultas da hs3.dll
/// Objetivo: Descobrir como Inergetix CoRe valida conexão física do HS3
/// </summary>
public class HS3FunctionDiscovery
{
    private readonly ILogger _logger;

    public HS3FunctionDiscovery(ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Testa TODAS as funções candidatas para validação de conexão
    /// </summary>
    public void DiscoverValidationFunctions()
    {
        _logger.LogInformation("=== DESCOBERTA DE FUNÇÕES HS3.DLL ===");
        _logger.LogInformation("");

        // Teste 1: IsDeviceConnected
        _logger.LogInformation("Testando: IsDeviceConnected()");
        if (HS3NativeExtended.TryCall_IsDeviceConnected(out bool connected, out string error1))
        {
            _logger.LogInformation("✅ ENCONTRADA! IsDeviceConnected() = {Result}", connected);
        }
        else
        {
            _logger.LogWarning("❌ {Error}", error1);
        }

        // Teste 2: GetConnectionStatus
        _logger.LogInformation("");
        _logger.LogInformation("Testando: GetConnectionStatus()");
        if (HS3NativeExtended.TryCall_GetConnectionStatus(out int status, out string error2))
        {
            _logger.LogInformation("✅ ENCONTRADA! GetConnectionStatus() = {Status}", status);
        }
        else
        {
            _logger.LogWarning("❌ {Error}", error2);
        }

        // Teste 3: CheckHardware
        _logger.LogInformation("");
        _logger.LogInformation("Testando: CheckHardware()");
        if (HS3NativeExtended.TryCall_CheckHardware(out bool hwOk, out string error3))
        {
            _logger.LogInformation("✅ ENCONTRADA! CheckHardware() = {Result}", hwOk);
        }
        else
        {
            _logger.LogWarning("❌ {Error}", error3);
        }

        // Teste 4: GetDeviceCount
        _logger.LogInformation("");
        _logger.LogInformation("Testando: GetDeviceCount()");
        if (HS3NativeExtended.TryCall_GetDeviceCount(out int count, out string error4))
        {
            _logger.LogInformation("✅ ENCONTRADA! GetDeviceCount() = {Count}", count);
        }
        else
        {
            _logger.LogWarning("❌ {Error}", error4);
        }

        _logger.LogInformation("");
        _logger.LogInformation("=== FIM DA DESCOBERTA ===");
    }
}
