using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Hardware.TiePie.Protocol;

namespace BioDesk.Services.Hardware.TiePie.Discovery;

/// <summary>
/// Ferramenta de descoberta de comandos USB TiePie HS3
/// Testa sistematicamente códigos de comando para mapear protocolo real
///
/// ATENÇÃO: Usar com EXTREMO CUIDADO com hardware real!
/// - Comandos desconhecidos podem danificar dispositivo
/// - SEMPRE começar com tensões baixas (< 2V)
/// - TER botão de emergência pronto
/// - Monitorizar corrente (< 10mA)
///
/// Estratégia:
/// 1. Testar ranges seguros de comandos (0x00000001-0x000000FF)
/// 2. Mapear comandos que retornam respostas válidas
/// 3. Comparar com logs API Monitor do Inergetix Core
/// 4. Inferir semântica dos comandos descobertos
/// </summary>
public class HS3CommandDiscovery : IDisposable
{
    private readonly ILogger<HS3CommandDiscovery> _logger;
    private readonly HS3DeviceProtocol _protocol;
    private readonly Dictionary<uint, CommandDiscoveryResult> _discoveredCommands = new();
    private bool _disposed;

    public HS3CommandDiscovery(ILogger<HS3CommandDiscovery> logger, HS3DeviceProtocol protocol)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
    }

    #region Discovery Methods

    /// <summary>
    /// Testa range de comandos de forma segura
    /// </summary>
    /// <param name="startCommand">Comando inicial (ex: 0x00000001)</param>
    /// <param name="endCommand">Comando final (ex: 0x000000FF)</param>
    /// <param name="delayMs">Delay entre tentativas (evitar sobrecarga)</param>
    /// <returns>Lista de comandos que retornaram respostas válidas</returns>
    public async Task<List<CommandDiscoveryResult>> DiscoverCommandRangeAsync(
        uint startCommand,
        uint endCommand,
        int delayMs = 50)
    {
        _logger.LogInformation("🔍 Iniciando descoberta de comandos: 0x{Start:X8} → 0x{End:X8}",
            startCommand, endCommand);

        var results = new List<CommandDiscoveryResult>();
        int totalCommands = (int)(endCommand - startCommand + 1);
        int testedCommands = 0;

        for (uint command = startCommand; command <= endCommand; command++)
        {
            try
            {
                var result = await TestCommandAsync(command);

                if (result.IsValid)
                {
                    results.Add(result);
                    _discoveredCommands[command] = result;

                    _logger.LogInformation("✅ Comando descoberto: 0x{Command:X8} → {Response}",
                        command, result.ResponseSummary);
                }

                testedCommands++;

                // Progress report a cada 10%
                if (testedCommands % (totalCommands / 10) == 0)
                {
                    double progress = (double)testedCommands / totalCommands * 100;
                    _logger.LogInformation("📊 Progresso: {Progress:F1}% ({Tested}/{Total} comandos testados)",
                        progress, testedCommands, totalCommands);
                }

                // Delay para não sobrecarregar dispositivo
                if (delayMs > 0)
                    await Task.Delay(delayMs);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("⚠️ Erro ao testar comando 0x{Command:X8}: {Error}",
                    command, ex.Message);
            }
        }

        _logger.LogInformation("🎯 Descoberta completa: {Found}/{Total} comandos válidos encontrados",
            results.Count, totalCommands);

        return results;
    }

    /// <summary>
    /// Testa comando específico usando padrão READ→WRITE
    /// </summary>
    /// <param name="command">Código do comando (4 bytes)</param>
    /// <returns>Resultado do teste com resposta READ e WRITE</returns>
    public Task<CommandDiscoveryResult> TestCommandAsync(uint command)
    {
        var result = new CommandDiscoveryResult { CommandCode = command };

        try
        {
            // FASE 1: READ_OPERATION (query status)
            bool readSuccess = _protocol.ReadOperation(command, out HS3Response8 readResponse);

            if (!readSuccess)
            {
                result.IsValid = false;
                result.ErrorMessage = "READ_OPERATION falhou";
                return Task.FromResult(result);
            }

            result.ReadResponse = readResponse;
            result.ReadSuccess = true;

            // FASE 2: WRITE_OPERATION (get data)
            // Testar múltiplos tamanhos: 1, 4, 8, 48, 64 bytes
            var writeSizes = new[] { 1, 4, 8, 48, 64 };

            foreach (int size in writeSizes)
            {
                bool writeSuccess = _protocol.WriteOperation(command, size, out byte[] writeResponse);

                if (writeSuccess && writeResponse.Length > 0)
                {
                    result.WriteResponses[size] = writeResponse;
                    result.WriteSuccess = true;
                }
            }

            // Comando é válido se READ ou WRITE retornaram dados
            result.IsValid = result.ReadSuccess || result.WriteSuccess;

            return Task.FromResult(result);
        }
        catch (Exception ex)
        {
            result.IsValid = false;
            result.ErrorMessage = ex.Message;
            return Task.FromResult(result);
        }
    }

    /// <summary>
    /// Compara comandos descobertos com logs do API Monitor
    /// Identifica comandos que o Inergetix Core usa frequentemente
    /// </summary>
    /// <param name="apiMonitorLogPath">Path do ficheiro de logs (ApiMonitor_COM_Equipamento.txt)</param>
    /// <returns>Comandos que coincidem com logs (alta probabilidade de serem corretos)</returns>
    public Task<List<uint>> CompareWithApiMonitorLogsAsync(string apiMonitorLogPath)
    {
        _logger.LogInformation("📋 Comparando comandos descobertos com logs API Monitor: {Path}",
            apiMonitorLogPath);

        var matchingCommands = new List<uint>();

        // TODO: Implementar parser de logs API Monitor
        // Procurar padrões:
        // - IOCTL 0x222051 com input = comando específico
        // - IOCTL 0x22204E com input = comando específico
        // - Comparar com _discoveredCommands

        _logger.LogWarning("⚠️ CompareWithApiMonitorLogs ainda não implementado (TODO)");

        return Task.FromResult(matchingCommands);
    }

    /// <summary>
    /// Tenta identificar função de comando baseado em padrões de resposta
    /// </summary>
    /// <param name="command">Código do comando</param>
    /// <returns>Descrição inferida do comando</returns>
    public string InferCommandFunction(uint command)
    {
        if (!_discoveredCommands.TryGetValue(command, out var result))
            return "Comando não testado";

        // Heurísticas baseadas em análise de respostas

        // 1. Comando retorna double? Provavelmente GET de valor (frequência, amplitude)
        if (result.ReadResponse.ValueAsDouble > 0 && result.ReadResponse.ValueAsDouble < 1e9)
        {
            if (result.ReadResponse.ValueAsDouble < 1000)
                return "Possível GET_AMPLITUDE (< 1000 = Volts?)";
            else if (result.ReadResponse.ValueAsDouble < 1e6)
                return "Possível GET_FREQUENCY (< 1MHz)";
            else
                return "Possível GET_FREQUENCY (> 1MHz = AWG mode?)";
        }

        // 2. Comando retorna 0? Provavelmente status/flag
        if (result.ReadResponse.ValueAsLong == 0)
            return "Possível STATUS_QUERY ou DISABLED_FEATURE";

        // 3. Comando retorna valores pequenos (< 256)? Provavelmente enum/flag
        if (result.ReadResponse.LowDWord < 256 && result.ReadResponse.HighDWord == 0)
            return $"Possível ENUM/FLAG (value={result.ReadResponse.LowDWord})";

        // 4. WRITE retorna 1 byte? Provavelmente status OK/Error
        if (result.WriteResponses.ContainsKey(1))
        {
            byte statusByte = result.WriteResponses[1][0];
            if (statusByte == 0x00)
                return "Possível SET_COMMAND (status=OK)";
            else if (statusByte == 0x01)
                return "Possível SET_COMMAND (status=BUSY)";
            else if (statusByte == 0xFF)
                return "Possível SET_COMMAND (status=ERROR)";
        }

        return "Função desconhecida (analisar manualmente)";
    }

    #endregion

    #region Export Methods

    /// <summary>
    /// Exporta comandos descobertos para ficheiro CSV
    /// Formato: CommandCode,ReadSuccess,WriteSuccess,InferredFunction,ResponseHex
    /// </summary>
    /// <param name="outputPath">Path do ficheiro CSV</param>
    public async Task ExportToCsvAsync(string outputPath)
    {
        _logger.LogInformation("💾 Exportando comandos descobertos para CSV: {Path}", outputPath);

        var sb = new StringBuilder();
        sb.AppendLine("CommandCode,ReadSuccess,WriteSuccess,InferredFunction,ReadResponseDouble,ReadResponseHex,WriteResponse1B,WriteResponse8B");

        foreach (var (command, result) in _discoveredCommands.OrderBy(x => x.Key))
        {
            sb.Append($"0x{command:X8},");
            sb.Append($"{result.ReadSuccess},");
            sb.Append($"{result.WriteSuccess},");
            sb.Append($"\"{InferCommandFunction(command)}\",");
            sb.Append($"{result.ReadResponse.ValueAsDouble:F6},");
            sb.Append($"\"{ToHexString(result.ReadResponse)}\",");

            if (result.WriteResponses.TryGetValue(1, out var write1B))
                sb.Append($"0x{write1B[0]:X2},");
            else
                sb.Append(",");

            if (result.WriteResponses.TryGetValue(8, out var write8B))
                sb.Append($"\"{BitConverter.ToString(write8B).Replace("-", " ")}\"");
            else
                sb.Append("");

            sb.AppendLine();
        }

        await System.IO.File.WriteAllTextAsync(outputPath, sb.ToString());
        _logger.LogInformation("✅ CSV exportado com sucesso: {Count} comandos",
            _discoveredCommands.Count);
    }

    /// <summary>
    /// Exporta comandos descobertos para ficheiro C# (constants)
    /// </summary>
    /// <param name="outputPath">Path do ficheiro .cs</param>
    public async Task ExportToCSharpAsync(string outputPath)
    {
        _logger.LogInformation("💾 Exportando comandos descobertos para C#: {Path}", outputPath);

        var sb = new StringBuilder();
        sb.AppendLine("// GERADO AUTOMATICAMENTE por HS3CommandDiscovery.cs");
        sb.AppendLine($"// Data: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"// Total de comandos: {_discoveredCommands.Count}");
        sb.AppendLine();
        sb.AppendLine("namespace BioDesk.Services.Hardware.TiePie.Protocol;");
        sb.AppendLine();
        sb.AppendLine("/// <summary>");
        sb.AppendLine("/// Comandos HS3 descobertos via engenharia reversa");
        sb.AppendLine("/// </summary>");
        sb.AppendLine("public static class HS3CommandsDiscovered");
        sb.AppendLine("{");

        foreach (var (command, result) in _discoveredCommands.OrderBy(x => x.Key))
        {
            string functionName = InferCommandFunction(command)
                .Replace("Possível ", "")
                .Replace(" ", "_")
                .Replace("(", "")
                .Replace(")", "")
                .Replace(",", "")
                .Replace("?", "")
                .ToUpperInvariant();

            // Garantir que nome é válido C#
            if (char.IsDigit(functionName[0]))
                functionName = "CMD_" + functionName;

            sb.AppendLine();
            sb.AppendLine($"    /// <summary>");
            sb.AppendLine($"    /// {InferCommandFunction(command)}");
            sb.AppendLine($"    /// Read: {(result.ReadSuccess ? "✅" : "❌")}, Write: {(result.WriteSuccess ? "✅" : "❌")}");
            sb.AppendLine($"    /// </summary>");
            sb.AppendLine($"    public const uint {functionName} = 0x{command:X8};");
        }

        sb.AppendLine("}");

        await System.IO.File.WriteAllTextAsync(outputPath, sb.ToString());
        _logger.LogInformation("✅ C# constants exportadas com sucesso");
    }

    #endregion

    #region Utility Methods

    private static string ToHexString(HS3Response8 response)
    {
        var bytes = new byte[8];
        BitConverter.GetBytes(response.ValueAsLong).CopyTo(bytes, 0);
        return BitConverter.ToString(bytes).Replace("-", " ");
    }

    #endregion

    #region Dispose

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // Protocolo é owned por caller, não dispose aqui
            // Cleanup managed resources se necessário
        }

        _disposed = true;
    }

    #endregion
}

/// <summary>
/// Resultado de teste de comando descoberto
/// </summary>
public class CommandDiscoveryResult
{
    public uint CommandCode { get; set; }
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }

    // READ_OPERATION results
    public bool ReadSuccess { get; set; }
    public HS3Response8 ReadResponse { get; set; }

    // WRITE_OPERATION results (múltiplos tamanhos)
    public bool WriteSuccess { get; set; }
    public Dictionary<int, byte[]> WriteResponses { get; set; } = new();

    /// <summary>
    /// Resumo da resposta para logging
    /// </summary>
    public string ResponseSummary
    {
        get
        {
            var parts = new List<string>();

            if (ReadSuccess)
                parts.Add($"READ: {ReadResponse.ValueAsDouble:F6} (0x{ReadResponse.ValueAsLong:X16})");

            if (WriteSuccess)
            {
                var writeSummary = string.Join(", ",
                    WriteResponses.Select(kv => $"{kv.Key}B:{BitConverter.ToString(kv.Value, 0, Math.Min(4, kv.Value.Length))}"));
                parts.Add($"WRITE: {writeSummary}");
            }

            return string.Join(" | ", parts);
        }
    }

    public override string ToString() =>
        $"Command 0x{CommandCode:X8}: {(IsValid ? "✅" : "❌")} {ResponseSummary}";
}
