using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace BioDesk.Core.Application.Terapia.Impl;

/// <summary>
/// Resultado simplificado de importação Excel para uso em BioDesk.Core
/// </summary>
public record ExcelImportResultCore(bool Sucesso, int LinhasImportadas, string? Erro);

/// <summary>
/// DTO simplificado de protocolo (sem dependência de BioDesk.Domain)
/// </summary>
public record ProtocoloSimples(string Nome, string? Categoria, string FrequenciasHz);

public sealed class ProgramLibraryExcel : IProgramLibrary
{
    private readonly Func<string, Task<ExcelImportResultCore>> _importFunction;
    private readonly Func<string?, Task<List<ProtocoloSimples>>> _searchFunction;

    /// <summary>
    /// Constructor com delegates para evitar dependência circular
    /// </summary>
    /// <param name="importFunction">Função que executa a importação Excel</param>
    /// <param name="searchFunction">Função que pesquisa protocolos na BD (null = todos ativos)</param>
    public ProgramLibraryExcel(
        Func<string, Task<ExcelImportResultCore>> importFunction,
        Func<string?, Task<List<ProtocoloSimples>>> searchFunction)
    {
        _importFunction = importFunction;
        _searchFunction = searchFunction;
    }

    public async Task<int> ImportExcelAsync(string path, CancellationToken ct)
    {
        var result = await _importFunction(path);
        if (!result.Sucesso)
        {
            throw new InvalidOperationException($"Falha na importação: {result.Erro}");
        }
        return result.LinhasImportadas;
    }

    public async Task<IReadOnlyList<string>> ListProgramsAsync(string? search, CancellationToken ct)
    {
        // Query real à BD via delegate
        var protocolos = await _searchFunction(search);

        // Converter para formato "PROTO::Nome"
        var items = protocolos.Select(p => $"PROTO::{p.Nome}").ToList();

        return items.AsReadOnly();
    }

    public async Task<IReadOnlyList<ProgramStep>> GetProgramAsync(string code, CancellationToken ct)
    {
        // Remover prefixo "PROTO::" se existir
        var nomeLimpo = code.StartsWith("PROTO::", StringComparison.OrdinalIgnoreCase)
            ? code[7..]
            : code;

        // Buscar protocolo completo
        var protocolos = await _searchFunction(nomeLimpo);
        var protocolo = protocolos.FirstOrDefault(p => p.Nome.Equals(nomeLimpo, StringComparison.OrdinalIgnoreCase));

        if (protocolo == null)
        {
            return Array.Empty<ProgramStep>();
        }

        // Parse FrequenciasHz "728;880;1500;..."
        var frequencias = protocolo.FrequenciasHz
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(f => f.Trim())
            .Where(f => double.TryParse(f, out _))
            .Select(f => double.Parse(f))
            .ToList();

        // Criar ProgramStep[] com defaults: Duty=50%, Duration=180s
        var steps = frequencias.Select(hz => new ProgramStep(
            Hz: hz,
            Duty: 50,
            Seconds: 180,
            Notes: $"{hz:F1} Hz"
        )).ToList();

        return steps.AsReadOnly();
    }
}
