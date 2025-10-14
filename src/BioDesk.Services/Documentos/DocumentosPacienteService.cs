using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Documentos;

/// <summary>
/// Serviço para listagem e gestão de documentos existentes de um paciente.
/// Complementa o DocumentoService com funcionalidades de busca.
/// </summary>
public sealed class DocumentosPacienteService : IDocumentosPacienteService
{
    private readonly ILogger<DocumentosPacienteService> _logger;
    private readonly string _baseDirectory;

    // Pastas onde buscar documentos (relativas ao BaseDirectory)
    private readonly string[] _pastasBusca = new[]
    {
        "Consentimentos",
        "Prescricoes",
        "DeclaracoesSaude"  // ✅ ADICIONADO: Incluir declarações de saúde
    };

    public DocumentosPacienteService(ILogger<DocumentosPacienteService> logger)
    {
        _logger = logger;

        // ✅ Usar PathService para obter caminho correto (Debug/Release)
        _baseDirectory = PathService.AppDataPath;
    }

    public async Task<List<DocumentoPaciente>> ObterDocumentosDoPacienteAsync(int pacienteId, string nomePaciente)
    {
        await Task.CompletedTask; // Operação I/O síncrona, mas mantém signature async para futuro

        var documentos = new List<DocumentoPaciente>();
        var nomeNormalizado = NormalizarNomeParaBusca(nomePaciente);

        // 🔍 DEBUG: Escrever log detalhado para ficheiro
        var logPath = Path.Combine(_baseDirectory, "DEBUG_DOCUMENTOS.txt");
        var logLines = new List<string>
        {
            $"=== DEBUG BUSCA DOCUMENTOS - {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===",
            $"PacienteId: {pacienteId}",
            $"NomePaciente: {nomePaciente}",
            $"NomeNormalizado: {nomeNormalizado}",
            $"BaseDirectory: {_baseDirectory}",
            ""
        };

        try
        {
            // ✅ Usar PathService para obter pasta de Pacientes (Debug/Release)
            var pastaPacienteRaiz = Path.Combine(PathService.DocumentosPath, "Pacientes");
            logLines.Add($"PastaPacienteRaiz: {pastaPacienteRaiz}");
            logLines.Add($"Pasta existe? {Directory.Exists(pastaPacienteRaiz)}");

            if (!Directory.Exists(pastaPacienteRaiz))
            {
                _logger.LogWarning("⚠️ Pasta de pacientes não encontrada: {Pasta}", pastaPacienteRaiz);
                logLines.Add("❌ PASTA RAIZ NÃO EXISTE!");
                File.WriteAllLines(logPath, logLines);
                return new List<DocumentoPaciente>();
            }

            // Listar TODAS as pastas dentro de Pacientes/
            var todasPastas = Directory.GetDirectories(pastaPacienteRaiz);
            logLines.Add($"\nTotal de pastas em Pacientes/: {todasPastas.Length}");
            foreach (var pasta in todasPastas)
            {
                logLines.Add($"  - {Path.GetFileName(pasta)}");
            }

            // ✅ Procurar pasta que CONTÉM o nome do paciente (normalizar AMBOS removendo espaços)
            var nomeComUnderscores = nomePaciente.Replace(" ", "_").ToLowerInvariant();
            logLines.Add($"\nNomeComUnderscores: {nomeComUnderscores}");
            logLines.Add($"Buscando pastas que contenham: '{nomeNormalizado}' OU '{nomeComUnderscores}'");

            var pastasPaciente = Directory.GetDirectories(pastaPacienteRaiz)
                .Where(p =>
                {
                    var nomePasta = Path.GetFileName(p).ToLowerInvariant();
                    var nomePastaNormalizado = nomePasta.Replace(" ", "").Replace("_", ""); // Remover espaços E underscores
                    var match = nomePastaNormalizado.Contains(nomeNormalizado) || nomePasta.Contains(nomeComUnderscores);
                    logLines.Add($"  Pasta '{Path.GetFileName(p)}' (normalizado: '{nomePastaNormalizado}') → match: {match}");
                    return match;
                })
                .ToList();

            logLines.Add($"\nPastas encontradas para o paciente: {pastasPaciente.Count}");

            foreach (var pastaPaciente in pastasPaciente)
            {
                _logger.LogDebug("📂 Buscando em: {Pasta}", pastaPaciente);
                logLines.Add($"\n📂 Buscando em: {pastaPaciente}");

                // Listar subpastas
                var subpastas = Directory.GetDirectories(pastaPaciente);
                logLines.Add($"  Subpastas: {subpastas.Length}");
                foreach (var sub in subpastas)
                {
                    logLines.Add($"    - {Path.GetFileName(sub)}");
                }

                // ✅ Buscar recursivamente em todas as subpastas (Consentimentos/, Prescricoes/, DeclaracoesSaude/)
                var pdfs = Directory.GetFiles(pastaPaciente, "*.pdf", SearchOption.AllDirectories).ToList();
                logLines.Add($"  PDFs encontrados: {pdfs.Count}");

                foreach (var pdf in pdfs)
                {
                    var relPath = pdf.Replace(pastaPaciente, "").TrimStart('\\');
                    logLines.Add($"    ✅ {relPath}");
                    var doc = CriarDocumentoPaciente(pdf, pacienteId, DeterminarTipoPorCaminho(pdf));
                    documentos.Add(doc);
                }
            }

            // Ordenar por data (mais recente primeiro)
            var resultado = documentos
                .OrderByDescending(d => d.DataCriacao)
                .ToList();

            logLines.Add($"\n📄 TOTAL DE DOCUMENTOS ENCONTRADOS: {resultado.Count}");
            _logger.LogInformation("📄 Encontrados {Count} documentos para paciente {PacienteId}", resultado.Count, pacienteId);

            // Escrever log para ficheiro
            File.WriteAllLines(logPath, logLines);

            return resultado;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao buscar documentos do paciente {PacienteId}", pacienteId);
            logLines.Add($"\n❌ ERRO: {ex.Message}");
            logLines.Add($"StackTrace: {ex.StackTrace}");
            File.WriteAllLines(logPath, logLines);
            return new List<DocumentoPaciente>();
        }
    }

    public async Task<byte[]> LerDocumentoAsync(string caminhoCompleto)
    {
        try
        {
            if (!File.Exists(caminhoCompleto))
            {
                _logger.LogWarning("⚠️ Documento não encontrado: {Caminho}", caminhoCompleto);
                return Array.Empty<byte>();
            }

            return await File.ReadAllBytesAsync(caminhoCompleto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao ler documento: {Caminho}", caminhoCompleto);
            return Array.Empty<byte>();
        }
    }

    public bool DocumentoExiste(string caminhoCompleto)
    {
        return File.Exists(caminhoCompleto);
    }

    // ============================
    // MÉTODOS PRIVADOS AUXILIARES
    // ============================

    /// <summary>
    /// Normaliza o nome do paciente para busca (remove espaços, underscores, lowercase)
    /// </summary>
    private string NormalizarNomeParaBusca(string nome)
    {
        return nome
            .Replace(" ", "")
            .Replace("_", "")
            .ToLowerInvariant();
    }

    /// <summary>
    /// Verifica se o nome do ficheiro contém o nome do paciente
    /// </summary>
    private bool ContemNomePaciente(string caminhoFicheiro, string nomeNormalizado)
    {
        var nomeFicheiro = Path.GetFileNameWithoutExtension(caminhoFicheiro)
            .Replace(" ", "")
            .Replace("_", "")
            .ToLowerInvariant();

        return nomeFicheiro.Contains(nomeNormalizado);
    }

    /// <summary>
    /// Verifica se o nome da pasta contém o ID ou nome do paciente
    /// </summary>
    private bool ContemIdOuNome(string caminhoPasta, int pacienteId, string nomeNormalizado)
    {
        var nomePasta = Path.GetFileName(caminhoPasta).ToLowerInvariant();
        return nomePasta.StartsWith($"{pacienteId}_") || nomePasta.Contains(nomeNormalizado);
    }

    /// <summary>
    /// Cria um objeto DocumentoPaciente a partir de um ficheiro
    /// </summary>
    private DocumentoPaciente CriarDocumentoPaciente(string caminhoCompleto, int pacienteId, TipoDocumentoEnum tipo)
    {
        var fileInfo = new FileInfo(caminhoCompleto);

        return new DocumentoPaciente
        {
            PacienteId = pacienteId,
            Nome = fileInfo.Name,
            CaminhoCompleto = caminhoCompleto,
            DataCriacao = fileInfo.CreationTime,
            Tipo = tipo,
            Tamanho = fileInfo.Length
        };
    }

    /// <summary>
    /// Determina o tipo de documento pela pasta onde está armazenado
    /// </summary>
    private TipoDocumentoEnum DeterminarTipoPorPasta(string nomePasta)
    {
        return nomePasta.ToLowerInvariant() switch
        {
            "consentimentos" => TipoDocumentoEnum.Consentimento,
            "prescricoes" => TipoDocumentoEnum.Prescricao,
            "declaracoessaude" => TipoDocumentoEnum.Declaracao,  // ✅ ADICIONADO
            _ => TipoDocumentoEnum.Outro
        };
    }

    /// <summary>
    /// Determina o tipo de documento pelo caminho completo ou nome do ficheiro
    /// </summary>
    private TipoDocumentoEnum DeterminarTipoPorCaminho(string caminhoCompleto)
    {
        var caminho = caminhoCompleto.ToLowerInvariant();
        var nome = Path.GetFileName(caminho);

        if (caminho.Contains("consentimento") || nome.Contains("consentimento"))
            return TipoDocumentoEnum.Consentimento;

        if (caminho.Contains("prescri") || nome.Contains("prescri"))
            return TipoDocumentoEnum.Prescricao;

        if (caminho.Contains("declara") || nome.Contains("declara"))
            return TipoDocumentoEnum.Declaracao;

        if (caminho.Contains("analise") || nome.Contains("analise"))
            return TipoDocumentoEnum.Analise;

        return TipoDocumentoEnum.Outro;
    }
}
