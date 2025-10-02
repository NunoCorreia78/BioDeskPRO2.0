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
        "Prescricoes"
    };

    public DocumentosPacienteService(ILogger<DocumentosPacienteService> logger)
    {
        _logger = logger;
        _baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
    }

    public async Task<List<DocumentoPaciente>> ObterDocumentosDoPacienteAsync(int pacienteId, string nomePaciente)
    {
        await Task.CompletedTask; // Operação I/O síncrona, mas mantém signature async para futuro

        var documentos = new List<DocumentoPaciente>();
        var nomeNormalizado = NormalizarNomeParaBusca(nomePaciente);

        try
        {
            // 1. Buscar nas pastas globais (Consentimentos/, Prescricoes/)
            foreach (var pasta in _pastasBusca)
            {
                var caminhoPasta = Path.Combine(_baseDirectory, pasta);
                if (!Directory.Exists(caminhoPasta))
                {
                    _logger.LogDebug("Pasta não encontrada: {Pasta}", caminhoPasta);
                    continue;
                }

                var pdfs = Directory.GetFiles(caminhoPasta, "*.pdf", SearchOption.TopDirectoryOnly)
                    .Where(f => ContemNomePaciente(f, nomeNormalizado))
                    .Select(f => CriarDocumentoPaciente(f, pacienteId, DeterminarTipoPorPasta(pasta)));

                documentos.AddRange(pdfs);
            }

            // 2. Buscar na pasta específica do paciente (Pacientes/{Id}_Nome/)
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var pastaPacienteRaiz = Path.Combine(appData, "BioDeskPro2", "Documentos", "Pacientes");

            if (Directory.Exists(pastaPacienteRaiz))
            {
                var pastasPaciente = Directory.GetDirectories(pastaPacienteRaiz)
                    .Where(p => ContemIdOuNome(p, pacienteId, nomeNormalizado));

                foreach (var pastaPaciente in pastasPaciente)
                {
                    var pdfs = Directory.GetFiles(pastaPaciente, "*.pdf", SearchOption.AllDirectories)
                        .Select(f => CriarDocumentoPaciente(f, pacienteId, DeterminarTipoPorCaminho(f)));

                    documentos.AddRange(pdfs);
                }
            }

            // Ordenar por data (mais recente primeiro)
            var resultado = documentos
                .OrderByDescending(d => d.DataCriacao)
                .ToList();

            _logger.LogInformation("📄 Encontrados {Count} documentos para paciente {PacienteId}", resultado.Count, pacienteId);
            return resultado;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao buscar documentos do paciente {PacienteId}", pacienteId);
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
