using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Templates;

/// <summary>
/// Serviço para gestão de templates PDF
/// Lista PDFs da pasta Templates/PDFs/ e converte nomes em títulos limpos
/// </summary>
public class TemplatesPdfService : ITemplatesPdfService
{
    private readonly ILogger<TemplatesPdfService> _logger;
    private readonly string _templatesPdfPath;

    public TemplatesPdfService(ILogger<TemplatesPdfService> logger)
    {
        _logger = logger;

        // Calcular caminho da pasta Templates/PDFs/
        // De: bin/Debug/net8.0-windows7.0/
        // Para: Templates/PDFs/
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        _templatesPdfPath = Path.Combine(baseDir, "../../../../Templates/PDFs");
        _templatesPdfPath = Path.GetFullPath(_templatesPdfPath);

        _logger.LogInformation("📋 TemplatesPdfService inicializado. Pasta: {Path}", _templatesPdfPath);

        GarantirPastaTemplates();
    }

    /// <summary>
    /// Lista todos os templates PDF da pasta Templates/PDFs/
    /// </summary>
    public async Task<List<TemplatePdf>> ListarTemplatesAsync()
    {
        try
        {
            GarantirPastaTemplates();

            var templates = new List<TemplatePdf>();

            if (!Directory.Exists(_templatesPdfPath))
            {
                _logger.LogWarning("⚠️ Pasta de templates não existe: {Path}", _templatesPdfPath);
                return templates;
            }

            var pdfFiles = Directory.GetFiles(_templatesPdfPath, "*.pdf", SearchOption.TopDirectoryOnly);

            foreach (var filePath in pdfFiles)
            {
                var fileInfo = new FileInfo(filePath);
                var nomeLimpo = ConverterNomeFicheiroParaTitulo(fileInfo.Name);

                templates.Add(new TemplatePdf
                {
                    Nome = nomeLimpo,
                    CaminhoCompleto = filePath,
                    NomeFicheiro = fileInfo.Name,
                    TamanhoBytes = fileInfo.Length
                });
            }

            // Ordenar alfabeticamente por nome
            templates = templates.OrderBy(t => t.Nome).ToList();

            _logger.LogInformation("📋 Listados {Count} templates PDF", templates.Count);

            return await Task.FromResult(templates);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao listar templates PDF");
            return new List<TemplatePdf>();
        }
    }

    /// <summary>
    /// Filtra templates por texto de pesquisa
    /// </summary>
    public async Task<List<TemplatePdf>> FiltrarTemplatesAsync(string textoPesquisa)
    {
        var todosTemplates = await ListarTemplatesAsync();

        if (string.IsNullOrWhiteSpace(textoPesquisa))
            return todosTemplates;

        var filtrados = todosTemplates
            .Where(t => t.Nome.Contains(textoPesquisa, StringComparison.OrdinalIgnoreCase))
            .ToList();

        _logger.LogInformation("🔍 Filtrados {Count} templates com '{Pesquisa}'", filtrados.Count, textoPesquisa);

        return filtrados;
    }

    /// <summary>
    /// Abre template PDF no visualizador padrão do sistema
    /// </summary>
    public void AbrirTemplate(string caminhoCompleto)
    {
        try
        {
            if (!File.Exists(caminhoCompleto))
            {
                _logger.LogWarning("⚠️ Template não encontrado: {Caminho}", caminhoCompleto);
                return;
            }

            var processStartInfo = new ProcessStartInfo
            {
                FileName = caminhoCompleto,
                UseShellExecute = true
            };

            Process.Start(processStartInfo);

            _logger.LogInformation("👁 Template aberto: {Nome}", Path.GetFileName(caminhoCompleto));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao abrir template: {Caminho}", caminhoCompleto);
        }
    }

    /// <summary>
    /// Garante que a pasta Templates/PDFs/ existe
    /// </summary>
    public void GarantirPastaTemplates()
    {
        try
        {
            if (!Directory.Exists(_templatesPdfPath))
            {
                Directory.CreateDirectory(_templatesPdfPath);
                _logger.LogInformation("📁 Pasta de templates criada: {Path}", _templatesPdfPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao criar pasta de templates");
        }
    }

    /// <summary>
    /// Converte nome de ficheiro em título limpo
    /// Ex: "Escoliose_Dorsal.pdf" → "Escoliose Dorsal"
    /// Ex: "Dieta_Anti_Inflamatoria.pdf" → "Dieta Anti Inflamatória"
    /// </summary>
    private string ConverterNomeFicheiroParaTitulo(string nomeFicheiro)
    {
        // Remover extensão .pdf
        var semExtensao = Path.GetFileNameWithoutExtension(nomeFicheiro);

        // Substituir _ por espaço
        var comEspacos = semExtensao.Replace('_', ' ');

        // Capitalizar primeira letra de cada palavra
        var palavras = comEspacos.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var titulo = new StringBuilder();

        foreach (var palavra in palavras)
        {
            if (titulo.Length > 0)
                titulo.Append(' ');

            // Capitalizar primeira letra, manter resto como está
            if (palavra.Length > 0)
            {
                titulo.Append(char.ToUpper(palavra[0]));
                if (palavra.Length > 1)
                    titulo.Append(palavra.Substring(1));
            }
        }

        return titulo.ToString();
    }
}
