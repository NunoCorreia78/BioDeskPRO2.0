using System.Collections.Generic;
using System.Threading.Tasks;

namespace BioDesk.Services.Templates;

/// <summary>
/// Serviço para gestão de templates PDF (protocolos, dietas, exercícios, etc.)
/// </summary>
public interface ITemplatesPdfService
{
    /// <summary>
    /// Lista todos os templates PDF disponíveis na pasta Templates/PDFs/
    /// </summary>
    /// <returns>Lista de templates ordenados alfabeticamente por nome</returns>
    Task<List<TemplatePdf>> ListarTemplatesAsync();

    /// <summary>
    /// Filtra templates por texto de pesquisa (busca no nome)
    /// </summary>
    /// <param name="textoPesquisa">Texto para filtrar templates</param>
    /// <returns>Lista de templates filtrados</returns>
    Task<List<TemplatePdf>> FiltrarTemplatesAsync(string textoPesquisa);

    /// <summary>
    /// Abre um template PDF no visualizador padrão do sistema
    /// </summary>
    /// <param name="caminhoCompleto">Caminho completo do arquivo PDF</param>
    void AbrirTemplate(string caminhoCompleto);

    /// <summary>
    /// Verifica se a pasta de templates existe e cria se necessário
    /// </summary>
    void GarantirPastaTemplates();
}

/// <summary>
/// Representa um template PDF disponível para anexar em emails
/// </summary>
public class TemplatePdf
{
    /// <summary>
    /// Nome limpo do template (ex: "Escoliose Dorsal")
    /// Convertido automaticamente do nome do ficheiro
    /// </summary>
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Caminho completo do ficheiro PDF
    /// </summary>
    public string CaminhoCompleto { get; set; } = string.Empty;

    /// <summary>
    /// Nome do ficheiro original (ex: "Escoliose_Dorsal.pdf")
    /// </summary>
    public string NomeFicheiro { get; set; } = string.Empty;

    /// <summary>
    /// Tamanho do ficheiro em bytes
    /// </summary>
    public long TamanhoBytes { get; set; }

    /// <summary>
    /// Tamanho formatado (ex: "1.5 MB")
    /// </summary>
    public string TamanhoFormatado
    {
        get
        {
            if (TamanhoBytes < 1024)
                return $"{TamanhoBytes} B";
            if (TamanhoBytes < 1024 * 1024)
                return $"{TamanhoBytes / 1024.0:F1} KB";
            return $"{TamanhoBytes / (1024.0 * 1024.0):F1} MB";
        }
    }
}
