using System.Collections.Generic;
using System.Threading.Tasks;

namespace BioDesk.Services.Templates;

/// <summary>
/// Serviço para gestão de templates (emails, prescrições, relatórios)
/// </summary>
public interface ITemplateService
{
    /// <summary>
    /// Lista todos os templates de email disponíveis
    /// </summary>
    Task<List<TemplateEmail>> ListarTemplatesEmailAsync();

    /// <summary>
    /// Carrega um template específico por ID
    /// </summary>
    Task<TemplateEmail?> CarregarTemplateEmailAsync(string templateId);

    /// <summary>
    /// Preenche um template com dados do paciente
    /// </summary>
    Task<EmailPreenchido> PreencherTemplateEmailAsync(string templateId, int pacienteId, Dictionary<string, string>? dadosAdicionais = null);
}

/// <summary>
/// Informação básica de um template de email
/// </summary>
public class TemplateEmail
{
    public string Id { get; set; } = string.Empty;
    public string Nome { get; set; } = string.Empty;
    public string Categoria { get; set; } = string.Empty;
    public string Descricao { get; set; } = string.Empty;
    public string Versao { get; set; } = "1.0";
    public string Assunto { get; set; } = string.Empty;
    public string Corpo { get; set; } = string.Empty;
    public List<string> Variaveis { get; set; } = new();
}

/// <summary>
/// Email com template preenchido e pronto para envio
/// </summary>
public class EmailPreenchido
{
    public string Assunto { get; set; } = string.Empty;
    public string Corpo { get; set; } = string.Empty;
    public int PacienteId { get; set; }
    public string TemplateId { get; set; } = string.Empty;
}
