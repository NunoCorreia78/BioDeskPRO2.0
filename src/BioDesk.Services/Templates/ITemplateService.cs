using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BioDesk.Services.Templates;

/// <summary>
/// Serviço para gestão de templates PDF (exercícios, dietas, prescrições, etc.)
/// Templates são ficheiros PDF armazenados em Templates/ na raiz do projeto
/// </summary>
public interface ITemplateService
{
    /// <summary>
    /// Lista todos os templates disponíveis em Templates/
    /// </summary>
    Task<List<TemplateInfo>> ListarTemplatesAsync();

    /// <summary>
    /// Envia template PDF para paciente por e-mail
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="templateNome">Nome do template (ex: "Exercicios_Escoliose.pdf")</param>
    /// <param name="emailDestinatario">E-mail do destinatário (opcional, usa email do paciente se null)</param>
    /// <param name="assunto">Assunto do e-mail (opcional, usa assunto padrão se null)</param>
    /// <param name="mensagem">Corpo do e-mail (opcional, usa mensagem padrão se null)</param>
    /// <returns>True se enviado com sucesso</returns>
    Task<bool> EnviarTemplateParaPacienteAsync(
        int pacienteId, 
        string templateNome, 
        string? emailDestinatario = null,
        string? assunto = null,
        string? mensagem = null);

    /// <summary>
    /// Copia template para pasta do paciente (Pacientes/{NomeCompleto}/Documentos/)
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="templateNome">Nome do template</param>
    /// <returns>Caminho completo do ficheiro copiado</returns>
    Task<string> CopiarTemplateParaPacienteAsync(int pacienteId, string templateNome);

    /// <summary>
    /// Verifica se um template existe
    /// </summary>
    bool TemplateExiste(string templateNome);

    /// <summary>
    /// Obtém o caminho completo de um template
    /// </summary>
    string? ObterCaminhoTemplate(string templateNome);
}

/// <summary>
/// Informação sobre um template disponível
/// </summary>
public class TemplateInfo
{
    public string Nome { get; set; } = string.Empty;
    public string NomeAmigavel { get; set; } = string.Empty; // Nome sem extensão, formatado
    public string CaminhoCompleto { get; set; } = string.Empty;
    public long TamanhoBytes { get; set; }
    public DateTime DataCriacao { get; set; }
    public string Categoria { get; set; } = "Geral"; // Ex: "Exercícios", "Dietas", "Prescrições"
    public string Descricao { get; set; } = string.Empty;

    /// <summary>
    /// Tamanho formatado (ex: "1.2 MB")
    /// </summary>
    public string TamanhoFormatado
    {
        get
        {
            if (TamanhoBytes < 1024) return $"{TamanhoBytes} B";
            if (TamanhoBytes < 1024 * 1024) return $"{TamanhoBytes / 1024.0:F1} KB";
            return $"{TamanhoBytes / (1024.0 * 1024.0):F1} MB";
        }
    }
}
