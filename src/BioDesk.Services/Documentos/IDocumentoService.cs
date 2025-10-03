using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BioDesk.Services.Documentos;

/// <summary>
/// Interface para serviço de gestão de documentos por paciente
/// </summary>
public interface IDocumentoService
{
    /// <summary>
    /// Obtém o caminho da pasta raiz de documentos de um paciente
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="nomePaciente">Nome do paciente (para criar pasta legível)</param>
    /// <returns>Caminho completo da pasta do paciente</returns>
    string ObterPastaPaciente(int pacienteId, string nomePaciente);

    /// <summary>
    /// Obtém o caminho de uma subpasta específica (Declarações, Consentimentos, etc.)
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="nomePaciente">Nome do paciente</param>
    /// <param name="subpasta">Nome da subpasta (TipoDocumento)</param>
    /// <returns>Caminho completo da subpasta</returns>
    string ObterSubpastaPaciente(int pacienteId, string nomePaciente, TipoDocumento subpasta);

    /// <summary>
    /// Cria a estrutura de pastas para um novo paciente
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="nomePaciente">Nome do paciente</param>
    /// <returns>True se criada com sucesso</returns>
    Task<bool> CriarEstruturaPastasPacienteAsync(int pacienteId, string nomePaciente);

    /// <summary>
    /// Abre a pasta do paciente no Windows Explorer
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="nomePaciente">Nome do paciente</param>
    /// <param name="subpasta">Subpasta específica a abrir (opcional)</param>
    Task AbrirPastaPacienteAsync(int pacienteId, string nomePaciente, TipoDocumento? subpasta = null);

    /// <summary>
    /// Lista todos os ficheiros na pasta do paciente
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="nomePaciente">Nome do paciente</param>
    /// <param name="subpasta">Filtrar por subpasta específica (opcional)</param>
    /// <returns>Lista de informações dos ficheiros</returns>
    Task<List<FicheiroInfo>> ListarFicheirosPacienteAsync(int pacienteId, string nomePaciente, TipoDocumento? subpasta = null);

    /// <summary>
    /// Copia um ficheiro para a pasta do paciente
    /// </summary>
    /// <param name="caminhoOrigem">Caminho do ficheiro original</param>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="nomePaciente">Nome do paciente</param>
    /// <param name="subpasta">Subpasta destino</param>
    /// <returns>Caminho do ficheiro copiado</returns>
    Task<string> CopiarFicheiroParaPacienteAsync(string caminhoOrigem, int pacienteId, string nomePaciente, TipoDocumento subpasta);

    /// <summary>
    /// Verifica se a pasta do paciente existe
    /// </summary>
    bool PastaExiste(int pacienteId, string nomePaciente);
}

/// <summary>
/// Tipos de documentos organizados em subpastas
/// </summary>
public enum TipoDocumento
{
    Declaracoes,
    Consentimentos,
    Prescricoes,
    Receitas,
    Relatorios,
    Analises,
    Outros
}

/// <summary>
/// Informação de um ficheiro na pasta do paciente
/// </summary>
public class FicheiroInfo
{
    public string Nome { get; set; } = string.Empty;
    public string CaminhoCompleto { get; set; } = string.Empty;
    public long TamanhoBytes { get; set; }
    public DateTime DataCriacao { get; set; }
    public DateTime DataModificacao { get; set; }
    public TipoDocumento Categoria { get; set; }
    public string Extensao { get; set; } = string.Empty;

    public string TamanhoFormatado => TamanhoBytes switch
    {
        < 1024 => $"{TamanhoBytes} B",
        < 1024 * 1024 => $"{TamanhoBytes / 1024.0:F1} KB",
        < 1024 * 1024 * 1024 => $"{TamanhoBytes / (1024.0 * 1024):F1} MB",
        _ => $"{TamanhoBytes / (1024.0 * 1024 * 1024):F1} GB"
    };
}
