using System;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um documento (PDF) associado a um paciente.
/// Usado para listar ficheiros das pastas Consentimentos/, Prescricoes/, Pacientes/[Nome]/
/// </summary>
public class DocumentoPaciente
{
    /// <summary>
    /// ID do paciente proprietário do documento
    /// </summary>
    public int PacienteId { get; set; }

    /// <summary>
    /// Nome do ficheiro (ex: "Consentimento_Naturopatia_JoaoSilva_20251001.pdf")
    /// </summary>
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Caminho absoluto do ficheiro no sistema
    /// </summary>
    public string CaminhoCompleto { get; set; } = string.Empty;

    /// <summary>
    /// Data de criação do ficheiro
    /// </summary>
    public DateTime DataCriacao { get; set; }

    /// <summary>
    /// Tipo de documento
    /// </summary>
    public TipoDocumentoEnum Tipo { get; set; }

    /// <summary>
    /// Tamanho do ficheiro em bytes
    /// </summary>
    public long Tamanho { get; set; }
}

/// <summary>
/// Tipos de documentos reconhecidos pelo sistema (para listagem)
/// </summary>
public enum TipoDocumentoEnum
{
    Consentimento,
    Prescricao,
    Declaracao,
    Analise,
    Outro
}
