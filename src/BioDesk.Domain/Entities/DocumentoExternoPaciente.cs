using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Documentos externos trazidos/enviados pelo paciente
/// Ex: Análises sangue, ressonâncias, receitas médicas, relatórios outros especialistas
/// Guardados em: Pacientes/[Nome]/Documentos_Externos/
/// </summary>
public class DocumentoExternoPaciente
{
    public int Id { get; set; }

    /// <summary>
    /// Paciente a quem pertence o documento
    /// </summary>
    [Required]
    public int PacienteId { get; set; }

    /// <summary>
    /// Nome do arquivo original (ex: "Analises_Sangue.pdf")
    /// </summary>
    [Required]
    [StringLength(255)]
    public string NomeArquivo { get; set; } = string.Empty;

    /// <summary>
    /// Caminho relativo completo (ex: "Pacientes/João Carlos/Documentos_Externos/Analises_2024.pdf")
    /// </summary>
    [Required]
    [StringLength(500)]
    public string CaminhoArquivo { get; set; } = string.Empty;

    /// <summary>
    /// Descrição do documento (ex: "Análises de sangue - Dr. Silva - Cardiologia")
    /// </summary>
    [StringLength(500)]
    public string? Descricao { get; set; }

    /// <summary>
    /// Data do documento/exame (não confundir com data de upload)
    /// </summary>
    public DateTime? DataDocumento { get; set; }

    /// <summary>
    /// Categoria: "Análises" | "Imagiologia" | "Receitas" | "Relatórios" | "Outros"
    /// </summary>
    [StringLength(50)]
    public string Categoria { get; set; } = "Outros";

    /// <summary>
    /// Data em que foi feito upload
    /// </summary>
    public DateTime DataUpload { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Tamanho do ficheiro em bytes
    /// </summary>
    public long? TamanhoBytes { get; set; }

    /// <summary>
    /// Tipo MIME (ex: "application/pdf", "image/jpeg")
    /// </summary>
    [StringLength(100)]
    public string? TipoMime { get; set; }

    /// <summary>
    /// Soft delete
    /// </summary>
    public bool IsDeleted { get; set; } = false;

    /// <summary>
    /// Tamanho formatado para exibição (ex: "1.5 MB", "256 KB")
    /// </summary>
    [NotMapped]
    public string TamanhoFormatado
    {
        get
        {
            if (!TamanhoBytes.HasValue || TamanhoBytes.Value == 0)
                return "-";

            double bytes = TamanhoBytes.Value;
            string[] suffixes = { "B", "KB", "MB", "GB" };
            int suffixIndex = 0;

            while (bytes >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                bytes /= 1024;
                suffixIndex++;
            }

            return $"{bytes:0.##} {suffixes[suffixIndex]}";
        }
    }

    // === NAVEGAÇÃO ===
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;
}
