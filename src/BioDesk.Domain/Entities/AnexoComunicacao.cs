using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um anexo de uma comunicação (PDF, imagem, documento)
/// </summary>
public class AnexoComunicacao
{
    public int Id { get; set; }

    /// <summary>
    /// Comunicação à qual o anexo pertence
    /// </summary>
    public int ComunicacaoId { get; set; }
    public Comunicacao Comunicacao { get; set; } = null!;

    /// <summary>
    /// Nome do arquivo
    /// </summary>
    [Required]
    [StringLength(255)]
    public string NomeArquivo { get; set; } = string.Empty;

    /// <summary>
    /// Caminho completo do arquivo no sistema
    /// Pode ser path local ou base64 se armazenado na DB
    /// </summary>
    [Required]
    public string CaminhoArquivo { get; set; } = string.Empty;

    /// <summary>
    /// Tipo MIME do arquivo (ex: application/pdf, image/jpeg)
    /// </summary>
    [StringLength(100)]
    public string TipoMime { get; set; } = "application/octet-stream";

    /// <summary>
    /// Tamanho do arquivo em bytes
    /// </summary>
    public long TamanhoBytes { get; set; }

    /// <summary>
    /// Data de criação do anexo
    /// </summary>
    public DateTime DataCriacao { get; set; } = DateTime.Now;

    /// <summary>
    /// Propriedade computed para exibir tamanho formatado
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
