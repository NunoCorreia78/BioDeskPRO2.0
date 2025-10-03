using System;
using System.Collections.Generic;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma imagem de íris capturada para irisdiagnóstico
/// </summary>
public class IrisImagem
{
    public int Id { get; set; }

    /// <summary>
    /// ID do paciente (FK para Paciente)
    /// </summary>
    public int PacienteId { get; set; }

    /// <summary>
    /// Olho capturado: "Esquerdo" ou "Direito"
    /// </summary>
    public string Olho { get; set; } = string.Empty;

    /// <summary>
    /// Data e hora da captura
    /// </summary>
    public DateTime DataCaptura { get; set; }

    /// <summary>
    /// Caminho relativo da imagem no sistema de ficheiros
    /// </summary>
    public string CaminhoImagem { get; set; } = string.Empty;

    /// <summary>
    /// Observações sobre a imagem (opcional)
    /// </summary>
    public string? Observacoes { get; set; }

    // Navegação
    public virtual Paciente? Paciente { get; set; }
    public virtual ICollection<IrisMarca> Marcas { get; set; } = new List<IrisMarca>();
}
