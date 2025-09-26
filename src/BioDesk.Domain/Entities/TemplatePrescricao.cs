using System;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Template de prescrição para facilitar a criação de receitas padrão
/// </summary>
public class TemplatePrescricao
{
    public int Id { get; set; }
    public string Nome { get; set; } = string.Empty;
    public string Categoria { get; set; } = string.Empty; // "Lombalgia", "Ansiedade", etc.
    public string Conteudo { get; set; } = string.Empty;
    public string Descricao { get; set; } = string.Empty;
    public bool Ativo { get; set; } = true;
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;
}