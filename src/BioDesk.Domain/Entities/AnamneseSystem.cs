using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Prioridade de um item na timeline e sistema de flags
/// </summary>
public enum Prioridade
{
    Baixa = 0,
    Media = 1,
    Alta = 2
}

/// <summary>
/// Flags de controlo para Expanders (nível superior - defaults)
/// </summary>
public class ExpanderFlags
{
    /// <summary>
    /// Incluir este expander no PDF oficial
    /// </summary>
    public bool IncluirNoPdf { get; set; } = true;

    /// <summary>
    /// Enviar conteúdo deste expander para a Timeline da sessão
    /// </summary>
    public bool EnviarParaTimeline { get; set; } = true;

    /// <summary>
    /// Prioridade padrão para items deste expander
    /// </summary>
    public Prioridade PrioridadePadrao { get; set; } = Prioridade.Media;

    /// <summary>
    /// Marcar como pretendido pelo paciente (destaque na timeline)
    /// </summary>
    public bool PretendidoPeloPaciente { get; set; } = false;

    /// <summary>
    /// Propor atualização do Painel Permanente com alterações deste expander
    /// </summary>
    public bool AtualizarPermanente { get; set; } = false;
}

/// <summary>
/// Flags de controlo para Items individuais (herda do expander + overrides)
/// </summary>
public class ItemFlags
{
    /// <summary>
    /// Incluir este item no PDF (null = herdar do expander)
    /// </summary>
    public bool? IncluirNoPdf { get; set; } = null;

    /// <summary>
    /// Enviar este item para Timeline (null = herdar do expander)
    /// </summary>
    public bool? EnviarParaTimeline { get; set; } = null;

    /// <summary>
    /// Prioridade específica deste item (null = herdar do expander)
    /// </summary>
    public Prioridade? Prioridade { get; set; } = null;

    /// <summary>
    /// Este item é pretendido pelo paciente (null = herdar do expander)
    /// </summary>
    public bool? PretendidoPeloPaciente { get; set; } = null;

    /// <summary>
    /// Este item deve propor atualização do Permanente (null = herdar do expander)
    /// </summary>
    public bool? AtualizarPermanente { get; set; } = null;

    /// <summary>
    /// Marcar para trabalhar especificamente hoje (força aparecer na Timeline)
    /// </summary>
    public bool TrabalharHoje { get; set; } = false;

    // Métodos helper para resolver herança
    public bool GetIncluirNoPdf(ExpanderFlags expanderDefault) => IncluirNoPdf ?? expanderDefault.IncluirNoPdf;
    public bool GetEnviarParaTimeline(ExpanderFlags expanderDefault) => EnviarParaTimeline ?? expanderDefault.EnviarParaTimeline;
    public Prioridade GetPrioridade(ExpanderFlags expanderDefault) => Prioridade ?? expanderDefault.PrioridadePadrao;
    public bool GetPretendidoPeloPaciente(ExpanderFlags expanderDefault) => PretendidoPeloPaciente ?? expanderDefault.PretendidoPeloPaciente;
    public bool GetAtualizarPermanente(ExpanderFlags expanderDefault) => AtualizarPermanente ?? expanderDefault.AtualizarPermanente;
}

/// <summary>
/// Dados de um item individual dentro de um expander
/// </summary>
public class ItemAnamnese : INotifyPropertyChanged
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Nome { get; set; } = string.Empty;
    public string Conteudo { get; set; } = string.Empty;
    public string TipoItem { get; set; } = string.Empty; // "sintoma", "medicacao", "alergia", etc.
    
    // Campos específicos por tipo
    public int? Intensidade { get; set; } // 0-10 para sintomas
    public string Estado { get; set; } = string.Empty; // "ativo", "resolvido", "cronico"
    public string Dose { get; set; } = string.Empty; // para medicações
    public DateTime? DataInicio { get; set; }
    public string Observacoes { get; set; } = string.Empty;

    // Sistema de flags (herança do expander)
    public ItemFlags Flags { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Dados de um expander (secção da anamnese)
/// </summary>
public class ExpanderAnamnese : INotifyPropertyChanged
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Titulo { get; set; } = string.Empty;
    public string Categoria { get; set; } = string.Empty; // "motivo", "sintomas", "medicacao", etc.
    public bool IsExpanded { get; set; } = false;
    
    // Sistema de flags (defaults para items)
    public ExpanderFlags Flags { get; set; } = new();
    
    // Items dentro deste expander
    public List<ItemAnamnese> Items { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Delta proposto para atualização do Painel Permanente
/// </summary>
public class DeltaPermanente
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Categoria { get; set; } = string.Empty; // "sintoma", "medicacao", "alergia"
    public string TipoOperacao { get; set; } = string.Empty; // "adicionar", "atualizar", "remover"
    public string Descricao { get; set; } = string.Empty; // "Adicionar Alergia: AINEs (moderada)?"
    public string ItemId { get; set; } = string.Empty; // referência ao item original
    public bool Confirmado { get; set; } = false;
}

/// <summary>
/// Item para a Timeline da sessão
/// </summary>
public class ItemTimeline
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Categoria { get; set; } = string.Empty;
    public string Titulo { get; set; } = string.Empty;
    public string Descricao { get; set; } = string.Empty;
    public Prioridade Prioridade { get; set; }
    public bool PretendidoPeloPaciente { get; set; }
    public bool TrabalharHoje { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string ItemOrigemId { get; set; } = string.Empty;
}