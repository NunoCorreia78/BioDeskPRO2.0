using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Sistema de Questionário Completo - 11 Expanders
/// Implementado conforme especificação detalhada PT-PT
/// </summary>
public class QuestionarioCompleto : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    // 11 EXPANDERS PRINCIPAIS
    public IdentificacaoExpander Identificacao { get; set; } = new();        // 🔴 Crítico
    public MotivoExpander Motivo { get; set; } = new();                      // 🔴 Crítico
    public HQAExpander HistoriaQueixaAtual { get; set; } = new();            // 🔴 Crítico
    public SintomasExpander Sintomas { get; set; } = new();                 // 🟡 Importante
    public AlergiasExpander Alergias { get; set; } = new();                 // 🔴 Crítico
    public CondicoesCronicasExpander Cronicas { get; set; } = new();        // 🔴 Crítico
    public MedicacaoExpander Medicacao { get; set; } = new();               // 🔴 Crítico
    public CirurgiasExpander Cirurgias { get; set; } = new();               // 🟡 Importante
    public HistoriaFamiliarExpander HistoriaFamiliar { get; set; } = new(); // 🟡 Importante
    public EstiloVidaExpander EstiloVida { get; set; } = new();             // 🟡 Importante
    public FuncoesBiologicasExpander FuncoesBiol { get; set; } = new();     // 🟡 Importante
    public ExamesExpander Exames { get; set; } = new();                     // 🟡 Importante

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Tipos de input conforme especificação
/// TXT (texto curto) · TXTL (texto longo) · CHIP (chips multi) · DD (dropdown) · MS (multi-select) 
/// SL (slider) · NUM (número) · DAT (data) · HOR (hora) · TOG (toggle) · CHK (checkbox) · ANN (anexo)
/// </summary>
public enum TipoInput
{
    TXT,   // Texto curto
    TXTL,  // Texto longo
    CHIP,  // Chips multi-select
    DD,    // Dropdown
    MS,    // Multi-select
    SL,    // Slider
    NUM,   // Número
    DAT,   // Data
    HOR,   // Hora
    TOG,   // Toggle
    CHK,   // Checkbox
    ANN    // Anexo
}

/// <summary>
/// Obrigatoriedade: (OBR) obrigatório · (OPT) opcional
/// </summary>
public enum Obrigatoriedade
{
    OBR,   // Obrigatório
    OPT    // Opcional
}

/// <summary>
/// Prioridade clínica: 🔴 Crítico (PDF sempre) · 🟡 Importante (Timeline) · 🟢 Complementar (só se marcado)
/// </summary>
public enum PrioridadeClinica
{
    Critico,        // 🔴 Entra sempre no PDF
    Importante,     // 🟡 Entra por defeito na Timeline
    Complementar    // 🟢 Só se marcado
}

// Enum Prioridade já existe no AnamneseSystem.cs

/// <summary>
/// Sistema de Flags conforme especificação
/// [PDF] Incluir no PDF · [TL] Timeline · [PERM] Permanente · [❤] Pretendido · [HOJE] Trabalhar hoje
/// </summary>
public class FlagSystem : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private bool _pdf = false;
    private bool _timeline = false;
    private bool _permanente = false;
    private bool _pretendido = false;
    private bool _trabalharHoje = false;
    private Prioridade _prioridade = Prioridade.Media;

    public bool PDF
    {
        get => _pdf;
        set { _pdf = value; OnPropertyChanged(); }
    }

    public bool Timeline
    {
        get => _timeline;
        set { _timeline = value; OnPropertyChanged(); }
    }

    public bool Permanente
    {
        get => _permanente;
        set { _permanente = value; OnPropertyChanged(); }
    }

    public bool Pretendido
    {
        get => _pretendido;
        set { _pretendido = value; OnPropertyChanged(); }
    }

    public bool TrabalharHoje
    {
        get => _trabalharHoje;
        set { _trabalharHoje = value; OnPropertyChanged(); }
    }

    public Prioridade Prioridade
    {
        get => _prioridade;
        set { _prioridade = value; OnPropertyChanged(); }
    }

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Base para todos os expanders
/// </summary>
public abstract class ExpanderBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private bool _isExpanded = false;
    private FlagSystem _flags = new();

    public bool IsExpanded
    {
        get => _isExpanded;
        set { _isExpanded = value; OnPropertyChanged(); }
    }

    public FlagSystem Flags
    {
        get => _flags;
        set { _flags = value; OnPropertyChanged(); }
    }

    public abstract PrioridadeClinica PrioridadeClinica { get; }
    public abstract string NomeExpander { get; }

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}