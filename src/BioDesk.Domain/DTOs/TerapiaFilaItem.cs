using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioDesk.Domain.DTOs;

/// <summary>
/// DTO para binding de item na fila de execução de terapias
/// Usado no DataGrid de Fila de Execução com drag-drop
/// OBSERVÁVEL: Implementa INotifyPropertyChanged para atualização em tempo real
/// </summary>
public class TerapiaFilaItem : INotifyPropertyChanged
{
    /// <summary>
    /// ID do protocolo terapêutico
    /// </summary>
    public int ProtocoloId { get; set; }

    /// <summary>
    /// Ordem na fila de execução (1-based)
    /// Atualizado automaticamente ao reordenar (drag-drop)
    /// </summary>
    public int Ordem { get; set; }

    /// <summary>
    /// Nome do protocolo terapêutico
    /// </summary>
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Value % inicial (do Value Scanning)
    /// </summary>
    public double ValuePercent { get; set; }

    private double _improvementPercent;

    /// <summary>
    /// Improvement % atual (calculado em tempo real durante aplicação)
    /// Fórmula CoRe: (LeituraAtual - Baseline) / Baseline * 100
    /// OBSERVÁVEL: Notifica mudanças para UI
    /// </summary>
    public double ImprovementPercent
    {
        get => _improvementPercent;
        set
        {
            if (Math.Abs(_improvementPercent - value) > 0.01)
            {
                _improvementPercent = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(AtingiuAlvo));
            }
        }
    }

    private double _alvoMelhoria = 95.0;

    /// <summary>
    /// Alvo de melhoria (%) para auto-stop
    /// Default: 95% (CoRe 5.0 standard)
    /// Configurável: 80%, 95%, 100%
    /// OBSERVÁVEL: Notifica mudanças para UI
    /// </summary>
    public double AlvoMelhoria
    {
        get => _alvoMelhoria;
        set
        {
            if (Math.Abs(_alvoMelhoria - value) > 0.01)
            {
                _alvoMelhoria = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(AtingiuAlvo)); // Alvo muda → AtingiuAlvo recalcular
            }
        }
    }

    private string _estado = "Aguardando";

    /// <summary>
    /// Estado da terapia:
    /// - "Aguardando" (cinza)
    /// - "Em Execução" (azul)
    /// - "Concluída" (verde)
    /// - "Auto-Stop" (verde claro) - quando Improvement >= Alvo
    /// - "Parada" (amarelo) - interrompida manualmente
    /// OBSERVÁVEL: Notifica mudanças para UI
    /// </summary>
    public string Estado
    {
        get => _estado;
        set
        {
            if (_estado != value)
            {
                _estado = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(EstadoCor));
                OnPropertyChanged(nameof(IsRemovable));
            }
        }
    }

    /// <summary>
    /// Timestamp de quando foi aplicada
    /// </summary>
    public DateTime? AplicadoEm { get; set; }

    /// <summary>
    /// Duração total da aplicação (segundos)
    /// </summary>
    public int? DuracaoSegundos { get; set; }

    /// <summary>
    /// Indica se já foi aplicada (para histórico)
    /// </summary>
    public bool Aplicada => AplicadoEm.HasValue;

    /// <summary>
    /// Indica se atingiu o alvo de melhoria (auto-stop)
    /// </summary>
    public bool AtingiuAlvo => ImprovementPercent >= AlvoMelhoria;

    /// <summary>
    /// Indica se pode ser removido da fila
    /// Apenas protocolos "Aguardando" podem ser removidos
    /// </summary>
    public bool IsRemovable => Estado == "Aguardando";

    /// <summary>
    /// Cor do estado (para binding UI)
    /// </summary>
    public string EstadoCor => Estado switch
    {
        "Aguardando" => "#5A6558",    // TextoSecundario
        "Em Execução" => "#6B9F5F",   // BotaoPrimario
        "Concluída" => "#4A7C59",     // Verde escuro
        "Auto-Stop" => "#7FB069",     // Verde claro
        "Parada" => "#C9A961",        // Amarelo
        _ => "#5A6558"
    };

    /// <summary>
    /// Construtor com valores obrigatórios
    /// </summary>
    public TerapiaFilaItem(int protocoloId, string nome, double valuePercent, int ordem)
    {
        ProtocoloId = protocoloId;
        Nome = nome;
        ValuePercent = valuePercent;
        Ordem = ordem;
    }

    /// <summary>
    /// ToString para debugging
    /// </summary>
    public override string ToString() =>
        $"#{Ordem} - {Nome} | Value: {ValuePercent:N2}% | Improvement: {ImprovementPercent:N2}% | {Estado}";

    #region INotifyPropertyChanged

    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    #endregion
}
