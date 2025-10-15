using BioDesk.Domain.Entities;
using CommunityToolkit.Mvvm.ComponentModel;

namespace BioDesk.Domain.DTOs;

/// <summary>
/// DTO para binding de protocolos com Value % (CoRe 5.0 scanning)
/// Usado no DataGrid de Value % Scanning
/// </summary>
public partial class ProtocoloComValue : ObservableObject
{
    /// <summary>
    /// Protocolo terapêutico original da base de dados
    /// </summary>
    public ProtocoloTerapeutico Protocolo { get; set; } = null!;

    /// <summary>
    /// Value % calculado pelo RNG (0-100)
    /// CoRe 5.0: média de 10 amostras RNG normalizadas
    /// </summary>
    public double ValuePercent { get; set; }

    /// <summary>
    /// Indica se o protocolo está selecionado para adicionar à fila
    /// CRITICAL: ObservableProperty para notificar mudanças
    /// </summary>
    [ObservableProperty]
    private bool _isSelected;

    /// <summary>
    /// Construtor para inicialização simples
    /// </summary>
    public ProtocoloComValue(ProtocoloTerapeutico protocolo, double valuePercent)
    {
        Protocolo = protocolo;
        ValuePercent = valuePercent;
        IsSelected = false;
    }

    /// <summary>
    /// Nome do protocolo (conveniência para binding)
    /// </summary>
    public string Nome => Protocolo.Nome;

    /// <summary>
    /// Categoria do protocolo (conveniência para binding)
    /// </summary>
    public string Categoria => Protocolo.Categoria!;

    /// <summary>
    /// ID do protocolo (conveniência para binding)
    /// </summary>
    public int ProtocoloId => Protocolo.Id;

    /// <summary>
    /// Número de frequências do protocolo
    /// </summary>
    public int NumeroFrequencias => Protocolo.GetFrequencias()?.Length ?? 0;

    /// <summary>
    /// ToString para debugging
    /// </summary>
    public override string ToString() => $"{Nome} - Value: {ValuePercent:N2}%";
}
