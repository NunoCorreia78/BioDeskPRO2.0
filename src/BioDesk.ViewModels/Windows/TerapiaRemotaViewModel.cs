using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.Windows;

/// <summary>
/// ViewModel para modal de Terapia Remota (Informacional - sem Hz)
/// Usa seeds/RNG com anchor para transmissão à distância
/// </summary>
public partial class TerapiaRemotaViewModel : ObservableObject
{
    [ObservableProperty] private int _duracaoDias = 14; // Default 14 dias
    
    [ObservableProperty] private string _anchor = "Nome+DataNasc";
    
    [ObservableProperty] private string _hashAlgoritmo = "SHA256";
    
    [ObservableProperty] private string _modulacao = "Amplitude";
    
    [ObservableProperty] private int _ciclos = 1000;
    
    [ObservableProperty] private bool _emTransmissao;
    
    public ObservableCollection<string> HashAlgoritmos { get; } = new()
    {
        "SHA256",
        "MD5",
        "SHA512",
        "Blake2b"
    };
    
    public ObservableCollection<string> TiposModulacao { get; } = new()
    {
        "Amplitude",
        "Frequência",
        "Fase",
        "Pulse Width"
    };
    
    /// <summary>
    /// Protocolos selecionados para transmissão remota
    /// </summary>
    public ObservableCollection<string> ProtocolosSelecionados { get; } = new();
    
    [RelayCommand]
    private void IniciarTransmissao()
    {
        EmTransmissao = true;
        
        // TODO: Integrar com IResonanceEngine para transmissão informacional
        // - Criar seed com anchor (Nome+DataNasc ou custom)
        // - Configurar ScanConfig com protocolos selecionados
        // - Iniciar transmissão em background (duração: DuracaoDias)
        // - Persistir em SessionHistorico (TipoTerapia.Remota)
    }
    
    [RelayCommand]
    private void PararTransmissao()
    {
        EmTransmissao = false;
    }
}
