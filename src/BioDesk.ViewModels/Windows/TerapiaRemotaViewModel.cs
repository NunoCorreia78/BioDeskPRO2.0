using System;
using System.Collections.ObjectModel;
using System.Text.Json;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.Windows;

/// <summary>
/// ViewModel para modal de Terapia Remota (Informacional - sem Hz)
/// Usa seeds/RNG com anchor para transmissão à distância
/// </summary>
public partial class TerapiaRemotaViewModel : ObservableObject
{
    private readonly ISessionHistoricoRepository? _sessionRepository;
    
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
    
    public TerapiaRemotaViewModel() { }
    
    public TerapiaRemotaViewModel(ISessionHistoricoRepository sessionRepository)
    {
        _sessionRepository = sessionRepository;
    }
    
    [RelayCommand]
    private async Task IniciarTransmissaoAsync()
    {
        EmTransmissao = true;
        
        // TODO: Integrar com IResonanceEngine para transmissão informacional
        // - Criar seed com anchor (Nome+DataNasc ou custom)
        // - Configurar ScanConfig com protocolos selecionados
        // - Iniciar transmissão em background (duração: DuracaoDias)
        
        // 📊 Persistir em SessionHistorico
        if (_sessionRepository != null)
        {
            try
            {
                var protocolos = new System.Collections.Generic.List<string>(ProtocolosSelecionados);
                
                var session = new SessionHistorico
                {
                    DataHoraInicio = DateTime.Now,
                    TipoTerapia = TipoTerapia.Remota,
                    ProtocolosJson = JsonSerializer.Serialize(protocolos),
                    DuracaoMinutos = DuracaoDias * 24 * 60, // Converter dias para minutos
                    Notas = $"Anchor: {Anchor}, Hash: {HashAlgoritmo}, Modulação: {Modulacao}, Ciclos: {Ciclos}"
                };
                
                await _sessionRepository.AddAsync(session);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Erro ao persistir SessionHistorico: {ex.Message}");
            }
        }
    }
    
    [RelayCommand]
    private void PararTransmissao()
    {
        EmTransmissao = false;
    }
}
