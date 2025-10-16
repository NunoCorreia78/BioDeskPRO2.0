using System.Windows;
using BioDesk.ViewModels.UserControls.Terapia;
using HistoricoVM = BioDesk.ViewModels.Windows.HistoricoViewModel;
using TerapiaRemotaVM = BioDesk.ViewModels.Windows.TerapiaRemotaViewModel;
using TerapiaLocalVM = BioDesk.ViewModels.Windows.TerapiaLocalViewModel;
using BiofeedbackSessionVM = BioDesk.ViewModels.Windows.BiofeedbackSessionViewModel;

namespace BioDesk.App.Windows;

/// <summary>
/// Modal para visualizar Histórico de Sessões Terapêuticas
/// Permite filtrar por data/tipo e repetir sessões anteriores
/// </summary>
public partial class HistoricoWindow : Window
{
    public HistoricoWindow()
    {
        InitializeComponent();
        
        // Carregar sessões ao abrir
        Loaded += async (s, e) =>
        {
            if (DataContext is HistoricoVM vm)
            {
                await vm.LoadSessionsCommand.ExecuteAsync(null);
            }
        };
    }
    
    /// <summary>
    /// Constructor com ViewModel (para DI)
    /// </summary>
    public HistoricoWindow(HistoricoVM viewModel) : this()
    {
        DataContext = viewModel;
        
        // Subscrever eventos para abrir modais apropriados
        viewModel.TerapiaRemotaRequested += OnTerapiaRemotaRequested;
        viewModel.TerapiaLocalRequested += OnTerapiaLocalRequested;
        viewModel.BiofeedbackSessaoRequested += OnBiofeedbackSessaoRequested;
    }
    
    private void OnTerapiaRemotaRequested(object? sender, TerapiaRemotaRequestedEventArgs e)
    {
        var vm = new TerapiaRemotaVM();
        foreach (var protocolo in e.ProtocolosSelecionados)
        {
            vm.ProtocolosSelecionados.Add(protocolo);
        }
        
        var window = new TerapiaRemotaWindow { DataContext = vm, Owner = this };
        window.ShowDialog();
    }
    
    private void OnTerapiaLocalRequested(object? sender, TerapiaLocalRequestedEventArgs e)
    {
        var vm = new TerapiaLocalVM();
        foreach (var freq in e.Frequencias)
        {
            vm.Frequencias.Add(new BioDesk.ViewModels.Windows.FrequenciaStep(
                freq.Hz,
                (int)freq.DutyPercent,
                (int)freq.DuracaoSegundos
            ));
        }
        
        var window = new TerapiaLocalWindow { DataContext = vm, Owner = this };
        window.ShowDialog();
    }
    
    private void OnBiofeedbackSessaoRequested(object? sender, BiofeedbackSessaoRequestedEventArgs e)
    {
        var vm = new BiofeedbackSessionVM();
        var window = new BiofeedbackSessionWindow { DataContext = vm, Owner = this };
        window.ShowDialog();
    }
}
