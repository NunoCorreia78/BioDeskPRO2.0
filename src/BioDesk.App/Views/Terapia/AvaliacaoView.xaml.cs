using System.Windows.Controls;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Windows;
using BioDesk.App.Windows;

namespace BioDesk.App.Views.Terapia;

public partial class AvaliacaoView : UserControl
{
    public AvaliacaoView()
    {
        InitializeComponent();

        // Escutar evento de solicitação de terapia remota
        Loaded += (s, e) =>
        {
            if (DataContext is AvaliacaoViewModel vm)
            {
                vm.TerapiaRemotaRequested += OnTerapiaRemotaRequested;
            }
        };

        Unloaded += (s, e) =>
        {
            if (DataContext is AvaliacaoViewModel vm)
            {
                vm.TerapiaRemotaRequested -= OnTerapiaRemotaRequested;
            }
        };
    }

    private void OnTerapiaRemotaRequested(object? sender, TerapiaRemotaRequestedEventArgs e)
    {
        // Criar ViewModel do modal e popular com protocolos selecionados
        var viewModel = new TerapiaRemotaViewModel();
        foreach (var protocolo in e.ProtocolosSelecionados)
        {
            viewModel.ProtocolosSelecionados.Add(protocolo);
        }

        // Abrir modal
        var window = new TerapiaRemotaWindow
        {
            DataContext = viewModel,
            Owner = System.Windows.Window.GetWindow(this)
        };
        window.ShowDialog();
    }
}
