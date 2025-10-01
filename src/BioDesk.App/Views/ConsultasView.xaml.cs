using BioDesk.ViewModels.Abas;
using Microsoft.Extensions.Logging;
using System.Windows.Controls;

namespace BioDesk.App.Views;

/// <summary>
/// Interaction logic for ConsultasView.xaml
/// Aba 4: Registo de Consultas/Sessões Clínicas com sistema multi-abordagem
/// </summary>
public partial class ConsultasView : UserControl
{
    private readonly ILogger<ConsultasView>? _logger;

    public ConsultasView()
    {
        InitializeComponent();
    }

    public ConsultasView(RegistoConsultasViewModel viewModel, ILogger<ConsultasView> logger) : this()
    {
        DataContext = viewModel;
        _logger = logger;
        _logger?.LogInformation("ConsultasView inicializada com RegistoConsultasViewModel injetado");
    }
}