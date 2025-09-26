using Microsoft.Extensions.Logging;
using System.Windows.Controls;

namespace BioDesk.App.Views;

/// <summary>
/// Interaction logic for ConsultasView.xaml
/// Interface de gestão de consultas médicas com filtros, agenda e CRUD completo
/// </summary>
public partial class ConsultasView : UserControl
{
    private readonly ILogger<ConsultasView>? _logger;

    public ConsultasView()
    {
        InitializeComponent();
    }

    public ConsultasView(ILogger<ConsultasView> logger) : this()
    {
        _logger = logger;
        _logger?.LogInformation("ConsultasView inicializada com sucesso");
    }
}