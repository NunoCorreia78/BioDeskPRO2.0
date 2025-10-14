using System.Windows.Controls;
using BioDesk.ViewModels.UserControls;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// Interaction logic for TerapiasBioenergeticasUserControl.xaml
/// </summary>
public partial class TerapiasBioenergeticasUserControl : UserControl
{
    public TerapiasBioenergeticasUserControl(TerapiasBioenergeticasUserControlViewModel viewModel)
    {
        System.Diagnostics.Debug.WriteLine($"🔥 TERAPIAS UserControl CONSTRUTOR - ViewModel: {viewModel != null}");
        InitializeComponent();
        DataContext = viewModel;
        System.Diagnostics.Debug.WriteLine($"🔥 TERAPIAS UserControl DataContext DEFINIDO: {DataContext != null}");

        if (viewModel != null)
        {
            System.Diagnostics.Debug.WriteLine($"🔥 ViewModel tem ProtocolosScanned: {viewModel.ProtocolosScanned != null}");
            System.Diagnostics.Debug.WriteLine($"🔥 ViewModel tem ScanValuesCommand: {viewModel.ScanValuesCommand != null}");
        }
    }
}
