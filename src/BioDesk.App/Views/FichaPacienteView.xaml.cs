using System.Windows.Controls;

namespace BioDesk.App.Views;

/// <summary>
/// UserControl para ficha completa de paciente com navegação por separadores
/// Sistema de 6 abas sequenciais: Dados Biográficos → Declaração → Consentimentos → Consultas → Íris → Terapias
/// </summary>
public partial class FichaPacienteView : UserControl
{
    public FichaPacienteView()
    {
        InitializeComponent();
    }
}
