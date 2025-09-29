using Microsoft.Extensions.DependencyInjection;
using System.Windows.Controls;
using BioDesk.ViewModels.Abas;

namespace BioDesk.App.Views.Abas
{
    public partial class ConsentimentosUserControl : UserControl
    {
        public ConsentimentosUserControl()
        {
            InitializeComponent();

            // O DataContext será definido pelo container pai
            // Quando este controlo for usado na FichaPacienteView
        }

        /// <summary>
        /// Método para definir o ViewModel via DI (chamado pela view pai)
        /// </summary>
        internal void ConfigurarViewModel(ConsentimentosViewModel viewModel)
        {
            DataContext = viewModel;
        }
    }
}
