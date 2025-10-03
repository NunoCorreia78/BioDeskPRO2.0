using BioDesk.ViewModels.Abas;
using Microsoft.Extensions.DependencyInjection;
using System.Windows;
using System.Windows.Controls;

namespace BioDesk.App.Views.Abas
{
    public partial class ComunicacaoUserControl : UserControl
    {
        public ComunicacaoUserControl()
        {
            InitializeComponent();
            Loaded += OnLoaded;

            // Resolve ViewModel do DI container
            var app = (App)Application.Current;
            if (app.ServiceProvider != null)
            {
                DataContext = app.ServiceProvider.GetRequiredService<ComunicacaoViewModel>();
            }
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            // Subscrever eventos de mudança em todos os controles
            SubscribeToControlChanges(this);
        }

        /// <summary>
        /// Subscrever recursivamente a mudanças em TextBox, ComboBox e CheckBox
        /// </summary>
        private void SubscribeToControlChanges(DependencyObject parent)
        {
            int childCount = System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < childCount; i++)
            {
                var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);

                if (child is TextBox textBox)
                {
                    textBox.TextChanged -= OnControlValueChanged;
                    textBox.TextChanged += OnControlValueChanged;
                }
                else if (child is ComboBox comboBox)
                {
                    comboBox.SelectionChanged -= OnControlValueChanged;
                    comboBox.SelectionChanged += OnControlValueChanged;
                }
                else if (child is CheckBox checkBox)
                {
                    checkBox.Checked -= OnControlValueChanged;
                    checkBox.Unchecked -= OnControlValueChanged;
                    checkBox.Checked += OnControlValueChanged;
                    checkBox.Unchecked += OnControlValueChanged;
                }

                SubscribeToControlChanges(child);
            }
        }

        private void OnControlValueChanged(object sender, RoutedEventArgs e)
        {
            var window = Window.GetWindow(this);
            if (window?.DataContext is BioDesk.ViewModels.FichaPacienteViewModel viewModel)
            {
                viewModel.MarcarComoAlterado();
            }
        }
    }
}
