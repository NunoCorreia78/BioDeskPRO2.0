using BioDesk.ViewModels;
using BioDesk.ViewModels.Abas;
using BioDesk.App.Views.Dialogs;
using Microsoft.Extensions.DependencyInjection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Linq;

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

            // ⭐ NOVO: Carregar histórico ao abrir a aba
            if (DataContext is ComunicacaoViewModel viewModel && viewModel.PacienteAtual != null)
            {
                _ = viewModel.SetPaciente(viewModel.PacienteAtual);
            }
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

        /// <summary>
        /// ⭐ NOVO: Handler para duplo-clique em documento → Abre PDF
        /// </summary>
        private void ListBoxDocumentos_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (DataContext is not ComunicacaoViewModel viewModel)
                return;

            // Obter documento clicado
            if (sender is ListBox listBox && listBox.SelectedItem is DocumentoPacienteViewModel documento)
            {
                viewModel.AbrirDocumentoCommand.Execute(documento);
            }
        }

        /// <summary>
        /// ⭐ NOVO: Abre pop-up de seleção de templates PDF
        /// </summary>
        private void BtnSelecionarTemplates_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is not ComunicacaoViewModel viewModel)
                return;

            if (viewModel.PacienteAtual == null)
            {
                MessageBox.Show(
                    "Nenhum paciente selecionado!",
                    "Aviso",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            try
            {
                // Criar e mostrar pop-up
                var window = new SelecionarTemplatesWindow
                {
                    Owner = Window.GetWindow(this)
                };

                if (window.ShowDialog() == true)
                {
                    var templatesSelecionados = window.TemplatesSelecionados;

                    if (templatesSelecionados.Any())
                    {
                        // Adicionar templates aos anexos do ViewModel
                        foreach (var template in templatesSelecionados)
                        {
                            if (!viewModel.Anexos.Contains(template.CaminhoCompleto))
                            {
                                viewModel.Anexos.Add(template.CaminhoCompleto);
                            }
                        }

                        // ✅ Atualizar status de anexos após adicionar
                        viewModel.AtualizarStatusAnexos();

                        // Feedback visual
                        MessageBox.Show(
                            $"✅ {templatesSelecionados.Count} template(s) adicionado(s) como anexo(s)!",
                            "Sucesso",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                }
            }
            catch (System.Exception ex)
            {
                MessageBox.Show(
                    $"Erro ao selecionar templates: {ex.Message}",
                    "Erro",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}
