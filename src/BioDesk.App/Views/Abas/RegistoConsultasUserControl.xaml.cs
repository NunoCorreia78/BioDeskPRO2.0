using System.Windows.Controls;
using System.Windows;
using System.Threading.Tasks;
using BioDesk.ViewModels.Abas;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

public partial class RegistoConsultasUserControl : UserControl
{
    private readonly ILogger<RegistoConsultasUserControl> _logger;

    public RegistoConsultasUserControl()
    {
        InitializeComponent();

        // Obter logger do DI container
        _logger = ((App)Application.Current).ServiceProvider.GetRequiredService<ILogger<RegistoConsultasUserControl>>();
        Loaded += OnLoaded;
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

    /// <summary>
    /// 🚨 HANDLER DIAGNÓSTICO BRUTAL - TESTA SE BOTÃO RECEBE CLICK
    /// </summary>
    private async void BtnGerarPdf_Click(object sender, RoutedEventArgs e)
    {
        _logger.LogWarning("🎯 CLICK HANDLER INVOCADO!");

        // Tentar obter ViewModel do UserControl
        if (DataContext is RegistoConsultasViewModel vm)
        {
            _logger.LogWarning("✅ ViewModel encontrado! Invocando método diretamente...");

            // Chamar método privado via reflexão (hack temporário para diagnóstico)
            var method = vm.GetType().GetMethod("GerarPdfPrescricaoAsync",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            if (method != null)
            {
                _logger.LogWarning("✅ Método GerarPdfPrescricaoAsync encontrado! Invocando...");
                await (Task)(method.Invoke(vm, null) ?? Task.CompletedTask);
            }
            else
            {
                _logger.LogError("❌ Método GerarPdfPrescricaoAsync NÃO encontrado!");
                MessageBox.Show("❌ Método não encontrado via reflexão!", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        else
        {
            _logger.LogError("❌ DataContext NÃO é RegistoConsultasViewModel! É: {Type}", DataContext?.GetType().FullName ?? "NULL");
            MessageBox.Show(
                $"❌ DataContext ERRADO!\n\nTipo: {DataContext?.GetType().FullName ?? "NULL"}",
                "Erro DataContext",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    // ✅ BINDING XAML CONTROLA VISIBILITY DO MODAL AUTOMATICAMENTE
    // ✅ COMANDO PDF É BINDEADO VIA {Binding GerarPdfPrescricaoAsyncCommand}
}
