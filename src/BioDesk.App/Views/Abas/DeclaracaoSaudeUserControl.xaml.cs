using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using BioDesk.ViewModels.Abas;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// UserControl para Aba 2: Declaração de Saúde
/// Contém formulário completo de histórico médico e estilo de vida
/// </summary>
public partial class DeclaracaoSaudeUserControl : UserControl
{
    private bool _isDrawing = false;
    private bool _hasSignature = false;
    private Polyline? _currentStroke = null;

    public DeclaracaoSaudeUserControl()
    {
        InitializeComponent();
        Loaded += OnLoaded;

        // Configura o DataContext através do DI container
        if (Application.Current is App app && app.ServiceProvider != null)
        {
            DataContext = app.ServiceProvider.GetRequiredService<DeclaracaoSaudeViewModel>();
        }

        // Configura data atual no TextBox
        TxtDataDeclaracao.Text = DateTime.Now.ToString("dd/MM/yyyy");
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Subscrever eventos de mudança em todos os controles
        SubscribeToControlChanges(this);
    }

    /// <summary>
    /// Subscrever recursivamente a mudanças em TextBox, ComboBox e CheckBox
    /// para marcar formulário como "dirty" (IsDirty = true)
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

            // Recursivo para filhos
            SubscribeToControlChanges(child);
        }
    }

    /// <summary>
    /// Marcar formulário como alterado (IsDirty = true)
    /// </summary>
    private void OnControlValueChanged(object sender, RoutedEventArgs e)
    {
        // Obter o ViewModel principal da FichaPaciente
        var window = Window.GetWindow(this);
        if (window?.DataContext is BioDesk.ViewModels.FichaPacienteViewModel viewModel)
        {
            viewModel.MarcarComoAlterado();
        }
    }

    // ===== ASSINATURA DIGITAL =====

    private void AssinaturaCanvas_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
        {
            _isDrawing = true;
            _hasSignature = true;

            // Oculta as instruções
            AssinaturaInstrucoesDeclaracao.Visibility = Visibility.Collapsed;

            // Cria nova linha
            _currentStroke = new Polyline
            {
                Stroke = Brushes.Black,
                StrokeThickness = 2,
                StrokeLineJoin = PenLineJoin.Round,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            };

            Point startPoint = e.GetPosition(AssinaturaCanvasDeclaracao);
            _currentStroke.Points.Add(startPoint);
            AssinaturaCanvasDeclaracao.Children.Add(_currentStroke);
            AssinaturaCanvasDeclaracao.CaptureMouse();
        }
    }

    private void AssinaturaCanvas_MouseMove(object sender, MouseEventArgs e)
    {
        if (_isDrawing && _currentStroke != null && e.LeftButton == MouseButtonState.Pressed)
        {
            Point currentPoint = e.GetPosition(AssinaturaCanvasDeclaracao);
            _currentStroke.Points.Add(currentPoint);
        }
    }

    private void AssinaturaCanvas_MouseUp(object sender, MouseButtonEventArgs e)
    {
        if (_isDrawing)
        {
            _isDrawing = false;
            _currentStroke = null;
            AssinaturaCanvasDeclaracao.ReleaseMouseCapture();
        }
    }

    private void AssinaturaCanvas_MouseLeave(object sender, MouseEventArgs e)
    {
        if (_isDrawing)
        {
            _isDrawing = false;
            _currentStroke = null;
            AssinaturaCanvasDeclaracao.ReleaseMouseCapture();
        }
    }

    private void BtnLimparAssinatura_Click(object sender, RoutedEventArgs e)
    {
        AssinaturaCanvasDeclaracao.Children.Clear();
        AssinaturaInstrucoesDeclaracao.Visibility = Visibility.Visible;
        _hasSignature = false;
        TxtMensagemAssinatura.Visibility = Visibility.Collapsed;
    }

    private void BtnConfirmarDeclaracao_Click(object sender, RoutedEventArgs e)
    {
        // Validações
        if (string.IsNullOrWhiteSpace(TxtNomePacienteDeclaracao.Text))
        {
            MessageBox.Show("Por favor, insira o nome completo do paciente.",
                "Campo Obrigatório", MessageBoxButton.OK, MessageBoxImage.Warning);
            TxtNomePacienteDeclaracao.Focus();
            return;
        }

        if (!_hasSignature)
        {
            MessageBox.Show("Por favor, assine a declaração para confirmar.",
                "Assinatura Obrigatória", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(TxtDataDeclaracao.Text))
        {
            MessageBox.Show("Por favor, preencha a data da declaração.",
                "Campo Obrigatório", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Confirma a declaração
        TxtMensagemAssinatura.Text = $"✅ Declaração confirmada em {TxtDataDeclaracao.Text} por {TxtNomePacienteDeclaracao.Text}";
        TxtMensagemAssinatura.Visibility = Visibility.Visible;

        MessageBox.Show("Declaração de Saúde confirmada com sucesso!\n\nA assinatura digital foi registada.",
            "Declaração Confirmada", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
