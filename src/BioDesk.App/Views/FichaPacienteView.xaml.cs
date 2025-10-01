using System.Windows.Controls;
using System.Windows;
using BioDesk.ViewModels;
using BioDesk.ViewModels.Abas;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views;

/// <summary>
/// UserControl para ficha completa de paciente com navegação por separadores
/// Sistema de 6 abas sequenciais: Dados Biográficos → Declaração → Consentimentos → Consultas → Comunicação → Terapias
/// </summary>
public partial class FichaPacienteView : UserControl
{
    private RegistoConsultasViewModel? _registoConsultasViewModel;
    private ComunicacaoViewModel? _comunicacaoViewModel;
    private DeclaracaoSaudeViewModel? _declaracaoSaudeViewModel;
    private ConsentimentosViewModel? _consentimentosViewModel;

    public FichaPacienteView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private async void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        // Unsubscribe do ViewModel anterior
        if (e.OldValue is FichaPacienteViewModel oldViewModel)
        {
            oldViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        // Subscribe ao novo ViewModel
        if (e.NewValue is FichaPacienteViewModel newViewModel)
        {
            newViewModel.PropertyChanged += OnViewModelPropertyChanged;
            // Atualizar imediatamente com o valor atual
            AtualizarVisibilidadeAbas(newViewModel.AbaAtiva);

            // ✅ CORREÇÃO: Obter ViewModels via App ServiceProvider (só uma vez)
            var app = (App)Application.Current;

            if (_registoConsultasViewModel == null)
            {
                _registoConsultasViewModel = app.ServiceProvider?.GetRequiredService<RegistoConsultasViewModel>();
            }

            if (_comunicacaoViewModel == null)
            {
                _comunicacaoViewModel = app.ServiceProvider?.GetRequiredService<ComunicacaoViewModel>();
            }

            if (_declaracaoSaudeViewModel == null)
            {
                _declaracaoSaudeViewModel = app.ServiceProvider?.GetRequiredService<DeclaracaoSaudeViewModel>();
            }

            if (_consentimentosViewModel == null)
            {
                _consentimentosViewModel = app.ServiceProvider?.GetRequiredService<ConsentimentosViewModel>();
            }

            // ✅ Configurar DataContext dos UserControls
            if (DeclaracaoSaudeUserControl != null && _declaracaoSaudeViewModel != null)
            {
                DeclaracaoSaudeUserControl.DataContext = _declaracaoSaudeViewModel;
            }

            if (ConsentimentosUserControl != null && _consentimentosViewModel != null)
            {
                ConsentimentosUserControl.DataContext = _consentimentosViewModel;
            }

            // ✅ Configurar DataContext do UserControl de Consultas
            if (RegistoConsultasUserControl != null && _registoConsultasViewModel != null)
            {
                RegistoConsultasUserControl.DataContext = _registoConsultasViewModel;

                // Passar paciente para o ViewModel de Consultas
                if (newViewModel.PacienteAtual != null)
                {
                    _registoConsultasViewModel.SetPaciente(newViewModel.PacienteAtual);
                }
            }

            // ✅ Configurar DataContext do UserControl de Comunicação
            if (ComunicacaoUserControl != null && _comunicacaoViewModel != null)
            {
                ComunicacaoUserControl.DataContext = _comunicacaoViewModel;

                // Passar paciente para o ViewModel de Comunicação (async)
                if (newViewModel.PacienteAtual != null)
                {
                    await _comunicacaoViewModel.SetPaciente(newViewModel.PacienteAtual);
                }
            }

            // ✅ NOVO: Passar nome do paciente para Declaração e Consentimentos
            if (newViewModel.PacienteAtual != null)
            {
                var nomePaciente = newViewModel.PacienteAtual.NomeCompleto ?? string.Empty;

                _declaracaoSaudeViewModel?.SetPacienteNome(nomePaciente);
                _consentimentosViewModel?.SetPacienteNome(nomePaciente);
            }
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(FichaPacienteViewModel.AbaAtiva) &&
            sender is FichaPacienteViewModel viewModel)
        {
            AtualizarVisibilidadeAbas(viewModel.AbaAtiva);
        }
    }

    private void AtualizarVisibilidadeAbas(int abaAtiva)
    {
        // CONTROLO DIRETO - SEM CONVERTERS
        System.Diagnostics.Debug.WriteLine($"🔧 CODE-BEHIND: Mudando para aba {abaAtiva}");

        // ✅ NOVO: Atualizar nome do paciente ao mudar para abas que precisam
        if (DataContext is FichaPacienteViewModel viewModel && viewModel.PacienteAtual != null)
        {
            var nomePaciente = viewModel.PacienteAtual.NomeCompleto ?? string.Empty;

            if (abaAtiva == 2 && _declaracaoSaudeViewModel != null)
            {
                _declaracaoSaudeViewModel.SetPacienteNome(nomePaciente);
            }
            else if (abaAtiva == 3 && _consentimentosViewModel != null)
            {
                _consentimentosViewModel.SetPacienteNome(nomePaciente);
            }
        }

        // Todos invisíveis primeiro
        DadosBiograficosUserControl.Visibility = Visibility.Collapsed;
        DeclaracaoSaudeUserControl.Visibility = Visibility.Collapsed;
        ConsentimentosUserControl.Visibility = Visibility.Collapsed;
        if (RegistoConsultasUserControl != null)
            RegistoConsultasUserControl.Visibility = Visibility.Collapsed;
        if (ComunicacaoUserControl != null)
            ComunicacaoUserControl.Visibility = Visibility.Collapsed;

        // Mostrar o correto
        switch (abaAtiva)
        {
            case 1:
                DadosBiograficosUserControl.Visibility = Visibility.Visible;
                System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: DadosBiograficos VISÍVEL");
                break;
            case 2:
                DeclaracaoSaudeUserControl.Visibility = Visibility.Visible;
                System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: DeclaracaoSaude VISÍVEL");
                break;
            case 3:
                ConsentimentosUserControl.Visibility = Visibility.Visible;
                System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: Consentimentos VISÍVEL");
                break;
            case 4:
                if (RegistoConsultasUserControl != null)
                {
                    RegistoConsultasUserControl.Visibility = Visibility.Visible;
                    System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: RegistoConsultas VISÍVEL");
                }
                break;
            case 5:
                if (ComunicacaoUserControl != null)
                {
                    ComunicacaoUserControl.Visibility = Visibility.Visible;
                    System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: Comunicacao VISÍVEL");
                }
                break;
            default:
                System.Diagnostics.Debug.WriteLine($"⚠️ CODE-BEHIND: Aba {abaAtiva} não implementada");
                break;
        }
    }
}
