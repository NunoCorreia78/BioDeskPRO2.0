using System.Windows.Controls;
using System.Windows;
using BioDesk.ViewModels;
using BioDesk.ViewModels.Abas;
using System.ComponentModel;
using System.Threading.Tasks;
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
    private IrisdiagnosticoViewModel? _irisdiagnosticoViewModel;

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

            if (_irisdiagnosticoViewModel == null)
            {
                _irisdiagnosticoViewModel = app.ServiceProvider?.GetRequiredService<IrisdiagnosticoViewModel>();
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
                    await _registoConsultasViewModel.SetPacienteAsync(newViewModel.PacienteAtual);
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

            // ✅ Configurar DataContext do UserControl de Irisdiagnóstico
            if (IrisdiagnosticoUserControl != null && _irisdiagnosticoViewModel != null)
            {
                IrisdiagnosticoUserControl.DataContext = _irisdiagnosticoViewModel;

                // Passar paciente para o ViewModel de Irisdiagnóstico (async)
                if (newViewModel.PacienteAtual != null)
                {
                    await _irisdiagnosticoViewModel.CarregarDadosAsync(newViewModel.PacienteAtual);
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

    private async void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(FichaPacienteViewModel.AbaAtiva) &&
            sender is FichaPacienteViewModel viewModel)
        {
            AtualizarVisibilidadeAbas(viewModel.AbaAtiva);
        }
        else if (e.PropertyName == nameof(FichaPacienteViewModel.PacienteAtual) &&
                 sender is FichaPacienteViewModel fichaVm &&
                 fichaVm.PacienteAtual != null &&
                 _registoConsultasViewModel != null)
        {
            await _registoConsultasViewModel.SetPacienteAsync(fichaVm.PacienteAtual);
        }
    }

    private async void AtualizarVisibilidadeAbas(int abaAtiva)
    {
        // CONTROLO DIRETO - SEM CONVERTERS
        System.Diagnostics.Debug.WriteLine($"🔧 CODE-BEHIND: Mudando para aba {abaAtiva}");

        // ✅ CORREÇÃO CRÍTICA: SEMPRE processar, mesmo se PacienteAtual == null
        if (DataContext is FichaPacienteViewModel viewModel)
        {
            // Atualizar nome do paciente para abas que precisam
            if (viewModel.PacienteAtual != null)
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

            // 🔥 CORREÇÃO BUG COMUNICAÇÃO: SEMPRE chamar, mesmo se paciente == null
            if (abaAtiva == 6 && _comunicacaoViewModel != null)
            {
                if (viewModel.PacienteAtual != null)
                {
                    await _comunicacaoViewModel.SetPaciente(viewModel.PacienteAtual);
                }
                else
                {
                    // 🔥 LIMPAR documentos quando não há paciente ativo!
                    _comunicacaoViewModel.PacienteAtual = null;
                    _comunicacaoViewModel.DocumentosPaciente.Clear();
                    _comunicacaoViewModel.StatusDocumentos = "Nenhum paciente selecionado";
                }
            }

            // Recarregar Íris quando há paciente
            if (abaAtiva == 5 && _irisdiagnosticoViewModel != null && viewModel.PacienteAtual != null)
            {
                await _irisdiagnosticoViewModel.CarregarDadosAsync(viewModel.PacienteAtual);
            }
        }

        // Todos invisíveis primeiro
        DadosBiograficosUserControl.Visibility = Visibility.Collapsed;
        DeclaracaoSaudeUserControl.Visibility = Visibility.Collapsed;
        ConsentimentosUserControl.Visibility = Visibility.Collapsed;
        if (RegistoConsultasUserControl != null)
            RegistoConsultasUserControl.Visibility = Visibility.Collapsed;
        if (IrisdiagnosticoUserControl != null)
            IrisdiagnosticoUserControl.Visibility = Visibility.Collapsed;
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
                if (IrisdiagnosticoUserControl != null)
                {
                    IrisdiagnosticoUserControl.Visibility = Visibility.Visible;
                    System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: Irisdiagnostico VISÍVEL");
                }
                break;
            case 6:
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
