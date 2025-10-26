using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using BioDesk.Core.Application.Terapia;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Windows;
using BioDesk.App.Windows;

namespace BioDesk.App.Views.Terapia;

public partial class BiofeedbackView : UserControl
{
    private bool _eventSubscribed = false;

    public BiofeedbackView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is BiofeedbackViewModel vm && !_eventSubscribed)
        {
            vm.BiofeedbackSessaoRequested += OnBiofeedbackSessaoRequested;
            _eventSubscribed = true;
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is BiofeedbackViewModel vm && _eventSubscribed)
        {
            vm.BiofeedbackSessaoRequested -= OnBiofeedbackSessaoRequested;
            _eventSubscribed = false;
        }
    }

    private void TerapiaControlos_IniciarClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is not BiofeedbackViewModel vm)
        {
            MessageBox.Show(
                "ViewModel não disponível.",
                "Erro",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            return;
        }

        // Criar parâmetros de terapia
        var parametros = new TerapiaParametros(
            VoltagemV: TerapiaControlosCompacto.VoltagemV,
            DuracaoTotalMinutos: (int)TerapiaControlosCompacto.DuracaoTotalMinutos,
            TempoFrequenciaSegundos: (int)TerapiaControlosCompacto.TempoFrequenciaSegundos,
            AjusteHz: (int)TerapiaControlosCompacto.AjusteHz
        );

        // Iniciar sessão diretamente (sem modal) - via comando
        if (vm.IniciarSessaoCommand.CanExecute(parametros))
        {
            vm.IniciarSessaoCommand.Execute(parametros);
        }
        else if (vm.SessaoEmAndamento)
        {
            MessageBox.Show(
                "Uma sessão de biofeedback já está em execução. Aguarde a conclusão ou pare-a antes de iniciar outra.",
                "Sessão em andamento",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    private void TerapiaControlos_PararClick(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🛑 BiofeedbackView: TerapiaControlos_PararClick DISPARADO");

        if (DataContext is not BiofeedbackViewModel vm)
        {
            System.Diagnostics.Debug.WriteLine("❌ BiofeedbackView: ViewModel não disponível!");
            return;
        }

        if (!vm.SessaoEmAndamento)
        {
            MessageBox.Show(
                "Não há nenhuma sessão em execução.",
                "Informação",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var resultado = MessageBox.Show(
            "Tem certeza que deseja parar a sessão de biofeedback?\n\nO progresso será perdido.",
            "Confirmar Paragem",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (resultado == MessageBoxResult.Yes)
        {
            System.Diagnostics.Debug.WriteLine("✅ BiofeedbackView: User confirmou paragem - definindo SessaoEmAndamento=false");
            vm.SessaoEmAndamento = false; // Isto interrompe o loop while(SessaoEmAndamento)
        }
    }

    private void OnBiofeedbackSessaoRequested(object? sender, BiofeedbackSessaoRequestedEventArgs e)
    {
        // Modal autónoma - não precisa de dados pré-carregados
        var viewModel = new BiofeedbackSessionViewModel();

        var window = new BiofeedbackSessionWindow
        {
            DataContext = viewModel,
            Owner = Window.GetWindow(this)
        };
        window.ShowDialog();
    }
}
