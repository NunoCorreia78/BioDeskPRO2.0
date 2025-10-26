using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using BioDesk.Core.Application.Terapia;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Windows;
using BioDesk.App.Windows;

namespace BioDesk.App.Views.Terapia;

public partial class RessonantesView : UserControl
{
    private bool _eventSubscribed = false;

    public RessonantesView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is RessonantesViewModel vm && !_eventSubscribed)
        {
            vm.TerapiaLocalRequested += OnTerapiaLocalRequested;
            _eventSubscribed = true;

            // Debug: Monitorar mudanças na propriedade TerapiaEmAndamento
            vm.PropertyChanged += (s, args) =>
            {
                if (args.PropertyName == nameof(vm.TerapiaEmAndamento))
                {
                    System.Diagnostics.Debug.WriteLine($"🔔 RessonantesView: TerapiaEmAndamento mudou para {vm.TerapiaEmAndamento}");
                }
            };
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is RessonantesViewModel vm && _eventSubscribed)
        {
            vm.TerapiaLocalRequested -= OnTerapiaLocalRequested;
            _eventSubscribed = false;
        }
    }

    private void ResultadosDataGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (DataContext is not RessonantesViewModel vm) return;

        // Sincronizar seleção do DataGrid com ViewModel
        vm.SelectedPoints.Clear();
        foreach (var item in ResultadosDataGrid.SelectedItems)
        {
            if (item is SweepPointVM point)
            {
                vm.SelectedPoints.Add(point);
            }
        }
    }

    private async void TerapiaControlos_IniciarClick(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🔵 RessonantesView: TerapiaControlos_IniciarClick DISPARADO");

        if (DataContext is not RessonantesViewModel vm)
        {
            System.Diagnostics.Debug.WriteLine("❌ RessonantesView: ViewModel não disponível!");
            MessageBox.Show(
                "ViewModel não disponível.",
                "Erro",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            return;
        }

        System.Diagnostics.Debug.WriteLine($"✅ RessonantesView: ViewModel OK, SelectedItems.Count = {ResultadosDataGrid.SelectedItems.Count}");

        if (ResultadosDataGrid.SelectedItems.Count == 0)
        {
            System.Diagnostics.Debug.WriteLine("⚠️ RessonantesView: Nenhuma frequência selecionada");
            MessageBox.Show(
                "Selecione pelo menos uma frequência ressonante.\n\n" +
                "💡 Dica: Use Ctrl+Click para selecionar múltiplas linhas.",
                "Nenhuma Frequência Selecionada",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        // Criar parâmetros de terapia
        var parametros = new TerapiaParametros(
            VoltagemV: TerapiaControlosCompacto.VoltagemV,
            DuracaoTotalMinutos: (int)TerapiaControlosCompacto.DuracaoTotalMinutos,
            TempoFrequenciaSegundos: (int)TerapiaControlosCompacto.TempoFrequenciaSegundos,
            AjusteHz: (int)TerapiaControlosCompacto.AjusteHz
        );

        System.Diagnostics.Debug.WriteLine($"📝 RessonantesView: Parâmetros criados - V={parametros.VoltagemV}, Duração={parametros.DuracaoTotalMinutos}min, Tempo/Freq={parametros.TempoFrequenciaSegundos}s");

        // Iniciar terapia diretamente (sem modal) - via comando
        var canExecute = vm.IniciarTerapiaLocalCommand.CanExecute(parametros);
        System.Diagnostics.Debug.WriteLine($"🔍 RessonantesView: CanExecute = {canExecute}");

        if (canExecute)
        {
            System.Diagnostics.Debug.WriteLine("▶️ RessonantesView: Executando comando...");
            vm.IniciarTerapiaLocalCommand.Execute(parametros);
            System.Diagnostics.Debug.WriteLine("✅ RessonantesView: Comando executado");
        }
        else
        {
            System.Diagnostics.Debug.WriteLine("❌ RessonantesView: Comando NÃO pode ser executado!");
            var mensagem = vm.TerapiaEmAndamento
                ? "Já existe uma terapia ressonante em andamento. Aguarde a conclusão para iniciar novamente."
                : "O comando de terapia não pode ser executado neste momento.";

            MessageBox.Show(
                mensagem,
                "Terapia em andamento",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    private void TerapiaControlos_PararClick(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🛑 RessonantesView: TerapiaControlos_PararClick DISPARADO");

        if (DataContext is not RessonantesViewModel vm)
        {
            System.Diagnostics.Debug.WriteLine("❌ RessonantesView: ViewModel não disponível!");
            return;
        }

        if (!vm.TerapiaEmAndamento)
        {
            MessageBox.Show(
                "Não há nenhuma terapia em execução.",
                "Informação",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var resultado = MessageBox.Show(
            "Tem certeza que deseja parar a terapia?\n\nO progresso será perdido.",
            "Confirmar Paragem",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (resultado == MessageBoxResult.Yes)
        {
            System.Diagnostics.Debug.WriteLine("✅ RessonantesView: User confirmou paragem - definindo TerapiaEmAndamento=false");
            vm.TerapiaEmAndamento = false; // Isto interrompe o loop while(TerapiaEmAndamento)
        }
    }

    private void OnTerapiaLocalRequested(object? sender, TerapiaLocalRequestedEventArgs e)
    {
        var viewModel = new TerapiaLocalViewModel();

        // Converter FrequenciaInfo → FrequenciaStep
        foreach (var freq in e.Frequencias)
        {
            viewModel.Frequencias.Add(new FrequenciaStep(
                Hz: freq.Hz,
                DutyPercent: freq.DutyPercent,
                DuracaoSegundos: freq.DuracaoSegundos
            ));
        }

        var window = new TerapiaLocalWindow
        {
            DataContext = viewModel,
            Owner = Window.GetWindow(this)
        };
        window.ShowDialog();
    }
}
