using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Windows;
using BioDesk.App.Windows;
using BioDesk.Core.Application.Terapia;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Terapia;

public partial class ProgramasView : UserControl
{
    private bool _eventSubscribed = false;
    private readonly IProgramLibrary _programLibrary;

    public ProgramasView()
    {
        InitializeComponent();

        // Obter IProgramLibrary via DI
        // Null-forgiving: Application.Current e ServiceProvider sempre existem em runtime WPF após App.xaml.cs inicializar
        var app = (Application.Current as App)!;
        _programLibrary = app.ServiceProvider!.GetRequiredService<IProgramLibrary>();

        // Escutar evento de solicitação de terapia local
        Loaded += async (s, e) =>
        {
            if (DataContext is ProgramasViewModel vm && !_eventSubscribed)
            {
                vm.TerapiaLocalRequested += OnTerapiaLocalRequested;
                _eventSubscribed = true;
            }

            // Carregar frequências inline para programas visíveis
            await CarregarFrequenciasInlineAsync();
        };

        Unloaded += (s, e) =>
        {
            if (DataContext is ProgramasViewModel vm && _eventSubscribed)
            {
                vm.TerapiaLocalRequested -= OnTerapiaLocalRequested;
                _eventSubscribed = false;
            }
        };
    }

    private async Task CarregarFrequenciasInlineAsync()
    {
        // TODO: Implementar carregamento lazy das frequências
        // Por enquanto, placeholder está no XAML
        await Task.CompletedTask;
    }

    private void ProgramasDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DataContext is ProgramasViewModel vm)
        {
            // Sincronizar seleção DataGrid → ViewModel
            vm.SelectedPrograms.Clear();
            foreach (var item in ProgramasDataGrid.SelectedItems)
            {
                if (item is string programName)
                {
                    vm.SelectedPrograms.Add(programName);
                }
            }
        }
    }

    private void TerapiaControlos_IniciarClick(object sender, RoutedEventArgs e)
    {
        // Validar seleção
        if (ProgramasDataGrid.SelectedItems.Count == 0)
        {
            MessageBox.Show("Selecione pelo menos 1 programa (Ctrl+Click para múltiplos)",
                          "Atenção",
                          MessageBoxButton.OK,
                          MessageBoxImage.Warning);
            return;
        }

        if (DataContext is ProgramasViewModel vm)
        {
            // Capturar parâmetros do controlo
            var parametros = new TerapiaParametros(
                VoltagemV: TerapiaControlosCompacto.VoltagemV,
                DuracaoTotalMinutos: (int)TerapiaControlosCompacto.DuracaoTotalMinutos,
                TempoFrequenciaSegundos: (int)TerapiaControlosCompacto.TempoFrequenciaSegundos,
                AjusteHz: (int)TerapiaControlosCompacto.AjusteHz
            );

            // Iniciar terapia diretamente (sem modal) - via comando
            if (vm.IniciarTerapiaLocalCommand.CanExecute(parametros))
            {
                vm.IniciarTerapiaLocalCommand.Execute(parametros);
            }
            else if (vm.TerapiaEmAndamento)
            {
                MessageBox.Show(
                    "Já existe uma terapia de programas em andamento. Aguarde a conclusão antes de iniciar outra.",
                    "Terapia em andamento",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
    }

    private void TerapiaControlos_PararClick(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🛑 ProgramasView: TerapiaControlos_PararClick DISPARADO");

        if (DataContext is not ProgramasViewModel vm)
        {
            System.Diagnostics.Debug.WriteLine("❌ ProgramasView: ViewModel não disponível!");
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
            "Tem certeza que deseja parar a terapia de programas?\n\nO progresso será perdido.",
            "Confirmar Paragem",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (resultado == MessageBoxResult.Yes)
        {
            System.Diagnostics.Debug.WriteLine("✅ ProgramasView: User confirmou paragem - definindo TerapiaEmAndamento=false");
            vm.TerapiaEmAndamento = false; // Isto interrompe o loop while(TerapiaEmAndamento)
        }
    }

    private void OnTerapiaLocalRequested(object? sender, TerapiaLocalRequestedEventArgs e)
    {
        // Criar ViewModel do modal e popular com frequências da BD
        var viewModel = new TerapiaLocalViewModel();
        foreach (var freq in e.Frequencias)
        {
            viewModel.Frequencias.Add(new BioDesk.ViewModels.Windows.FrequenciaStep(
                Hz: freq.Hz,
                DutyPercent: freq.DutyPercent,
                DuracaoSegundos: freq.DuracaoSegundos));
        }

        // Aplicar valores dos controlos unificados
        viewModel.VoltagemV = TerapiaControlosCompacto.VoltagemV;
        viewModel.DuracaoUniformeSegundos = TerapiaControlosCompacto.TempoFrequenciaSegundos;
        // TODO: Implementar DuracaoTotalMinutos e AjusteHz no ViewModel

        // Abrir modal
        var window = new TerapiaLocalWindow
        {
            DataContext = viewModel,
            Owner = System.Windows.Window.GetWindow(this)
        };
        window.ShowDialog();
    }
}
