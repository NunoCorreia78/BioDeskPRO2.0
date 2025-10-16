using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Domain.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.UserControls.Terapia;

/// <summary>
/// EventArgs para solicitação de terapia local.
/// Contém lista de frequências (Hz) extraídas dos protocolos selecionados.
/// </summary>
public class TerapiaLocalRequestedEventArgs : EventArgs
{
    public List<FrequenciaInfo> Frequencias { get; }

    public TerapiaLocalRequestedEventArgs(List<FrequenciaInfo> frequencias)
    {
        Frequencias = frequencias;
    }
}

/// <summary>
/// Informação de uma frequência para terapia local.
/// </summary>
public record FrequenciaInfo(double Hz, int DutyPercent, int DuracaoSegundos);

public partial class ProgramasViewModel : ObservableObject
{
    private readonly IProgramLibrary _library;

    [ObservableProperty] private string _search = string.Empty;
    [ObservableProperty] private string? _selectedProgram;

    public ObservableCollection<string> Programs { get; } = new();
    public ObservableCollection<string> SelectedPrograms { get; } = new(); // Seleção múltipla
    public ObservableCollection<ProgramStepVM> SelectedProgramSteps { get; } = new();

    /// <summary>
    /// Evento disparado quando user pede para iniciar terapia local.
    /// View (XAML.cs) escuta este evento e abre TerapiaLocalWindow.
    /// </summary>
    public event EventHandler<TerapiaLocalRequestedEventArgs>? TerapiaLocalRequested;

    public ProgramasViewModel(IProgramLibrary library)
    {
        _library = library;

        // Auto-load ao instanciar
        _ = LoadAllProgramsAsync();
    }

    private async Task LoadAllProgramsAsync()
    {
        Programs.Clear();
        var list = await _library.ListProgramsAsync(null, CancellationToken.None);
        foreach (var program in list)
        {
            Programs.Add(program);
        }
    }

    partial void OnSearchChanged(string value)
    {
        _ = FilterProgramsAsync(value);
    }

    private async Task FilterProgramsAsync(string searchTerm)
    {
        Programs.Clear();
        var list = await _library.ListProgramsAsync(searchTerm, CancellationToken.None);
        foreach (var program in list)
        {
            Programs.Add(program);
        }
    }

    partial void OnSelectedProgramChanged(string? value)
    {
        _ = LoadProgramAsync(value);
    }

    private async Task LoadProgramAsync(string? value)
    {
        SelectedProgramSteps.Clear();
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var steps = await _library.GetProgramAsync(value, CancellationToken.None);
        var index = 1;
        foreach (var step in steps)
        {
            SelectedProgramSteps.Add(new ProgramStepVM(index++, step.Hz, step.Duty, step.Seconds, step.Notes));
        }
    }

    /// <summary>
    /// Prepara dados e solicita abertura de modal de Terapia Local.
    /// User requirement: Terapia local = Hz direto, voltagem controlável 0-12V.
    /// </summary>
    [RelayCommand]
    private async Task IniciarTerapiaLocalAsync()
    {
        // Processar múltiplos protocolos selecionados
        var programsToAdd = SelectedPrograms.Count > 0
            ? SelectedPrograms.ToList()
            : (SelectedProgram != null ? new List<string> { SelectedProgram } : new List<string>());

        if (programsToAdd.Count == 0)
        {
            // TODO: Mostrar mensagem ao user "Nenhum protocolo selecionado"
            return;
        }

        // Buscar Hz reais da BD para todos os protocolos
        var todasFrequencias = new List<FrequenciaInfo>();
        foreach (var program in programsToAdd)
        {
            if (string.IsNullOrWhiteSpace(program)) continue;

            var steps = await _library.GetProgramAsync(program!, CancellationToken.None);
            foreach (var step in steps)
            {
                todasFrequencias.Add(new FrequenciaInfo(
                    Hz: step.Hz,
                    DutyPercent: (int)step.Duty,
                    DuracaoSegundos: step.Seconds));
            }
        }

        if (todasFrequencias.Count == 0)
        {
            // TODO: Mostrar mensagem "Nenhuma frequência encontrada"
            return;
        }

        // Disparar evento para View abrir modal
        TerapiaLocalRequested?.Invoke(this, new TerapiaLocalRequestedEventArgs(todasFrequencias));
    }
}

public sealed record ProgramStepVM(int Index, double Hz, double Duty, int Seconds, string? Notes);
