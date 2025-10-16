using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Domain.Terapia;
using BioDesk.ViewModels.Services.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.UserControls.Terapia;

public partial class ProgramasViewModel : ObservableObject
{
    private readonly IProgramLibrary _library;
    private readonly IActiveListService _activeList;

    [ObservableProperty] private string _search = string.Empty;
    [ObservableProperty] private string? _selectedProgram;

    public ObservableCollection<string> Programs { get; } = new();
    public ObservableCollection<string> SelectedPrograms { get; } = new(); // Seleção múltipla
    public ObservableCollection<ProgramStepVM> SelectedProgramSteps { get; } = new();

    public ProgramasViewModel(IProgramLibrary library, IActiveListService activeList)
    {
        _library = library;
        _activeList = activeList;

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

    [RelayCommand]
    private async Task AddProgramToActiveListAsync()
    {
        // Processar múltiplos protocolos selecionados
        var programsToAdd = SelectedPrograms.Count > 0
            ? SelectedPrograms.ToList()
            : (SelectedProgram != null ? new List<string> { SelectedProgram } : new List<string>());

        if (programsToAdd.Count == 0)
        {
            return;
        }

        foreach (var program in programsToAdd)
        {
            if (string.IsNullOrWhiteSpace(program)) continue;

            var steps = await _library.GetProgramAsync(program!, CancellationToken.None);
            var index = 1;
            foreach (var step in steps)
            {
                var item = new ScanResultItem(
                    ItemId: index,
                    Code: $"{program}::{index}",
                    Name: $"{program.Replace("PROTO::", "")} - {step.Hz:N1} Hz",
                    Category: "Programa",
                    ScorePercent: 100,
                    ZScore: 0,
                    QValue: 0,
                    ImprovementPercent: 0,
                    Rank: index);

                _activeList.AddOrUpdate(item);
                index++;
            }
        }
    }
}

public sealed record ProgramStepVM(int Index, double Hz, double Duty, int Seconds, string? Notes);
