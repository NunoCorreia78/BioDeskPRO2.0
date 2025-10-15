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

    [ObservableProperty] private string _excelPath = string.Empty;
    [ObservableProperty] private string _search = string.Empty;
    [ObservableProperty] private string? _selectedProgram;

    public ObservableCollection<string> Programs { get; } = new();
    public ObservableCollection<ProgramStepVM> SelectedProgramSteps { get; } = new();

    public ProgramasViewModel(IProgramLibrary library, IActiveListService activeList)
    {
        _library = library;
        _activeList = activeList;
    }

    [RelayCommand]
    private async Task ImportExcelAsync()
    {
        if (string.IsNullOrWhiteSpace(ExcelPath))
        {
            return;
        }

        await _library.ImportExcelAsync(ExcelPath, CancellationToken.None);
        await RefreshProgramsAsync();
    }

    [RelayCommand]
    private async Task RefreshProgramsAsync()
    {
        Programs.Clear();
        var list = await _library.ListProgramsAsync(Search, CancellationToken.None);
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
    private void AddProgramToActiveList()
    {
        if (SelectedProgramSteps.Count == 0)
        {
            return;
        }

        foreach (var step in SelectedProgramSteps)
        {
            var item = new ScanResultItem(
                ItemId: step.Index,
                Code: $"{SelectedProgram ?? "PROGRAM"}::{step.Index}",
                Name: $"{SelectedProgram ?? "Programa"} - {step.Hz:N1} Hz",
                Category: "Programa",
                ScorePercent: 100,
                ZScore: 0,
                QValue: 0,
                ImprovementPercent: 0,
                Rank: step.Index);

            _activeList.AddOrUpdate(item);
        }
    }
}

public sealed record ProgramStepVM(int Index, double Hz, double Duty, int Seconds, string? Notes);
