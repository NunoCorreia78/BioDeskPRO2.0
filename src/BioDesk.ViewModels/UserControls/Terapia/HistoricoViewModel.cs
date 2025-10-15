using System;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace BioDesk.ViewModels.UserControls.Terapia;

public sealed class HistoricoViewModel : ObservableObject
{
    public ObservableCollection<HistoricoSessaoVM> Sessions { get; } = new();
}

public sealed record HistoricoSessaoVM(DateTime Date, string Seed, string Rng, int Iterations, string Summary);
