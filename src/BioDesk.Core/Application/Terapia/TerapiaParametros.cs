namespace BioDesk.Core.Application.Terapia;

/// <summary>
/// Parâmetros de terapia vindos do TerapiaControlosUserControl.
/// Compartilhado entre RessonantesViewModel, ProgramasViewModel e BiofeedbackViewModel.
/// </summary>
public record TerapiaParametros(
    double VoltagemV,
    int DuracaoTotalMinutos,
    int TempoFrequenciaSegundos,
    int AjusteHz
);
