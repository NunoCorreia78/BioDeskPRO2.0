using CommunityToolkit.Mvvm.ComponentModel;

namespace BioDesk.ViewModels.UserControls.Terapia;

public partial class TerapiaCoreViewModel : ObservableObject
{
    public AvaliacaoViewModel Avaliacao { get; }
    public ProgramasViewModel Programas { get; }
    public RessonantesViewModel Ressonantes { get; }
    public BiofeedbackViewModel Biofeedback { get; }
    public HistoricoViewModel Historico { get; }
    public EmissaoConfiguracaoViewModel EmissaoConfiguracao { get; }

    public TerapiaCoreViewModel(
        AvaliacaoViewModel avaliacao,
        ProgramasViewModel programas,
        RessonantesViewModel ressonantes,
        BiofeedbackViewModel biofeedback,
        HistoricoViewModel historico,
        EmissaoConfiguracaoViewModel emissaoConfiguracao)
    {
        Avaliacao = avaliacao;
        Programas = programas;
        Ressonantes = ressonantes;
        Biofeedback = biofeedback;
        Historico = historico;
        EmissaoConfiguracao = emissaoConfiguracao;
    }
}
