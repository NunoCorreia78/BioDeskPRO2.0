using CommunityToolkit.Mvvm.ComponentModel;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel para representar um template PDF no seletor
/// Usado no pop-up SelecionarTemplatesWindow
/// </summary>
public partial class TemplatePdfViewModel : ObservableObject
{
    /// <summary>
    /// Nome limpo do template (ex: "Escoliose Dorsal")
    /// </summary>
    [ObservableProperty]
    private string _nome = string.Empty;

    /// <summary>
    /// Caminho completo do ficheiro PDF
    /// </summary>
    [ObservableProperty]
    private string _caminhoCompleto = string.Empty;

    /// <summary>
    /// Nome do ficheiro original (ex: "Escoliose_Dorsal.pdf")
    /// </summary>
    [ObservableProperty]
    private string _nomeFicheiro = string.Empty;

    /// <summary>
    /// Tamanho formatado (ex: "1.5 MB")
    /// </summary>
    [ObservableProperty]
    private string _tamanhoFormatado = string.Empty;

    /// <summary>
    /// Indica se o template está selecionado no checkbox
    /// </summary>
    [ObservableProperty]
    private bool _selecionado = false;

    /// <summary>
    /// Construtor padrão
    /// </summary>
    public TemplatePdfViewModel()
    {
    }

    /// <summary>
    /// Construtor com dados do template
    /// </summary>
    public TemplatePdfViewModel(string nome, string caminhoCompleto, string nomeFicheiro, string tamanhoFormatado)
    {
        Nome = nome;
        CaminhoCompleto = caminhoCompleto;
        NomeFicheiro = nomeFicheiro;
        TamanhoFormatado = tamanhoFormatado;
    }
}
