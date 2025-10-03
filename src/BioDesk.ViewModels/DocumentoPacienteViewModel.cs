using System;
using System.Linq;
using BioDesk.Domain.Entities;
using CommunityToolkit.Mvvm.ComponentModel;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para apresentação de um documento de paciente na UI.
/// Adiciona propriedades calculadas e estado de seleção para binding WPF.
/// </summary>
public partial class DocumentoPacienteViewModel : ObservableObject
{
    private readonly DocumentoPaciente _documento;

    public DocumentoPacienteViewModel(DocumentoPaciente documento)
    {
        _documento = documento;
    }

    // ============================
    // PROPRIEDADES DO MODELO
    // ============================

    public int PacienteId => _documento.PacienteId;
    public string Nome => _documento.Nome;
    public string CaminhoCompleto => _documento.CaminhoCompleto;
    public DateTime DataCriacao => _documento.DataCriacao;
    public TipoDocumentoEnum Tipo => _documento.Tipo;
    public long Tamanho => _documento.Tamanho;

    // ============================
    // PROPRIEDADES UI (OBSERVÁVEIS)
    // ============================

    /// <summary>
    /// Indica se o documento está selecionado para anexar ao email
    /// </summary>
    [ObservableProperty]
    private bool _selecionado;

    // ============================
    // PROPRIEDADES CALCULADAS (READ-ONLY)
    // ============================

    /// <summary>
    /// Nome formatado para exibição (sem timestamp, mais legível)
    /// Ex: "Consentimento_🌿_Naturopatia_JoaoSilva.pdf"
    /// </summary>
    public string NomeExibicao
    {
        get
        {
            // Remove timestamp do final (padrão: _20251001_212509.pdf)
            var nome = Nome;
            var semExtensao = System.IO.Path.GetFileNameWithoutExtension(nome);
            var extensao = System.IO.Path.GetExtension(nome);

            // Tentar remover padrão _YYYYMMDD_HHMMSS
            var partes = semExtensao.Split('_');
            if (partes.Length >= 2 && partes[^1].Length == 6 && partes[^2].Length == 8)
            {
                // Remover os 2 últimos componentes (data + hora)
                semExtensao = string.Join("_", partes.Take(partes.Length - 2));
            }

            return $"{semExtensao}{extensao}";
        }
    }

    /// <summary>
    /// Tamanho formatado (KB, MB)
    /// Ex: "1.2 MB", "456 KB"
    /// </summary>
    public string TamanhoFormatado
    {
        get
        {
            if (Tamanho < 1024)
                return $"{Tamanho} B";

            if (Tamanho < 1024 * 1024)
                return $"{Tamanho / 1024.0:F1} KB";

            return $"{Tamanho / (1024.0 * 1024.0):F1} MB";
        }
    }

    /// <summary>
    /// Data formatada para exibição
    /// Ex: "01/10/2025 21:35"
    /// </summary>
    public string DataFormatada => DataCriacao.ToString("dd/MM/yyyy HH:mm");

    /// <summary>
    /// Ícone emoji baseado no tipo de documento
    /// </summary>
    public string Icone => Tipo switch
    {
        TipoDocumentoEnum.Consentimento => "📋",
        TipoDocumentoEnum.Prescricao => "💊",
        TipoDocumentoEnum.Declaracao => "📄",
        TipoDocumentoEnum.Analise => "🔬",
        _ => "📁"
    };

    /// <summary>
    /// Descrição do tipo de documento
    /// </summary>
    public string TipoDescricao => Tipo switch
    {
        TipoDocumentoEnum.Consentimento => "Consentimento",
        TipoDocumentoEnum.Prescricao => "Prescrição",
        TipoDocumentoEnum.Declaracao => "Declaração",
        TipoDocumentoEnum.Analise => "Análise",
        _ => "Documento"
    };

    /// <summary>
    /// Texto completo para exibição no ListBox
    /// Ex: "📋 Consentimento_Naturopatia.pdf (1.2 MB)"
    /// </summary>
    public string TextoCompleto => $"{Icone} {NomeExibicao} ({TamanhoFormatado})";

    /// <summary>
    /// Tooltip com informações detalhadas
    /// </summary>
    public string Tooltip => $"""
        {TipoDescricao}
        
        Ficheiro: {Nome}
        Tamanho: {TamanhoFormatado}
        Criado: {DataFormatada}
        Caminho: {CaminhoCompleto}
        """;
}
