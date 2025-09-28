using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade para análises de irisdiagnose
/// Aba 5: Irisdiagnose - Captura e análise das íris
/// </summary>
public class IrisAnalise
{
    public int Id { get; set; }

    [Required]
    public int PacienteId { get; set; }

    // === INFORMAÇÕES DA SESSÃO ===
    /// <summary>
    /// Data e hora da análise
    /// </summary>
    [Required]
    public DateTime DataHoraAnalise { get; set; }

    /// <summary>
    /// Tipo de equipamento usado: "Webcam"|"Câmara Especializada"|"Smartphone"
    /// </summary>
    [StringLength(50)]
    public string? TipoEquipamento { get; set; }

    /// <summary>
    /// Resolução de captura: "720p"|"1080p"|"4K"
    /// </summary>
    [StringLength(20)]
    public string? ResolucaoCaptura { get; set; }

    /// <summary>
    /// Configurações de luz usadas
    /// </summary>
    [StringLength(50)]
    public string? ConfiguracoesLuz { get; set; }

    // === IMAGENS CAPTURADAS ===
    /// <summary>
    /// Caminho para imagem da íris esquerda
    /// </summary>
    [StringLength(500)]
    public string? CaminhoImagemEsquerda { get; set; }

    /// <summary>
    /// Caminho para imagem da íris direita
    /// </summary>
    [StringLength(500)]
    public string? CaminhoImagemDireita { get; set; }

    /// <summary>
    /// Qualidade da imagem esquerda (0-100)
    /// </summary>
    public int? QualidadeImagemEsquerda { get; set; }

    /// <summary>
    /// Qualidade da imagem direita (0-100)
    /// </summary>
    public int? QualidadeImagemDireita { get; set; }

    /// <summary>
    /// Tamanho do ficheiro da imagem esquerda (bytes)
    /// </summary>
    public long? TamanhoFicheiroEsquerda { get; set; }

    /// <summary>
    /// Tamanho do ficheiro da imagem direita (bytes)
    /// </summary>
    public long? TamanhoFicheiroDireita { get; set; }

    // === ANÁLISE POR SETORES (MAPA IRIDOLÓGICO) ===
    /// <summary>
    /// Observações por setor da íris esquerda (JSON)
    /// Ex: {"1":{"orgao":"Estômago","observacao":"Inflamação crónica","severidade":6},"2":{"orgao":"Intestino",...}}
    /// Setores 1-24 do mapa iridológico
    /// </summary>
    public string? ObservacoesPorSetorEsquerda { get; set; }

    /// <summary>
    /// Observações por setor da íris direita (JSON)
    /// </summary>
    public string? ObservacoesPorSetorDireita { get; set; }

    // === ANÁLISE POR SISTEMAS CORPORAIS ===
    /// <summary>
    /// Sistema digestivo - observações e severidade (0-10)
    /// JSON: {"observacoes":"...","severidade":5,"recomendacoes":["...","..."]}
    /// </summary>
    public string? SistemaDigestivo { get; set; }

    /// <summary>
    /// Sistema circulatório/cardiovascular
    /// </summary>
    public string? SistemaCirculatorio { get; set; }

    /// <summary>
    /// Sistema nervoso central e periférico
    /// </summary>
    public string? SistemaNervoso { get; set; }

    /// <summary>
    /// Sistema respiratório
    /// </summary>
    public string? SistemaRespiratorio { get; set; }

    /// <summary>
    /// Sistema geniturinário
    /// </summary>
    public string? SistemaGeniturinario { get; set; }

    /// <summary>
    /// Sistema músculo-esquelético
    /// </summary>
    public string? SistemaMusculoEsqueletico { get; set; }

    // === INTERPRETAÇÃO E RELATÓRIO ===
    /// <summary>
    /// Resumo geral da análise - impressão das íris
    /// </summary>
    public string? InterpretacaoGeral { get; set; }

    /// <summary>
    /// Pontos críticos identificados (JSON array)
    /// Ex: ["Inflamação crónica digestiva","Tensão no sistema nervoso","Fraqueza circulatória"]
    /// </summary>
    public string? PontosCriticos { get; set; }

    /// <summary>
    /// Comparação com análises anteriores (se existirem)
    /// </summary>
    public string? ComparacaoAnaliseAnterior { get; set; }

    // === RECOMENDAÇÕES TERAPÊUTICAS ===
    /// <summary>
    /// Tratamentos naturais sugeridos baseados nos achados (JSON array)
    /// </summary>
    public string? TratamentosSugeridos { get; set; }

    /// <summary>
    /// Suplementação recomendada (JSON array)
    /// Ex: [{"tipo":"Vitamina","nome":"B Complex","dosagem":"1 cápsula/dia","duracao":"3 meses"}]
    /// </summary>
    public string? SuplementacaoRecomendada { get; set; }

    /// <summary>
    /// Mudanças no estilo de vida recomendadas
    /// </summary>
    public string? MudancasEstiloVida { get; set; }

    /// <summary>
    /// Frequência recomendada para próxima análise
    /// Ex: "3 meses", "6 meses", "1 ano"
    /// </summary>
    [StringLength(50)]
    public string? FrequenciaProximaAnalise { get; set; }

    // === METADADOS ===
    /// <summary>
    /// Profissional que realizou a análise
    /// </summary>
    [StringLength(200)]
    public string? ProfissionalAnalise { get; set; }

    /// <summary>
    /// Duração da sessão de análise em minutos
    /// </summary>
    public int? DuracaoSessao { get; set; }

    /// <summary>
    /// Observações técnicas sobre a captura/análise
    /// </summary>
    public string? ObservacoesTecnicas { get; set; }

    public DateTime DataCriacao { get; set; } = DateTime.UtcNow;
    public DateTime? DataAtualizacao { get; set; }

    // === NAVEGAÇÃO ===
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;

    // === PROPRIEDADES CALCULADAS ===
    /// <summary>
    /// Qualidade média das imagens capturadas
    /// </summary>
    public decimal? QualidadeMediaImagens
    {
        get
        {
            if (!QualidadeImagemEsquerda.HasValue && !QualidadeImagemDireita.HasValue)
                return null;

            var total = 0;
            var count = 0;

            if (QualidadeImagemEsquerda.HasValue)
            {
                total += QualidadeImagemEsquerda.Value;
                count++;
            }

            if (QualidadeImagemDireita.HasValue)
            {
                total += QualidadeImagemDireita.Value;
                count++;
            }

            return count > 0 ? Math.Round((decimal)total / count, 1) : null;
        }
    }

    /// <summary>
    /// Indica se a análise tem imagens de ambas as íris
    /// </summary>
    public bool AnaliseCompleta =>
        !string.IsNullOrEmpty(CaminhoImagemEsquerda) &&
        !string.IsNullOrEmpty(CaminhoImagemDireita);
}
