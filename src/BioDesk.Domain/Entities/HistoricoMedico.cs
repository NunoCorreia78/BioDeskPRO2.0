using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade para histórico médico do paciente
/// Aba 2: Declaração de Saúde - Antecedentes e estado atual
/// </summary>
public class HistoricoMedico
{
    public int Id { get; set; }

    [Required]
    public int PacienteId { get; set; }

    // === ANTECEDENTES PESSOAIS ===
    /// <summary>
    /// Doenças crónicas (JSON array ou string delimitada)
    /// Ex: "Diabetes,Hipertensão,Cardiopatias"
    /// </summary>
    public string? DoencasCronicas { get; set; }

    /// <summary>
    /// Especificação de outras doenças não listadas
    /// </summary>
    public string? OutrasDoencas { get; set; }

    /// <summary>
    /// Cirurgias anteriores (JSON array de objetos)
    /// Ex: [{"Data":"2020-05-15","Tipo":"Apendicectomia","Hospital":"Hospital X","Observacoes":"Sem complicações"}]
    /// </summary>
    public string? CirurgiasAnteriores { get; set; }

    /// <summary>
    /// Hospitalizações anteriores (JSON array)
    /// </summary>
    public string? Hospitalizacoes { get; set; }

    // === MEDICAÇÃO ATUAL ===
    /// <summary>
    /// Medicamentos prescritos atualmente (JSON array)
    /// Ex: [{"Nome":"Paracetamol","Dosagem":"500mg","Frequencia":"8/8h","DesdeQuando":"2024-01-15"}]
    /// </summary>
    public string? MedicacaoAtual { get; set; }

    /// <summary>
    /// Suplementos alimentares
    /// </summary>
    public string? Suplementos { get; set; }

    /// <summary>
    /// Medicamentos naturais/fitoterapia
    /// </summary>
    public string? MedicamentosNaturais { get; set; }

    // === ALERGIAS E INTOLERÂNCIAS ===
    /// <summary>
    /// Alergias medicamentosas (JSON array com severidade)
    /// Ex: [{"Medicamento":"Penicilina","Severidade":"Grave","Reacao":"Anafilaxia"}]
    /// </summary>
    public string? AlergiasMedicamentosas { get; set; }

    /// <summary>
    /// Alergias alimentares
    /// </summary>
    public string? AlergiasAlimentares { get; set; }

    /// <summary>
    /// Alergias ambientais (pólen, ácaros, etc.)
    /// </summary>
    public string? AlergiasAmbientais { get; set; }

    /// <summary>
    /// Intolerâncias alimentares (separadas das alergias)
    /// </summary>
    public string? IntoleranciasAlimentares { get; set; }

    // === ANTECEDENTES FAMILIARES ===
    /// <summary>
    /// História familiar relevante (JSON array)
    /// Ex: [{"Parentesco":"Pai","Condicao":"Diabetes Tipo 2","IdadeDiagnostico":45,"Status":"Vivo"}]
    /// </summary>
    public string? HistoriaFamiliar { get; set; }

    /// <summary>
    /// Doenças hereditárias conhecidas
    /// </summary>
    public string? DoencasHereditarias { get; set; }

    /// <summary>
    /// Observações adicionais sobre família
    /// </summary>
    public string? ObservacoesFamiliares { get; set; }

    // === ESTILO DE VIDA ===
    /// <summary>
    /// Hábitos de tabagismo: "Nunca fumou"|"Ex-fumador"|"Fumador atual"
    /// </summary>
    [StringLength(20)]
    public string? Tabagismo { get; set; }

    /// <summary>
    /// Detalhes do tabagismo (quantidade, há quanto tempo, etc.)
    /// </summary>
    public string? DetalheTabagismo { get; set; }

    /// <summary>
    /// Consumo de álcool: "Nunca"|"Ocasional"|"Regular"|"Excessivo"
    /// </summary>
    [StringLength(20)]
    public string? ConsumoAlcool { get; set; }

    /// <summary>
    /// Quantidades e detalhes do consumo de álcool
    /// </summary>
    public string? DetalheAlcool { get; set; }

    /// <summary>
    /// Exercício físico: "Sedentário"|"Ligeiro"|"Moderado"|"Intenso"
    /// </summary>
    [StringLength(20)]
    public string? ExercicioFisico { get; set; }

    /// <summary>
    /// Tipo e frequência do exercício
    /// </summary>
    public string? DetalheExercicio { get; set; }

    /// <summary>
    /// Horas de sono por noite
    /// </summary>
    public decimal? HorasSono { get; set; }

    /// <summary>
    /// Qualidade do sono: "Excelente"|"Boa"|"Razoável"|"Má"
    /// </summary>
    [StringLength(20)]
    public string? QualidadeSono { get; set; }

    /// <summary>
    /// Tipo de dieta: "Omnívora"|"Vegetariana"|"Vegana"|"Mediterrânica"|"Outras"
    /// </summary>
    [StringLength(30)]
    public string? TipoDieta { get; set; }

    /// <summary>
    /// Restrições alimentares específicas
    /// </summary>
    public string? RestricaoesAlimentares { get; set; }

    /// <summary>
    /// Consumo diário de água em litros
    /// </summary>
    public decimal? ConsumoAguaDiario { get; set; }

    /// <summary>
    /// Suplementação atual detalhada
    /// </summary>
    public string? SuplementacaoAtual { get; set; }

    // === DECLARAÇÃO LEGAL ===
    /// <summary>
    /// Confirmação da veracidade das informações
    /// </summary>
    public bool ConfirmaVeracidade { get; set; }

    /// <summary>
    /// Compreende importância da informação completa
    /// </summary>
    public bool CompreendImportancia { get; set; }

    /// <summary>
    /// Compromete-se a informar alterações
    /// </summary>
    public bool ComprometeMudancas { get; set; }

    /// <summary>
    /// Observações adicionais do paciente
    /// </summary>
    public string? ObservacoesAdicionais { get; set; }

    // === METADADOS ===
    public DateTime DataCriacao { get; set; } = DateTime.UtcNow;
    public DateTime? DataAtualizacao { get; set; }

    // === NAVEGAÇÃO ===
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;
}
