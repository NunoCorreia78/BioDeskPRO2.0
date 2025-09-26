using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade que representa a avaliação clínica estruturada de um paciente
/// Inclui motivos da consulta, história clínica, revisão de sistemas, estilo de vida e história familiar
/// </summary>
public class AvaliacaoClinica
{
    public int Id { get; set; }
    
    [Required]
    public int PacienteId { get; set; }
    
    [ForeignKey(nameof(PacienteId))]
    public Paciente Paciente { get; set; } = null!;
    
    public DateTime DataCriacao { get; set; } = DateTime.Now;
    public DateTime UltimaAtualizacao { get; set; } = DateTime.Now;
    
    // Relacionamentos com as seções da avaliação
    public MotivoConsulta? MotivoConsulta { get; set; }
    public HistoriaClinica? HistoriaClinica { get; set; }
    public RevisaoSistemas? RevisaoSistemas { get; set; }
    public EstiloVida? EstiloVida { get; set; }
    public HistoriaFamiliar? HistoriaFamiliar { get; set; }
    
    [MaxLength(2000)]
    public string? Observacoes { get; set; }
    
    public bool IsCompleta { get; set; }
}

/// <summary>
/// Entidade para os motivos da consulta
/// Interface moderna com chips, sliders e seletores
/// </summary>
public class MotivoConsulta
{
    public int Id { get; set; }
    
    [Required]
    public int AvaliacaoClinicaId { get; set; }
    
    [ForeignKey(nameof(AvaliacaoClinicaId))]
    public AvaliacaoClinica AvaliacaoClinica { get; set; } = null!;
    
    // Motivos (multi-select chips)
    [MaxLength(1000)]
    public string? MotivosJson { get; set; } // Serializado JSON dos chips selecionados
    
    [MaxLength(200)]
    public string? OutroMotivo { get; set; } // Campo para "Outro"
    
    // Localização e lateralidade
    [MaxLength(100)]
    public string? Localizacao { get; set; }
    
    [MaxLength(20)]
    public string? Lado { get; set; } // E/D/Bilateral
    
    // Características temporais
    public DateTime? DataInicio { get; set; }
    
    [MaxLength(50)]
    public string? Duracao { get; set; } // <1 semana / 1–4 semanas / 1–3 meses / >3 meses
    
    [MaxLength(20)]
    public string? Evolucao { get; set; } // Melhorou / Piorou / Estável
    
    // Intensidade (slider 0–10)
    public int? Intensidade { get; set; }
    
    // Caráter (multi-select chips)
    [MaxLength(500)]
    public string? CaraterJson { get; set; } // Pontada, Peso, Queimação, Latejante, Rigidez, Cólica
    
    // Fatores (chips)
    [MaxLength(500)]
    public string? FatoresAgravantesJson { get; set; }
    
    [MaxLength(500)]
    public string? FatoresAlivioJson { get; set; }
    
    [MaxLength(1000)]
    public string? Observacoes { get; set; }
}

/// <summary>
/// História clínica passada com interface otimizada
/// </summary>
public class HistoriaClinica
{
    public int Id { get; set; }
    
    [Required]
    public int AvaliacaoClinicaId { get; set; }
    
    [ForeignKey(nameof(AvaliacaoClinicaId))]
    public AvaliacaoClinica AvaliacaoClinica { get; set; } = null!;
    
    // Doenças crónicas (multi-select checklist)
    [MaxLength(1000)]
    public string? DoencasCronicasJson { get; set; } // HTA, Diabetes, Dislipidemia, etc.
    
    [MaxLength(2000)]
    public string? CirurgiasJson { get; set; } // Lista estruturada: Ano|Tipo|Observações
    
    // Alergias
    [MaxLength(500)]
    public string? TiposAlergiasJson { get; set; } // Medicamentos, Alimentares, Ambientais, Contacto
    
    [MaxLength(1000)]
    public string? EspecificarAlergias { get; set; }
    
    public bool SemAlergias { get; set; }
    
    // Medicação e suplementação
    [MaxLength(2000)]
    public string? MedicacaoAtualJson { get; set; } // Substância|Dose|Frequência
    
    public bool SemMedicacao { get; set; }
    
    [MaxLength(2000)]
    public string? SuplementacaoJson { get; set; }
    
    public bool SemSuplementacao { get; set; }
    
    // Vacinação
    [MaxLength(500)]
    public string? VacinacaoJson { get; set; }
    
    public bool VacinacaoNaoAplicavel { get; set; }
    
    [MaxLength(1000)]
    public string? Observacoes { get; set; }
}

/// <summary>
/// Revisão de sistemas com tri-state e observações opcionais
/// </summary>
public class RevisaoSistemas
{
    public int Id { get; set; }
    
    [Required]
    public int AvaliacaoClinicaId { get; set; }
    
    [ForeignKey(nameof(AvaliacaoClinicaId))]
    public AvaliacaoClinica AvaliacaoClinica { get; set; } = null!;
    
    // Sistemas com multi-select + observações opcionais
    [MaxLength(500)]
    public string? CardiovascularJson { get; set; }
    [MaxLength(500)]
    public string? CardiovascularObs { get; set; }
    
    [MaxLength(500)]
    public string? RespiratorioJson { get; set; }
    [MaxLength(500)]
    public string? RespiratorioObs { get; set; }
    
    [MaxLength(500)]
    public string? DigestivoJson { get; set; }
    [MaxLength(500)]
    public string? DigestivoObs { get; set; }
    
    [MaxLength(500)]
    public string? RenalUrinarioJson { get; set; }
    [MaxLength(500)]
    public string? RenalUrinarioObs { get; set; }
    
    [MaxLength(500)]
    public string? EndocrinoMetabolicoJson { get; set; }
    [MaxLength(500)]
    public string? EndocrinoMetabolicoObs { get; set; }
    
    [MaxLength(500)]
    public string? MusculoEsqueleticoJson { get; set; }
    [MaxLength(500)]
    public string? MusculoEsqueleticoObs { get; set; }
    
    [MaxLength(500)]
    public string? NeurologicoJson { get; set; }
    [MaxLength(500)]
    public string? NeurologicoObs { get; set; }
    
    [MaxLength(500)]
    public string? PeleJson { get; set; }
    [MaxLength(500)]
    public string? PeleObs { get; set; }
    
    [MaxLength(500)]
    public string? HumorSonoEnergiaJson { get; set; }
    [MaxLength(500)]
    public string? HumorSonoEnergiaObs { get; set; }
}

/// <summary>
/// Estilo de vida com chips e sliders
/// </summary>
public class EstiloVida
{
    public int Id { get; set; }
    
    [Required]
    public int AvaliacaoClinicaId { get; set; }
    
    [ForeignKey(nameof(AvaliacaoClinicaId))]
    public AvaliacaoClinica AvaliacaoClinica { get; set; } = null!;
    
    // Alimentação (chips)
    [MaxLength(500)]
    public string? AlimentacaoJson { get; set; } // Omnívoro, Mediterrânica, Vegetariana, etc.
    
    // Hidratação (dropdown)
    [MaxLength(20)]
    public string? Hidratacao { get; set; } // <1L | 1–1.5L | 1.5–2L | >2L
    
    // Exercício
    [MaxLength(500)]
    public string? ExercicioJson { get; set; } // Tipos em chips
    [MaxLength(50)]
    public string? ExercicioFrequencia { get; set; }
    
    // Hábitos
    [MaxLength(20)]
    public string? Tabaco { get; set; } // Nunca / Ex-fumador / Fumador
    public int? TabacoQuantidade { get; set; } // nº/dia se fumador
    
    [MaxLength(20)]
    public string? Alcool { get; set; } // Nunca / Social / Frequente
    
    [MaxLength(20)]
    public string? Cafeina { get; set; } // 0 / 1 / 2 / 3+ cafés/dia
    
    // Stress (slider 0–10)
    public int? Stress { get; set; }
    
    // Sono (chips)
    [MaxLength(500)]
    public string? SonoJson { get; set; } // Latência ↑, Despertares, Não restaurador, Roncopatia
    
    [MaxLength(1000)]
    public string? Observacoes { get; set; }
}

/// <summary>
/// História familiar com multi-select e parentesco
/// </summary>
public class HistoriaFamiliar
{
    public int Id { get; set; }
    
    [Required]
    public int AvaliacaoClinicaId { get; set; }
    
    [ForeignKey(nameof(AvaliacaoClinicaId))]
    public AvaliacaoClinica AvaliacaoClinica { get; set; } = null!;
    
    // Antecedentes (multi-select)
    [MaxLength(1000)]
    public string? AntecedentesJson { get; set; } // HTA, Diabetes, AVC, IAM, Cancro, etc.
    
    // Parentesco (chips)
    [MaxLength(500)]
    public string? ParentescoJson { get; set; } // Pai, Mãe, Avós, Irmãos
    
    [MaxLength(1000)]
    public string? Observacoes { get; set; }
}