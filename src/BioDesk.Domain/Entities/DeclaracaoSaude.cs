using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade principal para Declaração de Saúde - Aba 2
/// </summary>
public class DeclaracaoSaude
{
    public int Id { get; set; }
    public int PacienteId { get; set; }
    public DateTime DataCriacao { get; set; }
    public DateTime? DataUltimaAtualizacao { get; set; }

    // === ANTECEDENTES PESSOAIS ===

    // Doenças Crónicas
    public bool TemDiabetes { get; set; }
    public bool TemHipertensao { get; set; }
    public bool TemCardiopatias { get; set; }
    public bool TemAlergias { get; set; }
    public bool TemOutrasDoencas { get; set; }
    public string? EspecificacaoOutrasDoencas { get; set; }

    // Suplementação
    public string? SuplementosAlimentares { get; set; }
    public string? MedicamentosNaturais { get; set; }

    // === ANTECEDENTES FAMILIARES ===
    public string? DoencasHereditarias { get; set; }
    public string? ObservacoesFamiliares { get; set; }

    // === ESTILO DE VIDA ===

    // Hábitos
    [Required]
    public string Tabagismo { get; set; } = "Nunca fumou";
    public string? DetalheTabagismo { get; set; }

    [Required]
    public string ConsumoAlcool { get; set; } = "Nunca";
    public string? DetalheAlcool { get; set; }

    [Required]
    public string ExercicioFisico { get; set; } = "Sedentário";
    public string? DetalheExercicio { get; set; }

    public int HorasSono { get; set; } = 8;
    public string QualidadeSono { get; set; } = "Boa";

    // Alimentação
    [Required]
    public string TipoDieta { get; set; } = "Omnívora";
    public string? RestricaoesAlimentares { get; set; }
    public decimal ConsumoAguaDiario { get; set; } = 1.5m; // em litros

    // === DECLARAÇÃO LEGAL ===
    public bool ConfirmoVeracidade { get; set; }
    public bool CompreendoImportancia { get; set; }
    public bool ComprometoInformarAlteracoes { get; set; }
    public string? ObservacoesAdicionais { get; set; }

    // Navegação
    public virtual Paciente? Paciente { get; set; }
    public virtual ICollection<Cirurgia> Cirurgias { get; set; } = new List<Cirurgia>();
    public virtual ICollection<Hospitalizacao> Hospitalizacoes { get; set; } = new List<Hospitalizacao>();
    public virtual ICollection<MedicamentoAtual> MedicamentosAtuais { get; set; } = new List<MedicamentoAtual>();
    public virtual ICollection<AlergiaMedicamentosa> AlergiasMedicamentosas { get; set; } = new List<AlergiaMedicamentosa>();
    public virtual ICollection<AlergiaAlimentar> AlergiasAlimentares { get; set; } = new List<AlergiaAlimentar>();
    public virtual ICollection<AlergiaAmbiental> AlergiasAmbientais { get; set; } = new List<AlergiaAmbiental>();
    public virtual ICollection<IntoleranciaAlimentar> IntoleranciasAlimentares { get; set; } = new List<IntoleranciaAlimentar>();
    public virtual ICollection<HistoriaFamiliar> HistoriaFamiliar { get; set; } = new List<HistoriaFamiliar>();
}

/// <summary>
/// Cirurgias anteriores do paciente
/// </summary>
public class Cirurgia
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    public DateTime Data { get; set; }

    [Required]
    [MaxLength(200)]
    public string TipoCirurgia { get; set; } = string.Empty;

    [MaxLength(200)]
    public string? Hospital { get; set; }

    [MaxLength(500)]
    public string? Observacoes { get; set; }

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}

/// <summary>
/// Hospitalizações do paciente
/// </summary>
public class Hospitalizacao
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    public DateTime Data { get; set; }

    [Required]
    [MaxLength(300)]
    public string Motivo { get; set; } = string.Empty;

    public int DuracaoDias { get; set; }

    [MaxLength(200)]
    public string? Hospital { get; set; }

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}

/// <summary>
/// Medicamentos que o paciente toma atualmente
/// </summary>
public class MedicamentoAtual
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Dosagem { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string Frequencia { get; set; } = string.Empty;

    [Required]
    public DateTime DesdeQuando { get; set; }

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}

/// <summary>
/// Alergias medicamentosas
/// </summary>
public class AlergiaMedicamentosa
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Medicamento { get; set; } = string.Empty;

    [Required]
    public string Severidade { get; set; } = "Leve"; // Leve, Moderada, Grave

    [MaxLength(300)]
    public string? Reacao { get; set; }

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}

/// <summary>
/// Alergias alimentares
/// </summary>
public class AlergiaAlimentar
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Alimento { get; set; } = string.Empty;

    [MaxLength(300)]
    public string? ReacaoConhecida { get; set; }

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}

/// <summary>
/// Alergias ambientais (pólen, ácaros, etc.)
/// </summary>
public class AlergiaAmbiental
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Alergenio { get; set; } = string.Empty;

    [MaxLength(300)]
    public string? Sintomas { get; set; }

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}

/// <summary>
/// Intolerâncias alimentares (separadas das alergias)
/// </summary>
public class IntoleranciaAlimentar
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    [MaxLength(200)]
    public string Alimento { get; set; } = string.Empty;

    [MaxLength(300)]
    public string? Sintomas { get; set; }

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}

/// <summary>
/// História familiar médica relevante
/// </summary>
public class HistoriaFamiliar
{
    public int Id { get; set; }
    public int DeclaracaoSaudeId { get; set; }

    [Required]
    [MaxLength(100)]
    public string GrauParentesco { get; set; } = string.Empty; // Pai, Mãe, Irmão, Avô, etc.

    [Required]
    [MaxLength(200)]
    public string CondicaoDoenca { get; set; } = string.Empty;

    public int? IdadeDiagnostico { get; set; }

    [Required]
    public string Status { get; set; } = "Vivo"; // Vivo, Falecido

    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; }
}
