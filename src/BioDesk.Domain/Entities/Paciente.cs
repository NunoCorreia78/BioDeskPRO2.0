using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade que representa um paciente no sistema BioDeskPro2 para Naturopatia, Osteopatia e Medicina Quântica
/// Caminho de ouro: Criação → Validação → Gravação → SetPacienteAtivo → NavigateTo("FichaPaciente")
/// </summary>
public class Paciente
{
    public int Id { get; set; }

    #region Dados Pessoais Básicos
    [Required(ErrorMessage = "Nome é obrigatório")]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;

    [Required(ErrorMessage = "Data de nascimento é obrigatória")]
    public DateTime DataNascimento { get; set; }

    [Required(ErrorMessage = "Email é obrigatório")]
    [EmailAddress(ErrorMessage = "Email inválido")]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [MaxLength(20)]
    public string? Telefone { get; set; }

    [MaxLength(10)]
    public string? Genero { get; set; } // M/F/Outro

    [MaxLength(50)]
    public string? EstadoCivil { get; set; }

    [MaxLength(100)]
    public string? Profissao { get; set; }

    [MaxLength(9, ErrorMessage = "NIF deve ter 9 dígitos")]
    [MinLength(9, ErrorMessage = "NIF deve ter 9 dígitos")]
    [RegularExpression(@"^\d{9}$", ErrorMessage = "NIF deve conter apenas 9 dígitos")]
    public string? NIF { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Morada { get; set; }

    [MaxLength(50)]
    public string? ContatoEmergencia { get; set; }

    [MaxLength(20)]
    public string? TelefoneEmergencia { get; set; }
    #endregion

    #region Anamnese Médica Detalhada
    [MaxLength(2000)]
    public string? QueixaPrincipal { get; set; }

    [MaxLength(100)]
    public string? DuracaoSintomas { get; set; }

    [MaxLength(20)]
    public string? IntensidadeSintomas { get; set; }

    [MaxLength(3000)]
    public string? HistoriaDoencaAtual { get; set; }

    [MaxLength(2000)]
    public string? FatoresDesencadeantes { get; set; }

    [MaxLength(2000)]
    public string? TratamentosRealizados { get; set; }

    [MaxLength(2000)]
    public string? DoencasAnteriores { get; set; }

    [MaxLength(2000)]
    public string? CirurgiasRealizadas { get; set; }

    [MaxLength(1000)]
    public string? AlergiasConhecidas { get; set; }

    [MaxLength(2000)]
    public string? SistemaCardiovascular { get; set; }

    [MaxLength(2000)]
    public string? SistemaRespiratorio { get; set; }

    [MaxLength(2000)]
    public string? SistemaDigestivo { get; set; }

    [MaxLength(2000)]
    public string? SistemaNeurologico { get; set; }

    [MaxLength(2000)]
    public string? HabitosAlimentares { get; set; }

    [MaxLength(1000)]
    public string? AtividadeFisica { get; set; }

    [MaxLength(50)]
    public string? QualidadeDesonoEnum { get; set; }

    [MaxLength(2000)]
    public string? GestaoStress { get; set; }

    [MaxLength(50)]
    public string? ConsumoAlcoolEnum { get; set; }

    [MaxLength(50)]
    public string? Tabagismo { get; set; }

    [MaxLength(3000)]
    public string? AntecedentesFamiliares { get; set; }

    [MaxLength(2000)]
    public string? DoencasHereditarias { get; set; }
    #endregion

    #region Anamnese Médica (Legado)
    [MaxLength(2000)]
    public string? HistoricoMedicoFamiliar { get; set; }

    [MaxLength(2000)]
    public string? HistoricoMedicoPessoal { get; set; }

    [MaxLength(1000)]
    public string? MedicacaoAtual { get; set; }

    [MaxLength(1000)]
    public string? SuplementosAtuais { get; set; }

    [MaxLength(500)]
    public string? Alergias { get; set; }

    [MaxLength(500)]
    public string? IntoleranciasAlimentares { get; set; }

    [MaxLength(2000)]
    public string? SintomasPrincipais { get; set; }

    [MaxLength(1000)]
    public string? SintomasSecundarios { get; set; }

    public DateTime? InicioSintomas { get; set; }

    [MaxLength(1000)]
    public string? HistoricoTraumas { get; set; }

    [MaxLength(1000)]
    public string? CirurgiasAnteriores { get; set; }
    #endregion

    #region Estilo de Vida
    [MaxLength(1000)]
    public string? PadroesAlimentares { get; set; }

    public int? QualidadeSono { get; set; } // 1-10

    [MaxLength(500)]
    public string? PatternSono { get; set; }

    public int? NivelStress { get; set; } // 1-10

    public int? NivelAtividadeFisica { get; set; } // 1-10

    [MaxLength(500)]
    public string? TipoExercicio { get; set; }

    public bool Fumador { get; set; }

    [MaxLength(100)]
    public string? ConsumoAlcool { get; set; }

    [MaxLength(100)]
    public string? ConsumoAgua { get; set; } // litros/dia

    [MaxLength(1000)]
    public string? OutrosHabitos { get; set; }
    #endregion

    #region Exame Físico/Postural (Osteopatia)
    public decimal? Altura { get; set; } // cm

    public decimal? Peso { get; set; } // kg

    public int? PressaoSistolica { get; set; }

    public int? PressaoDiastolica { get; set; }

    public int? FrequenciaCardiaca { get; set; }

    [MaxLength(500)]
    public string? PosturaPrincipal { get; set; }

    [MaxLength(1000)]
    public string? AvaliacaoPostural { get; set; }

    [MaxLength(1000)]
    public string? TestesOrtopedicos { get; set; }

    [MaxLength(1000)]
    public string? PontosTensao { get; set; }

    [MaxLength(1000)]
    public string? AmplitudeMovimento { get; set; }

    [MaxLength(1000)]
    public string? PalpacaoTecidual { get; set; }

    [MaxLength(2000)]
    public string? ObservacoesExameFisico { get; set; }
    #endregion

    #region Avaliação Energética (Medicina Quântica)
    [MaxLength(500)]
    public string? EstadoChakraPrincipal { get; set; }

    [MaxLength(1000)]
    public string? AvaliacacaoChakras { get; set; }

    [MaxLength(1000)]
    public string? EstadoMeridianos { get; set; }

    [MaxLength(1000)]
    public string? TestesEnergeticos { get; set; }

    [MaxLength(500)]
    public string? FrequenciasDetectadas { get; set; }

    [MaxLength(1000)]
    public string? BloqueiosEnergeticos { get; set; }

    public int? NivelVitalidade { get; set; } // 1-10

    [MaxLength(1000)]
    public string? AuralEnergetica { get; set; }

    [MaxLength(2000)]
    public string? DiagnosticoEnergetico { get; set; }
    #endregion

    #region Plano Terapêutico
    [MaxLength(2000)]
    public string? TratamentosOsteopaticos { get; set; }

    [MaxLength(2000)]
    public string? ProtocolosNaturopaticos { get; set; }

    [MaxLength(1000)]
    public string? SuplementacaoRecomendada { get; set; }

    [MaxLength(1000)]
    public string? TerapiasComplementares { get; set; }

    [MaxLength(1000)]
    public string? ExerciciosRecomendados { get; set; }

    [MaxLength(1000)]
    public string? MudancasEstiloVida { get; set; }

    public int? FrequenciaSessoes { get; set; } // dias

    public DateTime? ProximaConsulta { get; set; }

    [MaxLength(2000)]
    public string? ObjetivosTratamento { get; set; }
    #endregion

    #region Evolução e Notas
    [MaxLength(5000)]
    public string? NotasSessoes { get; set; }

    [MaxLength(2000)]
    public string? ProgressoSintomas { get; set; }

    [MaxLength(1000)]
    public string? AjustesTratamento { get; set; }

    [MaxLength(1000)]
    public string? ResultadosTestes { get; set; }

    public DateTime? UltimaSessao { get; set; }

    public int? NumeroSessoesRealizadas { get; set; }

    [MaxLength(2000)]
    public string? ObservacoesGerais { get; set; }
    #endregion

    // Timestamps
    public DateTime CriadoEm { get; set; } = DateTime.Now;
    public DateTime AtualizadoEm { get; set; } = DateTime.Now;

    /// <summary>
    /// Calcula IMC baseado na altura e peso
    /// </summary>
    public decimal? IMC 
    { 
        get 
        { 
            if (Altura.HasValue && Peso.HasValue && Altura > 0)
                return Math.Round(Peso.Value / (decimal)Math.Pow((double)(Altura.Value / 100), 2), 2);
            return null;
        } 
    }

    /// <summary>
    /// Calcula idade baseada na data de nascimento
    /// </summary>
    public int Idade 
    { 
        get 
        { 
            var today = DateTime.Today;
            int age = today.Year - DataNascimento.Year;
            if (DataNascimento.Date > today.AddYears(-age)) age--;
            return age;
        } 
    }

    #region Navegação para Consultas
    /// <summary>
    /// Lista de consultas associadas a este paciente
    /// </summary>
    public virtual ICollection<Consulta> Consultas { get; set; } = new List<Consulta>();
    #endregion

    /// <summary>
    /// Atualiza a data de última atualização
    /// </summary>
    public void AtualizarTimestamp()
    {
        AtualizadoEm = DateTime.Now;
    }
}