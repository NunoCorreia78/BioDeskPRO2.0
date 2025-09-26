using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 1) MOTIVO DA CONSULTA 🔴 CRÍTICO
/// Motivo principal da consulta, com chips pré-definidos e texto livre
/// CHIP (motivos pré-definidos) · TXT (motivo personalizado) · TXTL (descrição detalhada)
/// </summary>
public class MotivoExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Critico;
    public override string NomeExpander => "1) Motivo da Consulta";

    // MOTIVOS SELECIONADOS
    private List<string> _motivosEscolhidos = new();
    private string _motivoPersonalizado = string.Empty;
    private string _descricaoDetalhada = string.Empty;
    private string _objetivoPrincipal = string.Empty;
    
    // CONTEXTO
    private string _tipoConsulta = "Primeira consulta";
    private DateTime? _inicioProblema;
    private string _duracaoProblema = string.Empty;
    private string _frequenciaProblema = string.Empty;

    // PROPRIEDADES
    public List<string> MotivosEscolhidos
    {
        get => _motivosEscolhidos;
        set { _motivosEscolhidos = value; OnPropertyChanged(); }
    }

    public string MotivoPersonalizado
    {
        get => _motivoPersonalizado;
        set { _motivoPersonalizado = value; OnPropertyChanged(); }
    }

    public string DescricaoDetalhada
    {
        get => _descricaoDetalhada;
        set { _descricaoDetalhada = value; OnPropertyChanged(); }
    }

    public string ObjetivoPrincipal
    {
        get => _objetivoPrincipal;
        set { _objetivoPrincipal = value; OnPropertyChanged(); }
    }

    public string TipoConsulta
    {
        get => _tipoConsulta;
        set { _tipoConsulta = value; OnPropertyChanged(); }
    }

    public DateTime? InicioProblema
    {
        get => _inicioProblema;
        set { _inicioProblema = value; OnPropertyChanged(); }
    }

    public string DuracaoProblema
    {
        get => _duracaoProblema;
        set { _duracaoProblema = value; OnPropertyChanged(); }
    }

    public string FrequenciaProblema
    {
        get => _frequenciaProblema;
        set { _frequenciaProblema = value; OnPropertyChanged(); }
    }

    // MOTIVOS PRÉ-DEFINIDOS (CHIPS)
    public static List<string> MotivosDisponiveis => new()
    {
        // DORES MUSCULOESQUELÉTICAS
        "Dor lombar",
        "Cervicalgia",
        "Dor no ombro",
        "Dor no joelho",
        "Dores articulares",
        "Tensão muscular",
        "Fibromialgia",
        "Artrite/Artrose",

        // NEUROLÓGICAS/MENTAIS
        "Cefaleias/Enxaquecas",
        "Tonturas",
        "Ansiedade",
        "Stress",
        "Depressão",
        "Fadiga",
        "Insónia",
        "Falta de concentração",

        // DIGESTIVAS
        "Refluxo gastroesofágico",
        "Dispepsia",
        "Obstipação",
        "Diarreia",
        "Síndrome intestino irritável",
        "Náuseas",
        "Dor abdominal",

        // RESPIRATÓRIAS
        "Asma",
        "Rinite alérgica",
        "Sinusite",
        "Tosse crónica",
        "Falta de ar",

        // DERMATOLÓGICAS
        "Eczema",
        "Psoríase",
        "Dermatite",
        "Acne",
        "Urticária",

        // GINECOLÓGICAS
        "Dores menstruais",
        "Síndrome pré-menstrual",
        "Menopausa",
        "Alterações do ciclo",

        // ALERGIAS/INTOLERÂNCIAS
        "Alergias alimentares",
        "Intolerâncias alimentares",
        "Alergias ambientais",

        // METABÓLICAS
        "Diabetes",
        "Obesidade",
        "Problemas da tiroide",
        "Colesterol alto",

        // CARDIOVASCULARES
        "Hipertensão",
        "Palpitações",
        "Problemas circulatórios",

        // OUTROS
        "Check-up preventivo",
        "Segunda opinião",
        "Seguimento",
        "Outro motivo"
    };

    // TIPOS DE CONSULTA
    public static List<string> TiposConsulta => new()
    {
        "Primeira consulta",
        "Consulta de seguimento",
        "Urgência",
        "Check-up preventivo",
        "Segunda opinião",
        "Reavaliação",
        "Outro"
    };

    // DURAÇÃO DO PROBLEMA
    public static List<string> OpcoesDuracao => new()
    {
        "Menos de 1 semana",
        "1-2 semanas",
        "2-4 semanas",
        "1-3 meses",
        "3-6 meses",
        "6 meses - 1 ano",
        "Mais de 1 ano",
        "Anos",
        "Desde sempre"
    };

    // FREQUÊNCIA
    public static List<string> OpcoesFrequencia => new()
    {
        "Constante",
        "Diário",
        "Várias vezes por semana",
        "Semanal",
        "Mensal",
        "Ocasional",
        "Raro",
        "Apenas uma vez"
    };

    // PROPRIEDADES CALCULADAS
    public string MotivoResumido
    {
        get
        {
            var motivos = new List<string>(MotivosEscolhidos);
            if (!string.IsNullOrWhiteSpace(MotivoPersonalizado))
                motivos.Add(MotivoPersonalizado);
            
            return motivos.Count > 0 ? string.Join(", ", motivos) : "Não especificado";
        }
    }

    public bool TemMotivos => MotivosEscolhidos.Count > 0 || !string.IsNullOrWhiteSpace(MotivoPersonalizado);

    // VALIDAÇÃO
    public bool IsValid => TemMotivos;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!TemMotivos)
            errors.Add("É necessário especificar pelo menos um motivo para a consulta");
        
        return errors;
    }

    // MÉTODOS HELPER
    public void AdicionarMotivo(string motivo)
    {
        if (!string.IsNullOrWhiteSpace(motivo) && !MotivosEscolhidos.Contains(motivo))
        {
            MotivosEscolhidos.Add(motivo);
            OnPropertyChanged(nameof(MotivosEscolhidos));
            OnPropertyChanged(nameof(MotivoResumido));
            OnPropertyChanged(nameof(TemMotivos));
        }
    }

    public void RemoverMotivo(string motivo)
    {
        if (MotivosEscolhidos.Remove(motivo))
        {
            OnPropertyChanged(nameof(MotivosEscolhidos));
            OnPropertyChanged(nameof(MotivoResumido));
            OnPropertyChanged(nameof(TemMotivos));
        }
    }

    public void LimparMotivos()
    {
        MotivosEscolhidos.Clear();
        OnPropertyChanged(nameof(MotivosEscolhidos));
        OnPropertyChanged(nameof(MotivoResumido));
        OnPropertyChanged(nameof(TemMotivos));
    }
}