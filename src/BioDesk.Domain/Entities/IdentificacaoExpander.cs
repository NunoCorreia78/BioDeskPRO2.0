using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 0) IDENTIFICAÇÃO 🔴 CRÍTICO
/// Campos essenciais para identificação do paciente
/// TXT (nome, telefone, email) · DD (género, estado civil, profissão) · DAT (nascimento)
/// </summary>
public class IdentificacaoExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Critico;
    public override string NomeExpander => "0) Identificação";

    // DADOS PESSOAIS BÁSICOS
    private string _nomeCompleto = string.Empty;
    private DateTime? _dataNascimento;
    private string _telefone = string.Empty;
    private string _email = string.Empty;
    private string _morada = string.Empty;
    
    // DROPDOWNS
    private string _genero = "Não especificado";
    private string _estadoCivil = "Não especificado";
    private string _profissao = string.Empty;
    private string _escolaridade = "Não especificado";

    // EMERGÊNCIA
    private string _contactoEmergencia = string.Empty;
    private string _relacionEmergencia = string.Empty;

    // PROFISSIONAL
    private string _medicoFamilia = string.Empty;
    private string _centroSaude = string.Empty;
    private string _seguroSaude = string.Empty;

    // PROPRIEDADES
    public string NomeCompleto
    {
        get => _nomeCompleto;
        set { _nomeCompleto = value; OnPropertyChanged(); }
    }

    public DateTime? DataNascimento
    {
        get => _dataNascimento;
        set { _dataNascimento = value; OnPropertyChanged(); CalcularIdade(); }
    }

    public string Telefone
    {
        get => _telefone;
        set { _telefone = value; OnPropertyChanged(); }
    }

    public string Email
    {
        get => _email;
        set { _email = value; OnPropertyChanged(); }
    }

    public string Morada
    {
        get => _morada;
        set { _morada = value; OnPropertyChanged(); }
    }

    public string Genero
    {
        get => _genero;
        set { _genero = value; OnPropertyChanged(); }
    }

    public string EstadoCivil
    {
        get => _estadoCivil;
        set { _estadoCivil = value; OnPropertyChanged(); }
    }

    public string Profissao
    {
        get => _profissao;
        set { _profissao = value; OnPropertyChanged(); }
    }

    public string Escolaridade
    {
        get => _escolaridade;
        set { _escolaridade = value; OnPropertyChanged(); }
    }

    public string ContactoEmergencia
    {
        get => _contactoEmergencia;
        set { _contactoEmergencia = value; OnPropertyChanged(); }
    }

    public string RelacionEmergencia
    {
        get => _relacionEmergencia;
        set { _relacionEmergencia = value; OnPropertyChanged(); }
    }

    public string MedicoFamilia
    {
        get => _medicoFamilia;
        set { _medicoFamilia = value; OnPropertyChanged(); }
    }

    public string CentroSaude
    {
        get => _centroSaude;
        set { _centroSaude = value; OnPropertyChanged(); }
    }

    public string SeguroSaude
    {
        get => _seguroSaude;
        set { _seguroSaude = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public int? Idade { get; private set; }
    public string IdadeTexto => Idade?.ToString() ?? "—";

    private void CalcularIdade()
    {
        if (DataNascimento.HasValue)
        {
            var hoje = DateTime.Today;
            var idade = hoje.Year - DataNascimento.Value.Year;
            if (DataNascimento.Value > hoje.AddYears(-idade)) idade--;
            Idade = idade >= 0 ? idade : null;
        }
        else
        {
            Idade = null;
        }
        OnPropertyChanged(nameof(Idade));
        OnPropertyChanged(nameof(IdadeTexto));
    }

    // OPÇÕES PARA DROPDOWNS
    public static List<string> OpcoesGenero => new()
    {
        "Não especificado",
        "Masculino",
        "Feminino",
        "Outro",
        "Prefiro não dizer"
    };

    public static List<string> OpcoesEstadoCivil => new()
    {
        "Não especificado",
        "Solteiro(a)",
        "Casado(a)",
        "União de facto",
        "Divorciado(a)",
        "Viúvo(a)",
        "Separado(a)"
    };

    public static List<string> OpcoesEscolaridade => new()
    {
        "Não especificado",
        "Ensino básico (1º ciclo)",
        "Ensino básico (2º ciclo)",
        "Ensino básico (3º ciclo)",
        "Ensino secundário",
        "Ensino profissional",
        "Bacharelato",
        "Licenciatura",
        "Mestrado",
        "Doutoramento",
        "Outro"
    };

    // VALIDAÇÃO
    public bool IsValid => !string.IsNullOrWhiteSpace(NomeCompleto) && 
                          !string.IsNullOrWhiteSpace(Telefone);

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (string.IsNullOrWhiteSpace(NomeCompleto))
            errors.Add("Nome completo é obrigatório");
        
        if (string.IsNullOrWhiteSpace(Telefone))
            errors.Add("Telefone é obrigatório");
        
        if (!string.IsNullOrWhiteSpace(Email) && !IsValidEmail(Email))
            errors.Add("Email inválido");
        
        return errors;
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}