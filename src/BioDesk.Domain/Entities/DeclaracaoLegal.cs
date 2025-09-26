using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa a declaração legal gerada automaticamente no Tab 2
/// Documento formatado com os dados da sessão + campos de assinatura
/// </summary>
public class DeclaracaoLegal
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Referência à sessão clínica (relação 1:1)
    /// </summary>
    [Required]
    public int SessaoClinicaId { get; set; }
    
    [ForeignKey(nameof(SessaoClinicaId))]
    public virtual SessaoClinica SessaoClinica { get; set; } = null!;

    /// <summary>
    /// Conteúdo da declaração em HTML/texto formatado
    /// Gerado automaticamente a partir dos dados do Tab 1
    /// </summary>
    [Required]
    public string ConteudoDeclaracao { get; set; } = string.Empty;

    /// <summary>
    /// Data de geração da declaração
    /// </summary>
    public DateTime DataGeracao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Versão da declaração (para controle de alterações)
    /// </summary>
    public int Versao { get; set; } = 1;

    /// <summary>
    /// Status da declaração
    /// </summary>
    public StatusDeclaracao Status { get; set; } = StatusDeclaracao.Rascunho;

    /// <summary>
    /// Indica se o paciente assinou
    /// </summary>
    public bool AssinadoPaciente { get; set; } = false;

    /// <summary>
    /// Data da assinatura do paciente
    /// </summary>
    public DateTime? DataAssinaturaPaciente { get; set; }

    /// <summary>
    /// Método de assinatura do paciente
    /// </summary>
    [MaxLength(50)]
    public string MetodoAssinaturaPaciente { get; set; } = string.Empty; // Digital, Manual, etc.

    /// <summary>
    /// Indica se o profissional assinou
    /// </summary>
    public bool AssinadoProfissional { get; set; } = false;

    /// <summary>
    /// Data da assinatura do profissional
    /// </summary>
    public DateTime? DataAssinaturaProfissional { get; set; }

    /// <summary>
    /// Nome do profissional que assinou
    /// </summary>
    [MaxLength(200)]
    public string NomeProfissional { get; set; } = string.Empty;

    /// <summary>
    /// Número de ordem/registo profissional
    /// </summary>
    [MaxLength(50)]
    public string RegistoProfissional { get; set; } = string.Empty;

    /// <summary>
    /// Consentimentos específicos marcados
    /// JSON com lista de consentimentos ativos
    /// </summary>
    [MaxLength(2000)]
    public string ConsentimentosAtivos { get; set; } = string.Empty;

    /// <summary>
    /// Hash de integridade do documento
    /// Para verificar se foi alterado após assinatura
    /// </summary>
    [MaxLength(256)]
    public string HashIntegridade { get; set; } = string.Empty;

    /// <summary>
    /// Observações sobre a declaração
    /// </summary>
    [MaxLength(500)]
    public string Observacoes { get; set; } = string.Empty;

    /// <summary>
    /// Última atualização
    /// </summary>
    public DateTime UltimaAtualizacao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Verifica se a declaração pode ser finalizada
    /// (ambas as assinaturas necessárias)
    /// </summary>
    public bool PodeFinalizar => AssinadoPaciente && AssinadoProfissional;

    /// <summary>
    /// Finaliza a declaração (marca como assinada)
    /// </summary>
    public void Finalizar()
    {
        if (!PodeFinalizar)
            throw new InvalidOperationException("Não é possível finalizar sem ambas as assinaturas");
            
        Status = StatusDeclaracao.Finalizada;
        UltimaAtualizacao = DateTime.UtcNow;
        
        // Gerar hash de integridade
        HashIntegridade = GerarHashIntegridade();
    }

    /// <summary>
    /// Gera hash de integridade do conteúdo
    /// </summary>
    private string GerarHashIntegridade()
    {
        var conteudo = $"{ConteudoDeclaracao}|{DataAssinaturaPaciente}|{DataAssinaturaProfissional}";
        return System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(conteudo))
            .Select(b => b.ToString("x2")).Aggregate((a, b) => a + b);
    }
}

public enum StatusDeclaracao
{
    Rascunho = 0,
    AguardandoAssinaturaPaciente = 1,
    AguardandoAssinaturaProfissional = 2,
    Finalizada = 3,
    Cancelada = 4
}