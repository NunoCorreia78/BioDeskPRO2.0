using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa sintomas ativos permanentes que aparecem no Painel Permanente (Tab 3)
/// Consolidação dos sintomas mais relevantes de todas as sessões
/// </summary>
public class SintomaAtivo
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Referência ao paciente
    /// </summary>
    [Required]
    public int PacienteId { get; set; }
    
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Nome/descrição do sintoma
    /// </summary>
    [Required]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Sistema corporal afetado
    /// </summary>
    [MaxLength(100)]
    public string Sistema { get; set; } = string.Empty;

    /// <summary>
    /// Intensidade atual (0-10)
    /// </summary>
    [Range(0, 10)]
    public int IntensidadeAtual { get; set; }

    /// <summary>
    /// Estado atual do sintoma
    /// </summary>
    public EstadoSintoma Estado { get; set; } = EstadoSintoma.Ativo;

    /// <summary>
    /// Prioridade para ordenação no painel (0-10, maior = mais prioritário)
    /// </summary>
    [Range(0, 10)]
    public int Prioridade { get; set; } = 5;

    /// <summary>
    /// Data da primeira ocorrência
    /// </summary>
    public DateTime PrimeiraOcorrencia { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Data da última atualização
    /// </summary>
    public DateTime UltimaAtualizacao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Data para revisar este sintoma
    /// </summary>
    public DateTime? ReverEm { get; set; }

    /// <summary>
    /// Indica se deve ser arquivado (resolvido há >90 dias)
    /// </summary>
    public bool DeveArquivar => Estado == EstadoSintoma.Resolvido && 
        UltimaAtualizacao < DateTime.UtcNow.AddDays(-90);

    /// <summary>
    /// Observações permanentes sobre este sintoma
    /// </summary>
    [MaxLength(1000)]
    public string ObservacoesPermanentes { get; set; } = string.Empty;

    /// <summary>
    /// Referência à sessão em que foi marcado como permanente
    /// </summary>
    public int? SessaoOrigemId { get; set; }
    
    [ForeignKey(nameof(SessaoOrigemId))]
    public virtual SessaoClinica? SessaoOrigem { get; set; }

    /// <summary>
    /// Histórico de intensidades (JSON para tracking de evolução)
    /// </summary>
    [MaxLength(2000)]
    public string HistoricoIntensidades { get; set; } = string.Empty;

    /// <summary>
    /// Atualiza a intensidade e adiciona ao histórico
    /// </summary>
    public void AtualizarIntensidade(int novaIntensidade, DateTime? data = null)
    {
        IntensidadeAtual = novaIntensidade;
        UltimaAtualizacao = data ?? DateTime.UtcNow;
        
        // Adicionar ao histórico JSON (implementação simplificada)
        var novoRegisto = $"{{\"data\":\"{UltimaAtualizacao:yyyy-MM-dd}\",\"intensidade\":{novaIntensidade}}}";
        HistoricoIntensidades = string.IsNullOrEmpty(HistoricoIntensidades) 
            ? $"[{novoRegisto}]" 
            : HistoricoIntensidades.TrimEnd(']') + $",{novoRegisto}]";
    }

    /// <summary>
    /// Marca o sintoma como resolvido
    /// </summary>
    public void MarcarResolvido()
    {
        Estado = EstadoSintoma.Resolvido;
        IntensidadeAtual = 0;
        UltimaAtualizacao = DateTime.UtcNow;
    }
}