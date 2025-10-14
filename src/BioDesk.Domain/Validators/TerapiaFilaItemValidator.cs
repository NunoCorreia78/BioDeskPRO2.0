using FluentValidation;
using BioDesk.Domain.DTOs;
using System.Linq;

namespace BioDesk.Domain.Validators;

/// <summary>
/// Validador FluentValidation para TerapiaFilaItem
/// Garante integridade de dados na fila de execução
/// </summary>
public class TerapiaFilaItemValidator : AbstractValidator<TerapiaFilaItem>
{
    public TerapiaFilaItemValidator()
    {
        // ProtocoloId obrigatório e positivo
        RuleFor(t => t.ProtocoloId)
            .GreaterThan(0).WithMessage("ProtocoloId deve ser maior que 0");

        // Ordem na fila (1-based)
        RuleFor(t => t.Ordem)
            .GreaterThan(0).WithMessage("Ordem deve ser maior que 0 (1-based indexing)");

        // Nome obrigatório
        RuleFor(t => t.Nome)
            .NotEmpty().WithMessage("Nome do protocolo é obrigatório")
            .MinimumLength(3).WithMessage("Nome deve ter no mínimo 3 caracteres");

        // ValuePercent: 0-100%
        RuleFor(t => t.ValuePercent)
            .InclusiveBetween(0, 100)
            .WithMessage("Value % deve estar entre 0% e 100%");

        // ImprovementPercent: -100% a +200% (permitir descidas temporárias)
        RuleFor(t => t.ImprovementPercent)
            .InclusiveBetween(-100, 200)
            .WithMessage("Improvement % deve estar entre -100% e +200%");

        // AlvoMelhoria: 1-100% (CoRe 5.0 permite 80%, 95%, 100%)
        RuleFor(t => t.AlvoMelhoria)
            .InclusiveBetween(1, 100)
            .WithMessage("Alvo de melhoria deve estar entre 1% e 100%");

        // Estado: valores permitidos
        RuleFor(t => t.Estado)
            .Must(BeValidEstado)
            .WithMessage("Estado deve ser: Aguardando, Em Execução, Concluída, Auto-Stop ou Parada");

        // DuracaoSegundos: se definida, deve ser positiva
        RuleFor(t => t.DuracaoSegundos)
            .GreaterThan(0).WithMessage("Duração deve ser maior que 0 segundos")
            .When(t => t.DuracaoSegundos.HasValue);
    }

    /// <summary>
    /// Valida estado da terapia na fila
    /// </summary>
    private bool BeValidEstado(string? estado)
    {
        if (string.IsNullOrWhiteSpace(estado))
            return false;

        var validStates = new[] { "Aguardando", "Em Execução", "Concluída", "Auto-Stop", "Parada" };
        return validStates.Contains(estado, System.StringComparer.OrdinalIgnoreCase);
    }
}
