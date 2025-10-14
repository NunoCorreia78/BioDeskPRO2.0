using FluentValidation;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels.Validators;

/// <summary>
/// Validator FluentValidation para ConfiguracaoClinica
/// Valida: NomeClinica (obrigatório), Telefone, Email, NIPC
/// </summary>
public class ConfiguracaoClinicaValidator : AbstractValidator<ConfiguracaoClinica>
{
    public ConfiguracaoClinicaValidator()
    {
        // ✅ Nome da Clínica: OBRIGATÓRIO + Máximo 200 caracteres
        RuleFor(x => x.NomeClinica)
            .NotEmpty()
            .WithMessage("❌ Nome da clínica é obrigatório")
            .MaximumLength(200)
            .WithMessage("❌ Nome muito longo (máximo 200 caracteres)");

        // ✅ Morada: Máximo 300 caracteres (opcional)
        RuleFor(x => x.Morada)
            .MaximumLength(300)
            .WithMessage("❌ Morada muito longa (máximo 300 caracteres)")
            .When(x => !string.IsNullOrWhiteSpace(x.Morada));

        // ✅ Telefone: Formato válido (opcional)
        // Aceita: +351912345678, 912345678, +351 912 345 678, (351) 912-345-678
        RuleFor(x => x.Telefone)
            .Matches(@"^[+\d\s()-]*$")
            .WithMessage("❌ Telefone inválido (use apenas números, +, -, (), espaços)")
            .MinimumLength(9)
            .WithMessage("❌ Telefone muito curto (mínimo 9 dígitos)")
            .MaximumLength(20)
            .WithMessage("❌ Telefone muito longo (máximo 20 caracteres)")
            .When(x => !string.IsNullOrWhiteSpace(x.Telefone));

        // ✅ Email: Formato válido (opcional)
        RuleFor(x => x.Email)
            .EmailAddress()
            .WithMessage("❌ Email inválido")
            .MaximumLength(100)
            .WithMessage("❌ Email muito longo (máximo 100 caracteres)")
            .When(x => !string.IsNullOrWhiteSpace(x.Email));

        // ✅ NIPC: Exatamente 9 dígitos (opcional)
        RuleFor(x => x.NIPC)
            .Matches(@"^\d{9}$")
            .WithMessage("❌ NIPC deve ter exatamente 9 dígitos")
            .When(x => !string.IsNullOrWhiteSpace(x.NIPC));

        // ✅ LogoPath: Máximo 500 caracteres (opcional)
        RuleFor(x => x.LogoPath)
            .MaximumLength(500)
            .WithMessage("❌ Caminho do logo muito longo (máximo 500 caracteres)")
            .When(x => !string.IsNullOrWhiteSpace(x.LogoPath));
    }
}
