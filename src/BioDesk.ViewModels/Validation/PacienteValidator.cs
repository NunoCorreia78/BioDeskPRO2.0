using System;
using FluentValidation;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels.Validation;

/// <summary>
/// Validador FluentValidation para entidade Paciente
/// Regras de negócio centralizadas e reutilizáveis baseadas na estrutura atual
/// </summary>
public class PacienteValidator : AbstractValidator<Paciente>
{
    public PacienteValidator()
    {
        RuleFor(p => p.Nome)
            .NotEmpty()
            .WithMessage("Nome é obrigatório")
            .MinimumLength(2)
            .WithMessage("Nome deve ter pelo menos 2 caracteres")
            .MaximumLength(200)
            .WithMessage("Nome não pode ter mais de 200 caracteres")
            .Matches(@"^[a-zA-ZÀ-ÿ\s'.-]*$")
            .WithMessage("Nome contém caracteres inválidos");

        RuleFor(p => p.Email)
            .NotEmpty()
            .WithMessage("Email é obrigatório")
            .EmailAddress()
            .WithMessage("Email inválido")
            .MaximumLength(255)
            .WithMessage("Email não pode ter mais de 255 caracteres");

        RuleFor(p => p.Telefone)
            .Matches(@"^[\d\s+()-]*$")
            .WithMessage("Telefone contém caracteres inválidos")
            .MaximumLength(20)
            .WithMessage("Telefone não pode ter mais de 20 caracteres")
            .When(p => !string.IsNullOrWhiteSpace(p.Telefone));

        RuleFor(p => p.DataNascimento)
            .NotEmpty()
            .WithMessage("Data de nascimento é obrigatória")
            .LessThan(DateTime.Today)
            .WithMessage("Data de nascimento deve ser anterior a hoje")
            .GreaterThan(DateTime.Today.AddYears(-150))
            .WithMessage("Data de nascimento inválida (mais de 150 anos)");
    }
}

/// <summary>
/// Validador simplificado para PacienteViewModel (wrapper)
/// Apenas validações básicas para UI
/// </summary>
public class PacienteViewModelValidator : AbstractValidator<PacienteViewModel>
{
    public PacienteViewModelValidator()
    {
        RuleFor(vm => vm.Nome)
            .NotEmpty()
            .WithMessage("Nome é obrigatório")
            .MinimumLength(2)
            .WithMessage("Nome deve ter pelo menos 2 caracteres");

        RuleFor(vm => vm.Email)
            .NotEmpty()
            .WithMessage("Email é obrigatório")
            .EmailAddress()
            .WithMessage("Email inválido")
            .When(vm => !string.IsNullOrWhiteSpace(vm.Email));

        RuleFor(vm => vm.DataNascimento)
            .NotEmpty()
            .WithMessage("Data de nascimento é obrigatória")
            .LessThan(DateTime.Today)
            .WithMessage("Data de nascimento deve ser anterior a hoje");
    }
}