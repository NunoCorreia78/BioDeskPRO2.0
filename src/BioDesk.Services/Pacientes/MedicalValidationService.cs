using System;
using System.Collections.Generic;
using System.Linq;
using BioDesk.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Pacientes
{
    public interface IMedicalValidationService
    {
        ValidationResult ValidatePaciente(Paciente paciente);
        ValidationResult ValidateIdade(DateTime? dataNascimento);
        ValidationResult ValidateContacts(string? email, string? telefone);
    }

    public class MedicalValidationService : IMedicalValidationService
    {
        private readonly ILogger<MedicalValidationService> _logger;

        public MedicalValidationService(ILogger<MedicalValidationService> logger)
        {
            _logger = logger;
        }

        public ValidationResult ValidatePaciente(Paciente paciente)
        {
            var result = new ValidationResult();

            if (string.IsNullOrWhiteSpace(paciente.Nome))
            {
                result.AddError("Nome é obrigatório");
            }

            // Validação de idade desabilitada após remoção de DataNascimento
            // var idadeResult = ValidateIdade(paciente.DataNascimento);
            // if (!idadeResult.IsValid)
            // {
            //     result.Errors.AddRange(idadeResult.Errors);
            // }

            var contactResult = ValidateContacts(paciente.Email, paciente.Telefone);
            if (!contactResult.IsValid)
            {
                result.Errors.AddRange(contactResult.Errors);
            }

            return result;
        }

        public ValidationResult ValidateIdade(DateTime? dataNascimento)
        {
            var result = new ValidationResult();

            if (dataNascimento.HasValue)
            {
                var idade = DateTime.Now.Year - dataNascimento.Value.Year;
                if (idade < 0 || idade > 150)
                {
                    result.AddError("Idade deve estar entre 0 e 150 anos");
                }
            }

            return result;
        }

        public ValidationResult ValidateContacts(string? email, string? telefone)
        {
            var result = new ValidationResult();

            if (!string.IsNullOrWhiteSpace(email) && !IsValidEmail(email))
            {
                result.AddError("Email inválido");
            }

            if (!string.IsNullOrWhiteSpace(telefone) && !IsValidPhone(telefone))
            {
                result.AddError("Telefone inválido");
            }

            return result;
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

        private static bool IsValidPhone(string phone)
        {
            return phone.Length >= 9 && phone.All(c => char.IsDigit(c) || c == ' ' || c == '-' || c == '+');
        }
    }

    public class ValidationResult
    {
        public List<string> Errors { get; } = new();
        public bool IsValid => !Errors.Any();

        public void AddError(string error)
        {
            Errors.Add(error);
        }
    }
}