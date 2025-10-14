using FluentValidation;
using BioDesk.Domain.Entities;
using System;
using System.Linq;
using System.Text.Json;

namespace BioDesk.Domain.Validators;

/// <summary>
/// Validador FluentValidation para ProtocoloTerapeutico
/// Garante integridade de dados antes de gravar na BD
/// </summary>
public class ProtocoloTerapeuticoValidator : AbstractValidator<ProtocoloTerapeutico>
{
    public ProtocoloTerapeuticoValidator()
    {
        // Nome obrigatório (min 3, max 200)
        RuleFor(p => p.Nome)
            .NotEmpty().WithMessage("Nome do protocolo é obrigatório")
            .MinimumLength(3).WithMessage("Nome deve ter no mínimo 3 caracteres")
            .MaximumLength(200).WithMessage("Nome deve ter no máximo 200 caracteres");

        // ExternalId obrigatório (GUID format)
        RuleFor(p => p.ExternalId)
            .NotEmpty().WithMessage("ExternalId é obrigatório")
            .MaximumLength(50).WithMessage("ExternalId deve ter no máximo 50 caracteres");

        // Categoria obrigatória
        RuleFor(p => p.Categoria)
            .NotEmpty().WithMessage("Categoria é obrigatória")
            .MaximumLength(100).WithMessage("Categoria deve ter no máximo 100 caracteres");

        // FrequenciasJson: obrigatório e formato válido
        RuleFor(p => p.FrequenciasJson)
            .NotEmpty().WithMessage("Frequências são obrigatórias")
            .Must(BeValidFrequencyJson).WithMessage("FrequenciasJson deve ser um array JSON válido de números")
            .Must(HaveAtLeastOneFrequency).WithMessage("Deve haver pelo menos 1 frequência definida");

        // AmplitudeV: 0.1 - 10.0V (segurança TiePie HS5)
        RuleFor(p => p.AmplitudeV)
            .InclusiveBetween(0.1, 10.0)
            .WithMessage("Amplitude deve estar entre 0.1V e 10.0V (limite segurança TiePie HS5)");

        // LimiteCorrenteMa: 0.1 - 50.0 mA
        RuleFor(p => p.LimiteCorrenteMa)
            .InclusiveBetween(0.1, 50.0)
            .WithMessage("Limite de corrente deve estar entre 0.1mA e 50.0mA");

        // DuracaoMinPorFrequencia: 1 - 60 minutos
        RuleFor(p => p.DuracaoMinPorFrequencia)
            .InclusiveBetween(1, 60)
            .WithMessage("Duração por frequência deve estar entre 1 e 60 minutos");

        // FormaOnda: valores permitidos
        RuleFor(p => p.FormaOnda)
            .Must(BeValidWaveform).WithMessage("Forma de onda deve ser: Sine, Square, Triangle ou Saw");

        // Modulacao: valores permitidos
        RuleFor(p => p.Modulacao)
            .Must(BeValidModulation).WithMessage("Modulação deve ser: None, AM, FM ou Burst");

        // Canal: valores permitidos
        RuleFor(p => p.Canal)
            .Must(BeValidChannel).WithMessage("Canal deve ser: 1, 2 ou Both");
    }

    /// <summary>
    /// Valida se FrequenciasJson é um array JSON válido
    /// </summary>
    private bool BeValidFrequencyJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return false;

        try
        {
            var frequencies = JsonSerializer.Deserialize<double[]>(json);
            return frequencies != null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Valida se há pelo menos 1 frequência no array
    /// </summary>
    private bool HaveAtLeastOneFrequency(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return false;

        try
        {
            var frequencies = JsonSerializer.Deserialize<double[]>(json);
            return frequencies != null && frequencies.Length > 0 && frequencies.Any(f => f > 0);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Valida forma de onda (TiePie HS5 supported waveforms)
    /// </summary>
    private bool BeValidWaveform(string? waveform)
    {
        if (string.IsNullOrWhiteSpace(waveform))
            return false;

        var validWaveforms = new[] { "Sine", "Square", "Triangle", "Saw" };
        return validWaveforms.Contains(waveform, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Valida modulação (TiePie HS5 supported modulations)
    /// </summary>
    private bool BeValidModulation(string? modulation)
    {
        if (string.IsNullOrWhiteSpace(modulation))
            return false;

        var validModulations = new[] { "None", "AM", "FM", "Burst" };
        return validModulations.Contains(modulation, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Valida canal de saída
    /// </summary>
    private bool BeValidChannel(string? channel)
    {
        if (string.IsNullOrWhiteSpace(channel))
            return false;

        var validChannels = new[] { "1", "2", "Both" };
        return validChannels.Contains(channel, StringComparer.OrdinalIgnoreCase);
    }
}
