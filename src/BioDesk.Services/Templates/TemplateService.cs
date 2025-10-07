using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Templates;

/// <summary>
/// Implementação do serviço de templates
/// </summary>
public class TemplateService : ITemplateService
{
    private readonly ILogger<TemplateService> _logger;
    private readonly IPacienteRepository _pacienteRepository;
    private readonly string _templatesPath;

    public TemplateService(
        ILogger<TemplateService> logger,
        IPacienteRepository pacienteRepository)
    {
        _logger = logger;
        _pacienteRepository = pacienteRepository;

        // Pasta Templates/ na raiz do projeto
        _templatesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "Templates");
        _logger.LogInformation("TemplateService inicializado. Pasta templates: {Path}", _templatesPath);
    }

    public async Task<List<TemplateEmail>> ListarTemplatesEmailAsync()
    {
        try
        {
            var emailsPath = Path.Combine(_templatesPath, "Emails");

            if (!Directory.Exists(emailsPath))
            {
                _logger.LogWarning("Pasta de templates de email não encontrada: {Path}", emailsPath);
                return new List<TemplateEmail>();
            }

            var jsonFiles = Directory.GetFiles(emailsPath, "*.json");
            var templates = new List<TemplateEmail>();

            foreach (var file in jsonFiles)
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file);
                    var template = JsonSerializer.Deserialize<TemplateEmail>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });

                    if (template != null)
                    {
                        templates.Add(template);
                        _logger.LogDebug("Template carregado: {Nome}", template.Nome);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erro ao carregar template: {File}", file);
                }
            }

            _logger.LogInformation("Total de templates de email carregados: {Count}", templates.Count);
            return templates.OrderBy(t => t.Nome).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao listar templates de email");
            return new List<TemplateEmail>();
        }
    }

    public async Task<TemplateEmail?> CarregarTemplateEmailAsync(string templateId)
    {
        try
        {
            var templates = await ListarTemplatesEmailAsync();
            return templates.FirstOrDefault(t => t.Id == templateId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar template {TemplateId}", templateId);
            return null;
        }
    }

    public async Task<EmailPreenchido> PreencherTemplateEmailAsync(
        string templateId,
        int pacienteId,
        Dictionary<string, string>? dadosAdicionais = null)
    {
        try
        {
            // Carregar template
            var template = await CarregarTemplateEmailAsync(templateId);
            if (template == null)
            {
                throw new InvalidOperationException($"Template '{templateId}' não encontrado");
            }

            // Obter dados do paciente
            var paciente = await _pacienteRepository.GetByIdAsync(pacienteId);
            if (paciente == null)
            {
                throw new InvalidOperationException($"Paciente ID {pacienteId} não encontrado");
            }

            // Criar dicionário de variáveis
            var variaveis = new Dictionary<string, string>
            {
                ["NomePaciente"] = paciente.NomeCompleto,
                ["DataConsulta"] = dadosAdicionais?.GetValueOrDefault("DataConsulta") ?? DateTime.Now.ToString("dd/MM/yyyy"),
                ["HoraConsulta"] = dadosAdicionais?.GetValueOrDefault("HoraConsulta") ?? "14:00",
                ["TipoConsulta"] = dadosAdicionais?.GetValueOrDefault("TipoConsulta") ?? "Consulta Geral",
                ["NomeTerapeuta"] = dadosAdicionais?.GetValueOrDefault("NomeTerapeuta") ?? "Dr. Nuno Correia",
                ["ContactoTerapeuta"] = dadosAdicionais?.GetValueOrDefault("ContactoTerapeuta") ?? "geral@biodesk.pt | +351 123 456 789"
            };

            // Adicionar variáveis extras fornecidas
            if (dadosAdicionais != null)
            {
                foreach (var (key, value) in dadosAdicionais)
                {
                    variaveis[key] = value;
                }
            }

            // Substituir variáveis no assunto e corpo
            var assuntoPreenchido = SubstituirVariaveis(template.Assunto, variaveis);
            var corpoPreenchido = SubstituirVariaveis(template.Corpo, variaveis);

            _logger.LogInformation("Template '{Template}' preenchido para paciente {Paciente}", template.Nome, paciente.NomeCompleto);

            return new EmailPreenchido
            {
                Assunto = assuntoPreenchido,
                Corpo = corpoPreenchido,
                PacienteId = pacienteId,
                TemplateId = templateId
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao preencher template {TemplateId} para paciente {PacienteId}", templateId, pacienteId);
            throw;
        }
    }

    /// <summary>
    /// Substitui variáveis no formato {{NomeVariavel}} pelos valores fornecidos
    /// </summary>
    private string SubstituirVariaveis(string texto, Dictionary<string, string> variaveis)
    {
        var resultado = texto;

        foreach (var (chave, valor) in variaveis)
        {
            resultado = resultado.Replace($"{{{{{chave}}}}}", valor);
        }

        return resultado;
    }
}
