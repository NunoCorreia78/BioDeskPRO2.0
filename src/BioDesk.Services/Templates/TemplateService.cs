using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using BioDesk.Services.Email;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Templates;

/// <summary>
/// Implementação do serviço de templates
/// Templates são ficheiros PDF em Templates/ na raiz do projeto
/// </summary>
public class TemplateService : ITemplateService
{
    private readonly ILogger<TemplateService> _logger;
    private readonly IEmailService _emailService;
    private readonly BioDeskDbContext _dbContext;
    private readonly string _templatePath;

    public TemplateService(
        ILogger<TemplateService> logger,
        IEmailService emailService,
        BioDeskDbContext dbContext)
    {
        _logger = logger;
        _emailService = emailService;
        _dbContext = dbContext;

        // ⚡ Caminho para pasta Templates/ (na raiz do projeto, ao lado de biodesk.db)
        var appPath = AppDomain.CurrentDomain.BaseDirectory;
        _templatePath = Path.Combine(appPath, "Templates");

        // ✅ Criar pasta se não existir
        if (!Directory.Exists(_templatePath))
        {
            Directory.CreateDirectory(_templatePath);
            _logger.LogInformation("📁 Pasta Templates/ criada em: {Path}", _templatePath);
        }
        else
        {
            _logger.LogInformation("📁 Pasta Templates/ encontrada: {Path}", _templatePath);
        }
    }

    /// <summary>
    /// Lista todos os templates disponíveis
    /// </summary>
    public async Task<List<TemplateInfo>> ListarTemplatesAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                if (!Directory.Exists(_templatePath))
                {
                    _logger.LogWarning("⚠️ Pasta Templates/ não existe: {Path}", _templatePath);
                    return new List<TemplateInfo>();
                }

                var templates = new List<TemplateInfo>();
                var files = Directory.GetFiles(_templatePath, "*.pdf");

                _logger.LogInformation("📂 Encontrados {Count} templates em {Path}", files.Length, _templatePath);

                foreach (var file in files)
                {
                    var fileInfo = new FileInfo(file);
                    var nomeArquivo = Path.GetFileNameWithoutExtension(file);

                    // ⚡ Extrair categoria do nome do ficheiro (ex: "Exercicios_Escoliose" → "Exercícios")
                    var categoria = ExtrairCategoria(nomeArquivo);
                    var nomeAmigavel = FormatarNomeAmigavel(nomeArquivo);
                    var descricao = GerarDescricao(nomeArquivo);

                    templates.Add(new TemplateInfo
                    {
                        Nome = fileInfo.Name,
                        NomeAmigavel = nomeAmigavel,
                        CaminhoCompleto = fileInfo.FullName,
                        TamanhoBytes = fileInfo.Length,
                        DataCriacao = fileInfo.CreationTime,
                        Categoria = categoria,
                        Descricao = descricao
                    });
                }

                // Ordenar por categoria e depois por nome
                return templates.OrderBy(t => t.Categoria).ThenBy(t => t.NomeAmigavel).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao listar templates");
                return new List<TemplateInfo>();
            }
        });
    }

    /// <summary>
    /// Envia template por e-mail para o paciente
    /// </summary>
    public async Task<bool> EnviarTemplateParaPacienteAsync(
        int pacienteId,
        string templateNome,
        string? emailDestinatario = null,
        string? assunto = null,
        string? mensagem = null)
    {
        try
        {
            // 1. Validar paciente
            var paciente = await _dbContext.Pacientes
                .Include(p => p.Contacto)
                .FirstOrDefaultAsync(p => p.Id == pacienteId);

            if (paciente == null)
            {
                _logger.LogError("❌ Paciente com ID {Id} não encontrado", pacienteId);
                return false;
            }

            // 2. Validar e-mail destinatário
            var emailFinal = emailDestinatario ?? paciente.Contacto?.EmailPrincipal;
            if (string.IsNullOrWhiteSpace(emailFinal))
            {
                _logger.LogError("❌ Paciente {Nome} não tem e-mail configurado", paciente.NomeCompleto);
                return false;
            }

            // 3. Validar template
            var caminhoTemplate = ObterCaminhoTemplate(templateNome);
            if (caminhoTemplate == null || !File.Exists(caminhoTemplate))
            {
                _logger.LogError("❌ Template '{Nome}' não encontrado", templateNome);
                return false;
            }

            // 4. Preparar mensagem de e-mail
            var assuntoFinal = assunto ?? $"Informação Terapêutica - {FormatarNomeAmigavel(templateNome)}";
            var mensagemFinal = mensagem ?? GerarMensagemPadrao(paciente.NomeCompleto, templateNome);

            // 5. Enviar e-mail com anexo
            var emailMessage = new EmailMessage
            {
                To = emailFinal,
                ToName = paciente.NomeCompleto,
                Subject = assuntoFinal,
                Body = mensagemFinal,
                IsHtml = true,
                Attachments = new List<string> { caminhoTemplate }
            };

            _logger.LogInformation("📧 Enviando template '{Template}' para {Email}...", templateNome, emailFinal);

            var resultado = await _emailService.EnviarAsync(emailMessage);

            if (resultado.Sucesso)
            {
                _logger.LogInformation("✅ Template enviado com sucesso!");

                // 6. Gravar na BD como comunicação
                await GravarComunicacaoAsync(paciente.Id, emailFinal, assuntoFinal, mensagemFinal, caminhoTemplate);

                return true;
            }
            else
            {
                _logger.LogError("❌ Erro ao enviar template: {Mensagem}", resultado.Mensagem);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao enviar template '{Template}' para paciente {PacienteId}", templateNome, pacienteId);
            return false;
        }
    }

    /// <summary>
    /// Copia template para a pasta do paciente
    /// </summary>
    public async Task<string> CopiarTemplateParaPacienteAsync(int pacienteId, string templateNome)
    {
        try
        {
            // 1. Validar paciente
            var paciente = await _dbContext.Pacientes.FindAsync(pacienteId);
            if (paciente == null)
            {
                throw new InvalidOperationException($"Paciente com ID {pacienteId} não encontrado");
            }

            // 2. Validar template
            var caminhoTemplate = ObterCaminhoTemplate(templateNome);
            if (caminhoTemplate == null || !File.Exists(caminhoTemplate))
            {
                throw new FileNotFoundException($"Template '{templateNome}' não encontrado");
            }

            // 3. Criar pasta do paciente se não existir
            var nomePacienteLimpo = LimparNomeParaPasta(paciente.NomeCompleto);
            var pastaPaciente = Path.Combine("Pacientes", nomePacienteLimpo, "Documentos");

            if (!Directory.Exists(pastaPaciente))
            {
                Directory.CreateDirectory(pastaPaciente);
                _logger.LogInformation("📁 Pasta criada: {Pasta}", pastaPaciente);
            }

            // 4. Copiar ficheiro
            var nomeArquivoFinal = $"{DateTime.Now:yyyyMMdd_HHmmss}_{templateNome}";
            var caminhoDestino = Path.Combine(pastaPaciente, nomeArquivoFinal);

            File.Copy(caminhoTemplate, caminhoDestino, overwrite: true);

            _logger.LogInformation("✅ Template copiado para: {Caminho}", caminhoDestino);

            return caminhoDestino;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao copiar template '{Template}' para paciente {PacienteId}", templateNome, pacienteId);
            throw;
        }
    }

    /// <summary>
    /// Verifica se template existe
    /// </summary>
    public bool TemplateExiste(string templateNome)
    {
        var caminho = ObterCaminhoTemplate(templateNome);
        return caminho != null && File.Exists(caminho);
    }

    /// <summary>
    /// Obtém caminho completo do template
    /// </summary>
    public string? ObterCaminhoTemplate(string templateNome)
    {
        if (string.IsNullOrWhiteSpace(templateNome))
            return null;

        var caminho = Path.Combine(_templatePath, templateNome);
        return File.Exists(caminho) ? caminho : null;
    }

    // === MÉTODOS AUXILIARES ===

    /// <summary>
    /// Extrai categoria do nome do ficheiro
    /// </summary>
    private string ExtrairCategoria(string nomeArquivo)
    {
        // Lógica: primeiro segmento antes de "_" (ex: "Exercicios_Escoliose" → "Exercícios")
        var partes = nomeArquivo.Split('_');
        if (partes.Length > 0)
        {
            return partes[0] switch
            {
                "Exercicios" => "Exercícios",
                "Dieta" or "Plano" or "Alimentar" => "Nutrição",
                "Prescricao" => "Prescrições",
                "Consentimento" => "Consentimentos",
                "Relatorio" => "Relatórios",
                _ => "Geral"
            };
        }
        return "Geral";
    }

    /// <summary>
    /// Formata nome do ficheiro para exibição amigável
    /// </summary>
    private string FormatarNomeAmigavel(string nomeArquivo)
    {
        // Remove extensão e substitui _ por espaço
        return nomeArquivo.Replace("_", " ");
    }

    /// <summary>
    /// Gera descrição com base no nome do ficheiro
    /// </summary>
    private string GerarDescricao(string nomeArquivo)
    {
        var nomeLower = nomeArquivo.ToLower();

        if (nomeLower.Contains("escoliose"))
            return "Exercícios terapêuticos para correção postural e escoliose";
        if (nomeLower.Contains("cardiaco"))
            return "Plano alimentar específico para saúde cardiovascular";
        if (nomeLower.Contains("exercicio"))
            return "Rotina de exercícios físicos personalizados";
        if (nomeLower.Contains("prescricao"))
            return "Prescrição naturopática e recomendações terapêuticas";
        if (nomeLower.Contains("consentimento"))
            return "Termo de consentimento informado";

        return "Template informativo para o paciente";
    }

    /// <summary>
    /// Gera mensagem padrão do e-mail
    /// </summary>
    private string GerarMensagemPadrao(string nomePaciente, string templateNome)
    {
        var nomeAmigavel = FormatarNomeAmigavel(Path.GetFileNameWithoutExtension(templateNome));

        return $@"<html>
<body style='font-family: Arial, sans-serif; line-height: 1.6; color: #3F4A3D;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 20px; background-color: #F7F9F6; border: 2px solid #E3E9DE; border-radius: 8px;'>
        <h2 style='color: #9CAF97; border-bottom: 2px solid #E3E9DE; padding-bottom: 10px;'>
            🌿 Nuno Correia - Terapias Naturais
        </h2>
        
        <p>Olá <strong>{nomePaciente}</strong>,</p>
        
        <p>Conforme conversado na consulta, segue em anexo o documento:</p>
        
        <div style='background-color: #FCFDFB; padding: 15px; margin: 20px 0; border-left: 4px solid #9CAF97;'>
            <strong>📄 {nomeAmigavel}</strong>
        </div>
        
        <p>Este material foi preparado especialmente para si, com base nas nossas avaliações e objetivos terapêuticos.</p>
        
        <p>Qualquer dúvida ou necessidade de esclarecimento, não hesite em contactar.</p>
        
        <hr style='border: 1px solid #E3E9DE; margin: 30px 0;'/>
        
        <p style='font-size: 14px; color: #5A6558;'>
            <strong>Nuno Correia</strong><br/>
            Naturopatia • Osteopatia • Medicina Bioenergética<br/>
            📧 <a href='mailto:nunocorreiaterapiasnaturais@gmail.com' style='color: #9CAF97;'>nunocorreiaterapiasnaturais@gmail.com</a><br/>
            📞 +351 964 860 387<br/>
            🌿 <em>Cuidar de si, naturalmente</em>
        </p>
    </div>
</body>
</html>";
    }

    /// <summary>
    /// Grava comunicação na base de dados
    /// </summary>
    private async Task GravarComunicacaoAsync(int pacienteId, string email, string assunto, string corpo, string caminhoAnexo)
    {
        try
        {
            var comunicacao = new Comunicacao
            {
                PacienteId = pacienteId,
                Tipo = TipoComunicacao.Email,
                Destinatario = email,
                Assunto = assunto,
                Corpo = corpo,
                DataCriacao = DateTime.Now,
                IsEnviado = true,
                Status = StatusComunicacao.Enviado,
                DataEnvio = DateTime.Now
            };

            await _dbContext.Comunicacoes.AddAsync(comunicacao);
            await _dbContext.SaveChangesAsync();

            // Gravar anexo
            if (!string.IsNullOrEmpty(caminhoAnexo) && File.Exists(caminhoAnexo))
            {
                var anexo = new AnexoComunicacao
                {
                    ComunicacaoId = comunicacao.Id,
                    CaminhoArquivo = caminhoAnexo,
                    NomeArquivo = Path.GetFileName(caminhoAnexo),
                    TamanhoBytes = new FileInfo(caminhoAnexo).Length,
                    DataCriacao = DateTime.Now
                };

                await _dbContext.Set<AnexoComunicacao>().AddAsync(anexo);
                await _dbContext.SaveChangesAsync();
            }

            _logger.LogInformation("✅ Comunicação gravada na BD: {Id}", comunicacao.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao gravar comunicação na BD");
        }
    }

    /// <summary>
    /// Limpa nome do paciente para usar como nome de pasta (remove caracteres inválidos)
    /// </summary>
    private string LimparNomeParaPasta(string nome)
    {
        var invalidos = Path.GetInvalidFileNameChars();
        var nomeLimpo = string.Join("_", nome.Split(invalidos, StringSplitOptions.RemoveEmptyEntries)).TrimEnd('.');
        return nomeLimpo.Replace(" ", "_");
    }
}
