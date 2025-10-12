using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Templates;

/// <summary>
/// Implementação do serviço de gestão de templates globais
/// </summary>
public class TemplateGlobalService : ITemplateGlobalService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<TemplateGlobalService> _logger;

    public TemplateGlobalService(
        IUnitOfWork unitOfWork,
        ILogger<TemplateGlobalService> logger)
    {
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    public async Task<IEnumerable<TemplateGlobal>> GetAllTemplatesAsync()
    {
        try
        {
            var templates = await _unitOfWork.TemplatesGlobais.GetAllAsync();
            return templates.Where(t => !t.IsDeleted).OrderBy(t => t.Nome);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter todos os templates");
            throw;
        }
    }

    public async Task<IEnumerable<TemplateGlobal>> GetTemplatesDisponiveisEmailAsync()
    {
        try
        {
            return await _unitOfWork.TemplatesGlobais.GetTemplatesDisponiveisEmailAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter templates disponíveis para email");
            throw;
        }
    }

    public async Task<IEnumerable<TemplateGlobal>> GetTemplatesPorCategoriaAsync(string categoria)
    {
        try
        {
            var templates = await _unitOfWork.TemplatesGlobais.GetByTipoAsync(categoria);
            return templates.Where(t => !t.IsDeleted).OrderBy(t => t.Nome);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter templates da categoria {Categoria}", categoria);
            throw;
        }
    }

    public async Task<TemplateGlobal?> GetTemplateByIdAsync(int id)
    {
        try
        {
            return await _unitOfWork.TemplatesGlobais.GetByIdAsync(id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter template {Id}", id);
            throw;
        }
    }

    public async Task<TemplateGlobal> AdicionarTemplateAsync(
        string nome,
        string tipo,
        string categoria,
        string caminhoArquivo,
        string? descricao = null,
        bool disponivelEmail = true)
    {
        try
        {
            var template = new TemplateGlobal
            {
                Nome = nome,
                Tipo = tipo,
                Categoria = categoria,
                CaminhoArquivo = caminhoArquivo,
                Descricao = descricao,
                DisponivelEmail = disponivelEmail,
                DataAdicao = DateTime.UtcNow
            };

            await _unitOfWork.TemplatesGlobais.AddAsync(template);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("Template '{Nome}' adicionado com sucesso", nome);
            return template;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao adicionar template '{Nome}'", nome);
            throw;
        }
    }

    public async Task AtualizarTemplateAsync(TemplateGlobal template)
    {
        try
        {
            template.DataAtualizacao = DateTime.UtcNow;
            _unitOfWork.TemplatesGlobais.Update(template);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("Template '{Nome}' atualizado com sucesso", template.Nome);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao atualizar template {Id}", template.Id);
            throw;
        }
    }

    public async Task RemoverTemplateAsync(int id)
    {
        try
        {
            var template = await _unitOfWork.TemplatesGlobais.GetByIdAsync(id);
            if (template == null)
            {
                _logger.LogWarning("Template {Id} não encontrado para remoção", id);
                return;
            }

            // Soft delete
            template.IsDeleted = true;
            template.DataAtualizacao = DateTime.UtcNow;
            _unitOfWork.TemplatesGlobais.Update(template);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("Template '{Nome}' removido (soft delete)", template.Nome);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao remover template {Id}", id);
            throw;
        }
    }

    public async Task AlterarDisponibilidadeEmailAsync(int id, bool disponivel)
    {
        try
        {
            var template = await _unitOfWork.TemplatesGlobais.GetByIdAsync(id);
            if (template == null)
            {
                _logger.LogWarning("Template {Id} não encontrado", id);
                return;
            }

            template.DisponivelEmail = disponivel;
            template.DataAtualizacao = DateTime.UtcNow;
            _unitOfWork.TemplatesGlobais.Update(template);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("Template '{Nome}' - DisponivelEmail alterado para {Disponivel}",
                template.Nome, disponivel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao alterar disponibilidade email do template {Id}", id);
            throw;
        }
    }

    public async Task<TemplateGlobal> ImportarDocumentoExternoAsync(
        string caminhoOrigem,
        string nome,
        string categoria,
        string? descricao = null,
        bool disponivelEmail = true)
    {
        try
        {
            if (!File.Exists(caminhoOrigem))
            {
                throw new FileNotFoundException($"Ficheiro não encontrado: {caminhoOrigem}");
            }

            // Criar pasta Templates_Globais se não existir
            var pastaTemplates = Path.Combine(PathService.AppDataPath, "Templates_Globais");
            Directory.CreateDirectory(pastaTemplates);

            // Gerar nome único para evitar conflitos
            var extensao = Path.GetExtension(caminhoOrigem);
            var nomeArquivo = $"{Path.GetFileNameWithoutExtension(caminhoOrigem)}_{DateTime.Now:yyyyMMdd_HHmmss}{extensao}";
            var caminhoDestino = Path.Combine(pastaTemplates, nomeArquivo);

            // Copiar ficheiro
            File.Copy(caminhoOrigem, caminhoDestino, overwrite: false);

            // Criar caminho relativo
            var caminhoRelativo = Path.Combine("Templates_Globais", nomeArquivo);

            // Adicionar à BD
            var template = await AdicionarTemplateAsync(
                nome,
                "DocumentoExterno",
                categoria,
                caminhoRelativo,
                descricao,
                disponivelEmail);

            _logger.LogInformation("Documento externo '{Nome}' importado com sucesso", nome);
            return template;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao importar documento externo '{Nome}'", nome);
            throw;
        }
    }
}
