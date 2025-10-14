using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação de IProtocoloRepository com EF Core
/// </summary>
public class ProtocoloRepository : IProtocoloRepository
{
    private readonly BioDeskDbContext _context;

    public ProtocoloRepository(BioDeskDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public async Task<ProtocoloTerapeutico?> GetByIdAsync(int id)
    {
        return await _context.ProtocolosTerapeuticos
            .FirstOrDefaultAsync(p => p.Id == id);
    }

    public async Task<ProtocoloTerapeutico?> GetByExternalIdAsync(string externalId)
    {
        return await _context.ProtocolosTerapeuticos
            .FirstOrDefaultAsync(p => p.ExternalId == externalId);
    }

    public async Task<List<ProtocoloTerapeutico>> GetAllActiveAsync()
    {
        return await _context.ProtocolosTerapeuticos
            .Where(p => p.Ativo)
            .OrderBy(p => p.Nome)
            .ToListAsync();
    }

    public async Task<List<ProtocoloTerapeutico>> GetByCategoriaAsync(string categoria)
    {
        return await _context.ProtocolosTerapeuticos
            .Where(p => p.Ativo && p.Categoria == categoria)
            .OrderBy(p => p.Nome)
            .ToListAsync();
    }

    public async Task<List<ProtocoloTerapeutico>> SearchByNameAsync(string searchTerm)
    {
        var term = searchTerm.ToLower();
        return await _context.ProtocolosTerapeuticos
            .Where(p => p.Ativo && p.Nome.ToLower().Contains(term))
            .OrderBy(p => p.Nome)
            .ToListAsync();
    }

    public async Task<ProtocoloTerapeutico> UpsertAsync(ProtocoloTerapeutico protocolo)
    {
        var existing = await GetByExternalIdAsync(protocolo.ExternalId);

        if (existing != null)
        {
            // Atualizar existente
            existing.Nome = protocolo.Nome;
            existing.Categoria = protocolo.Categoria;
            existing.FrequenciasJson = protocolo.FrequenciasJson;
            existing.AmplitudeV = protocolo.AmplitudeV;
            existing.LimiteCorrenteMa = protocolo.LimiteCorrenteMa;
            existing.FormaOnda = protocolo.FormaOnda;
            existing.Modulacao = protocolo.Modulacao;
            existing.DuracaoMinPorFrequencia = protocolo.DuracaoMinPorFrequencia;
            existing.Canal = protocolo.Canal;
            existing.Contraindicacoes = protocolo.Contraindicacoes;
            existing.Notas = protocolo.Notas;
            existing.AtualizadoEm = DateTime.UtcNow;

            _context.ProtocolosTerapeuticos.Update(existing);
            await _context.SaveChangesAsync();
            return existing;
        }
        else
        {
            // Inserir novo
            _context.ProtocolosTerapeuticos.Add(protocolo);
            await _context.SaveChangesAsync();
            return protocolo;
        }
    }

    public async Task<int> BulkInsertAsync(List<ProtocoloTerapeutico> protocolos)
    {
        if (protocolos == null || !protocolos.Any())
            return 0;

        int count = 0;
        foreach (var protocolo in protocolos)
        {
            await UpsertAsync(protocolo);
            count++;
        }

        return count;
    }

    public async Task<bool> DeactivateAsync(int id)
    {
        var protocolo = await GetByIdAsync(id);
        if (protocolo == null)
            return false;

        protocolo.Ativo = false;
        protocolo.AtualizadoEm = DateTime.UtcNow;

        _context.ProtocolosTerapeuticos.Update(protocolo);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<int> CountActiveAsync()
    {
        return await _context.ProtocolosTerapeuticos
            .CountAsync(p => p.Ativo);
    }

    public async Task AddImportLogAsync(string nomeArquivo, int totalLinhas, int sucessos, int erros, string? mensagemErro = null)
    {
        var log = new ImportacaoExcelLog
        {
            NomeFicheiro = nomeArquivo,
            CaminhoCompleto = nomeArquivo, // Simplificado por agora
            ImportadoEm = DateTime.UtcNow,
            TotalLinhas = totalLinhas,
            LinhasOk = sucessos,
            LinhasWarnings = 0,
            LinhasErros = erros,
            DuracaoSegundos = 0, // Calculado no ExcelImportService se necessário
            Sucesso = erros == 0,
            MensagemErro = mensagemErro
        };

        _context.ImportacoesExcelLog.Add(log);
        await _context.SaveChangesAsync();
    }
}
