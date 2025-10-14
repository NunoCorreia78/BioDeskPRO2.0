using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação do repository para Documentos Externos do Paciente
/// </summary>
public class DocumentoExternoPacienteRepository : Repository<DocumentoExternoPaciente>, IDocumentoExternoPacienteRepository
{
    public DocumentoExternoPacienteRepository(BioDeskDbContext context) : base(context)
    {
    }

    /// <summary>
    /// Obter documentos de um paciente específico
    /// </summary>
    public async Task<IEnumerable<DocumentoExternoPaciente>> GetByPacienteIdAsync(int pacienteId)
    {
        return await _dbSet
            .Where(d => d.PacienteId == pacienteId && !d.IsDeleted)
            .OrderByDescending(d => d.DataDocumento ?? d.DataUpload)
            .ToListAsync();
    }

    /// <summary>
    /// Obter documentos de um paciente por categoria
    /// </summary>
    public async Task<IEnumerable<DocumentoExternoPaciente>> GetByPacienteECategoriaAsync(int pacienteId, string categoria)
    {
        return await _dbSet
            .Where(d => d.PacienteId == pacienteId && d.Categoria == categoria && !d.IsDeleted)
            .OrderByDescending(d => d.DataDocumento ?? d.DataUpload)
            .ToListAsync();
    }

    /// <summary>
    /// Pesquisar documentos por descrição
    /// </summary>
    public async Task<IEnumerable<DocumentoExternoPaciente>> SearchByDescricaoAsync(int pacienteId, string termo)
    {
        if (string.IsNullOrWhiteSpace(termo))
        {
            return await GetByPacienteIdAsync(pacienteId);
        }

        return await _dbSet
            .Where(d => d.PacienteId == pacienteId &&
                       (d.Descricao!.Contains(termo) || d.NomeArquivo.Contains(termo)) &&
                       !d.IsDeleted)
            .OrderByDescending(d => d.DataDocumento ?? d.DataUpload)
            .ToListAsync();
    }

    /// <summary>
    /// Obter total de espaço ocupado pelos documentos de um paciente (em bytes)
    /// </summary>
    public async Task<long> GetTotalSizeByPacienteAsync(int pacienteId)
    {
        return await _dbSet
            .Where(d => d.PacienteId == pacienteId && !d.IsDeleted)
            .SumAsync(d => d.TamanhoBytes ?? 0);
    }
}
