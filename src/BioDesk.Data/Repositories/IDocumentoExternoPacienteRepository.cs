using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Repository para Documentos Externos do Paciente
/// </summary>
public interface IDocumentoExternoPacienteRepository : IRepository<DocumentoExternoPaciente>
{
    /// <summary>
    /// Obter documentos de um paciente específico
    /// </summary>
    Task<IEnumerable<DocumentoExternoPaciente>> GetByPacienteIdAsync(int pacienteId);

    /// <summary>
    /// Obter documentos de um paciente por categoria
    /// </summary>
    Task<IEnumerable<DocumentoExternoPaciente>> GetByPacienteECategoriaAsync(int pacienteId, string categoria);

    /// <summary>
    /// Pesquisar documentos por descrição
    /// </summary>
    Task<IEnumerable<DocumentoExternoPaciente>> SearchByDescricaoAsync(int pacienteId, string termo);

    /// <summary>
    /// Obter total de espaço ocupado pelos documentos de um paciente (em bytes)
    /// </summary>
    Task<long> GetTotalSizeByPacienteAsync(int pacienteId);
}
