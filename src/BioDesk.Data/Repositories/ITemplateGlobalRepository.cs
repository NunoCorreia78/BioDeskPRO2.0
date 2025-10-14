using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Repository para Templates Globais (templates da app + documentos externos)
/// </summary>
public interface ITemplateGlobalRepository : IRepository<TemplateGlobal>
{
    /// <summary>
    /// Obter templates disponíveis para anexar em emails
    /// </summary>
    Task<IEnumerable<TemplateGlobal>> GetTemplatesDisponiveisEmailAsync();

    /// <summary>
    /// Obter templates por categoria
    /// </summary>
    Task<IEnumerable<TemplateGlobal>> GetByCategoriaAsync(string categoria);

    /// <summary>
    /// Obter templates por tipo (TemplateApp | DocumentoExterno)
    /// </summary>
    Task<IEnumerable<TemplateGlobal>> GetByTipoAsync(string tipo);

    /// <summary>
    /// Pesquisar templates por nome
    /// </summary>
    Task<IEnumerable<TemplateGlobal>> SearchByNomeAsync(string termo);
}
