using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Templates;

/// <summary>
/// Serviço para gestão de templates globais e documentos externos da clínica
/// </summary>
public interface ITemplateGlobalService
{
    /// <summary>
    /// Obtém todos os templates globais ativos
    /// </summary>
    Task<IEnumerable<TemplateGlobal>> GetAllTemplatesAsync();

    /// <summary>
    /// Obtém templates disponíveis para anexar em emails
    /// </summary>
    Task<IEnumerable<TemplateGlobal>> GetTemplatesDisponiveisEmailAsync();

    /// <summary>
    /// Obtém templates por categoria
    /// </summary>
    Task<IEnumerable<TemplateGlobal>> GetTemplatesPorCategoriaAsync(string categoria);

    /// <summary>
    /// Obtém um template por ID
    /// </summary>
    Task<TemplateGlobal?> GetTemplateByIdAsync(int id);

    /// <summary>
    /// Adiciona um novo template/documento externo
    /// </summary>
    /// <param name="nome">Nome do template</param>
    /// <param name="tipo">TemplateApp ou DocumentoExterno</param>
    /// <param name="categoria">Categoria (Consentimento, Declaracao, Prescricao, Geral)</param>
    /// <param name="caminhoArquivo">Caminho relativo do arquivo</param>
    /// <param name="descricao">Descrição opcional</param>
    /// <param name="disponivelEmail">Se deve aparecer como opção de anexo em emails</param>
    Task<TemplateGlobal> AdicionarTemplateAsync(
        string nome,
        string tipo,
        string categoria,
        string caminhoArquivo,
        string? descricao = null,
        bool disponivelEmail = true);

    /// <summary>
    /// Atualiza um template existente
    /// </summary>
    Task AtualizarTemplateAsync(TemplateGlobal template);

    /// <summary>
    /// Remove um template (soft delete)
    /// </summary>
    Task RemoverTemplateAsync(int id);

    /// <summary>
    /// Marca/desmarca template como disponível para email
    /// </summary>
    Task AlterarDisponibilidadeEmailAsync(int id, bool disponivel);

    /// <summary>
    /// Copia um ficheiro para a pasta Templates_Globais e regista na BD
    /// </summary>
    /// <param name="caminhoOrigem">Caminho completo do ficheiro original</param>
    /// <param name="nome">Nome para o template</param>
    /// <param name="categoria">Categoria</param>
    /// <param name="descricao">Descrição opcional</param>
    /// <param name="disponivelEmail">Se deve estar disponível para email</param>
    Task<TemplateGlobal> ImportarDocumentoExternoAsync(
        string caminhoOrigem,
        string nome,
        string categoria,
        string? descricao = null,
        bool disponivelEmail = true);
}
