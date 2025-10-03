using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Documentos;

/// <summary>
/// Interface para serviço de listagem e gestão de documentos de um paciente.
/// Complementa o IDocumentoService com funcionalidades de busca e visualização.
/// </summary>
public interface IDocumentosPacienteService
{
    /// <summary>
    /// Obtém todos os documentos (PDFs) associados a um paciente.
    /// Busca nas pastas: Consentimentos/, Prescricoes/, Pacientes/[NomePaciente]/
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="nomePaciente">Nome completo do paciente (para filtrar ficheiros)</param>
    /// <returns>Lista de documentos ordenada por data (mais recente primeiro)</returns>
    Task<List<DocumentoPaciente>> ObterDocumentosDoPacienteAsync(int pacienteId, string nomePaciente);

    /// <summary>
    /// Lê o conteúdo binário de um documento (para anexar a email, por exemplo)
    /// </summary>
    /// <param name="caminhoCompleto">Caminho absoluto do ficheiro</param>
    /// <returns>Bytes do ficheiro</returns>
    Task<byte[]> LerDocumentoAsync(string caminhoCompleto);

    /// <summary>
    /// Verifica se um documento existe no sistema de ficheiros
    /// </summary>
    /// <param name="caminhoCompleto">Caminho absoluto do ficheiro</param>
    /// <returns>True se o ficheiro existe</returns>
    bool DocumentoExiste(string caminhoCompleto);
}
