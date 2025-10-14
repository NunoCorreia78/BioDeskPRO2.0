using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Documentos;

/// <summary>
/// Serviço para gestão de documentos externos dos pacientes
/// (Análises, exames, receitas de outros médicos, relatórios)
/// </summary>
public interface IDocumentoExternoPacienteService
{
    /// <summary>
    /// Obtém todos os documentos de um paciente
    /// </summary>
    Task<IEnumerable<DocumentoExternoPaciente>> GetDocumentosPorPacienteAsync(int pacienteId);

    /// <summary>
    /// Obtém documentos por categoria
    /// </summary>
    Task<IEnumerable<DocumentoExternoPaciente>> GetDocumentosPorCategoriaAsync(int pacienteId, string categoria);

    /// <summary>
    /// Obtém um documento por ID
    /// </summary>
    Task<DocumentoExternoPaciente?> GetDocumentoByIdAsync(int id);

    /// <summary>
    /// Adiciona um novo documento externo para um paciente
    /// </summary>
    /// <param name="pacienteId">ID do paciente</param>
    /// <param name="caminhoOrigem">Caminho completo do ficheiro original</param>
    /// <param name="categoria">Categoria: Análises, Imagiologia, Receitas, Relatórios, Outros</param>
    /// <param name="descricao">Descrição do documento</param>
    /// <param name="dataDocumento">Data do documento/exame (opcional)</param>
    Task<DocumentoExternoPaciente> AdicionarDocumentoAsync(
        int pacienteId,
        string caminhoOrigem,
        string categoria,
        string? descricao = null,
        DateTime? dataDocumento = null);

    /// <summary>
    /// Atualiza informações de um documento
    /// </summary>
    Task AtualizarDocumentoAsync(DocumentoExternoPaciente documento);

    /// <summary>
    /// Remove um documento (soft delete) e apaga o ficheiro físico
    /// </summary>
    Task RemoverDocumentoAsync(int id);

    /// <summary>
    /// Obtém o caminho completo de um documento
    /// </summary>
    string GetCaminhoCompletoDocumento(DocumentoExternoPaciente documento);

    /// <summary>
    /// Verifica se o ficheiro físico do documento existe
    /// </summary>
    bool DocumentoExiste(DocumentoExternoPaciente documento);
}
