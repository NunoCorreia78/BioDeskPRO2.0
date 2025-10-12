using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Documentos;

/// <summary>
/// Implementação do serviço de documentos externos dos pacientes
/// </summary>
public class DocumentoExternoPacienteService : IDocumentoExternoPacienteService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IDocumentosPacienteService _documentosPacienteService;
    private readonly ILogger<DocumentoExternoPacienteService> _logger;

    public DocumentoExternoPacienteService(
        IUnitOfWork unitOfWork,
        IDocumentosPacienteService documentosPacienteService,
        ILogger<DocumentoExternoPacienteService> logger)
    {
        _unitOfWork = unitOfWork;
        _documentosPacienteService = documentosPacienteService;
        _logger = logger;
    }

    public async Task<IEnumerable<DocumentoExternoPaciente>> GetDocumentosPorPacienteAsync(int pacienteId)
    {
        try
        {
            return await _unitOfWork.DocumentosExternos.GetByPacienteIdAsync(pacienteId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter documentos do paciente {PacienteId}", pacienteId);
            throw;
        }
    }

    public async Task<IEnumerable<DocumentoExternoPaciente>> GetDocumentosPorCategoriaAsync(int pacienteId, string categoria)
    {
        try
        {
            var documentos = await GetDocumentosPorPacienteAsync(pacienteId);
            return documentos.Where(d => d.Categoria == categoria && !d.IsDeleted);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter documentos da categoria {Categoria} do paciente {PacienteId}",
                categoria, pacienteId);
            throw;
        }
    }

    public async Task<DocumentoExternoPaciente?> GetDocumentoByIdAsync(int id)
    {
        try
        {
            return await _unitOfWork.DocumentosExternos.GetByIdAsync(id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter documento {Id}", id);
            throw;
        }
    }

    public async Task<DocumentoExternoPaciente> AdicionarDocumentoAsync(
        int pacienteId,
        string caminhoOrigem,
        string categoria,
        string? descricao = null,
        DateTime? dataDocumento = null)
    {
        try
        {
            if (!File.Exists(caminhoOrigem))
            {
                throw new FileNotFoundException($"Ficheiro não encontrado: {caminhoOrigem}");
            }

            // Obter paciente para construir caminho
            var paciente = await _unitOfWork.Pacientes.GetByIdAsync(pacienteId);
            if (paciente == null)
            {
                throw new InvalidOperationException($"Paciente {pacienteId} não encontrado");
            }

            // Criar pasta Documentos_Externos se não existir
            var pastaPaciente = Path.Combine(PathService.PacientesPath, paciente.NomeCompleto);
            var pastaDocumentosExternos = Path.Combine(pastaPaciente, "Documentos_Externos");
            Directory.CreateDirectory(pastaDocumentosExternos);

            // Gerar nome único
            var extensao = Path.GetExtension(caminhoOrigem);
            var nomeArquivo = $"{Path.GetFileNameWithoutExtension(caminhoOrigem)}_{DateTime.Now:yyyyMMdd_HHmmss}{extensao}";
            var caminhoDestino = Path.Combine(pastaDocumentosExternos, nomeArquivo);

            // Copiar ficheiro
            File.Copy(caminhoOrigem, caminhoDestino, overwrite: false);

            // Obter informações do ficheiro
            var fileInfo = new FileInfo(caminhoDestino);
            var tipoMime = GetMimeType(extensao);

            // Criar caminho relativo
            var caminhoRelativo = Path.Combine("Pacientes", paciente.NomeCompleto, "Documentos_Externos", nomeArquivo);

            // Criar entidade
            var documento = new DocumentoExternoPaciente
            {
                PacienteId = pacienteId,
                NomeArquivo = Path.GetFileName(caminhoOrigem), // Nome original
                CaminhoArquivo = caminhoRelativo,
                Categoria = categoria,
                Descricao = descricao,
                DataDocumento = dataDocumento,
                DataUpload = DateTime.UtcNow,
                TamanhoBytes = fileInfo.Length,
                TipoMime = tipoMime
            };

            await _unitOfWork.DocumentosExternos.AddAsync(documento);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("Documento '{NomeArquivo}' adicionado para paciente {PacienteId}",
                documento.NomeArquivo, pacienteId);

            return documento;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao adicionar documento para paciente {PacienteId}", pacienteId);
            throw;
        }
    }

    public async Task AtualizarDocumentoAsync(DocumentoExternoPaciente documento)
    {
        try
        {
            _unitOfWork.DocumentosExternos.Update(documento);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("Documento {Id} atualizado com sucesso", documento.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao atualizar documento {Id}", documento.Id);
            throw;
        }
    }

    public async Task RemoverDocumentoAsync(int id)
    {
        try
        {
            var documento = await _unitOfWork.DocumentosExternos.GetByIdAsync(id);
            if (documento == null)
            {
                _logger.LogWarning("Documento {Id} não encontrado para remoção", id);
                return;
            }

            // Soft delete na BD
            documento.IsDeleted = true;
            _unitOfWork.DocumentosExternos.Update(documento);
            await _unitOfWork.SaveChangesAsync();

            // Tentar apagar ficheiro físico
            try
            {
                var caminhoCompleto = GetCaminhoCompletoDocumento(documento);
                if (File.Exists(caminhoCompleto))
                {
                    File.Delete(caminhoCompleto);
                    _logger.LogInformation("Ficheiro físico do documento {Id} apagado", id);
                }
            }
            catch (Exception exFile)
            {
                _logger.LogWarning(exFile, "Erro ao apagar ficheiro físico do documento {Id}", id);
                // Não propaga exceção - soft delete na BD já foi feito
            }

            _logger.LogInformation("Documento {Id} removido (soft delete)", id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao remover documento {Id}", id);
            throw;
        }
    }

    public string GetCaminhoCompletoDocumento(DocumentoExternoPaciente documento)
    {
        return Path.Combine(PathService.AppDataPath, documento.CaminhoArquivo);
    }

    public bool DocumentoExiste(DocumentoExternoPaciente documento)
    {
        var caminhoCompleto = GetCaminhoCompletoDocumento(documento);
        return File.Exists(caminhoCompleto);
    }

    /// <summary>
    /// Determina o tipo MIME baseado na extensão do ficheiro
    /// </summary>
    private static string GetMimeType(string extensao)
    {
        return extensao.ToLowerInvariant() switch
        {
            ".pdf" => "application/pdf",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls" => "application/vnd.ms-excel",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".txt" => "text/plain",
            ".csv" => "text/csv",
            _ => "application/octet-stream"
        };
    }
}
