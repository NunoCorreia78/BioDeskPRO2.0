using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BioDesk.Services.Backup;

/// <summary>
/// Serviço para backup e restore completo da aplicação
/// Inclui: biodesk.db, Documentos/, Templates/, Pacientes/
/// </summary>
public interface IBackupService
{
    /// <summary>
    /// Cria backup completo da aplicação (ZIP timestamped)
    /// </summary>
    /// <param name="destinoPath">Pasta destino (default: Backups/)</param>
    /// <param name="incluirDocumentos">Incluir pasta Documentos/ no backup</param>
    /// <param name="incluirTemplates">Incluir pasta Templates/ no backup</param>
    /// <returns>Caminho completo do ZIP criado</returns>
    Task<BackupResult> CreateBackupAsync(
        string? destinoPath = null,
        bool incluirDocumentos = true,
        bool incluirTemplates = true);

    /// <summary>
    /// Restaura backup a partir de ficheiro ZIP
    /// </summary>
    /// <param name="backupZipPath">Caminho completo do ZIP de backup</param>
    /// <param name="validarIntegridade">Validar schema SQLite antes de restaurar</param>
    /// <returns>True se restaurado com sucesso</returns>
    Task<RestoreResult> RestoreBackupAsync(string backupZipPath, bool validarIntegridade = true);

    /// <summary>
    /// Lista todos os backups disponíveis (ordenados por data desc)
    /// </summary>
    /// <returns>Lista de metadados de backups</returns>
    Task<List<BackupMetadata>> ListBackupsAsync();

    /// <summary>
    /// Remove backups antigos (mantém apenas últimos N)
    /// </summary>
    /// <param name="manterUltimos">Número de backups a manter</param>
    /// <returns>Número de backups removidos</returns>
    Task<int> CleanOldBackupsAsync(int manterUltimos = 10);

    /// <summary>
    /// Valida integridade de um ficheiro de backup
    /// </summary>
    /// <param name="backupZipPath">Caminho do ZIP</param>
    /// <returns>True se válido</returns>
    Task<bool> ValidateBackupAsync(string backupZipPath);
}

/// <summary>
/// Resultado de operação de backup
/// </summary>
public record BackupResult(
    bool Sucesso,
    string? CaminhoZip,
    long TamanhoBytes,
    int NumeroFicheiros,
    TimeSpan Duracao,
    string? Erro = null)
{
    public string TamanhoFormatado => TamanhoBytes < 1024 * 1024
        ? $"{TamanhoBytes / 1024.0:N2} KB"
        : $"{TamanhoBytes / (1024.0 * 1024.0):N2} MB";
}

/// <summary>
/// Resultado de operação de restore
/// </summary>
public record RestoreResult(
    bool Sucesso,
    int FicheirosRestaurados,
    TimeSpan Duracao,
    string? Erro = null);

/// <summary>
/// Metadados de um backup
/// </summary>
public record BackupMetadata(
    string CaminhoCompleto,
    string NomeFicheiro,
    DateTime DataCriacao,
    long TamanhoBytes,
    bool TemBaseDados,
    bool TemDocumentos,
    bool TemTemplates)
{
    public string TamanhoFormatado => TamanhoBytes < 1024 * 1024
        ? $"{TamanhoBytes / 1024.0:N2} KB"
        : $"{TamanhoBytes / (1024.0 * 1024.0):N2} MB";

    public string DataFormatada => DataCriacao.ToString("dd/MM/yyyy HH:mm");
}
