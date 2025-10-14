using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Backup;

/// <summary>
/// Implementação de backup/restore completo com compressão ZIP
/// </summary>
public class BackupService : IBackupService
{
    private readonly ILogger<BackupService> _logger;
    private readonly string _databasePath;
    private readonly string _backupsPath;
    private readonly string _documentosPath;
    private readonly string _templatesPath;

    public BackupService(ILogger<BackupService> logger)
    {
        _logger = logger;
        _databasePath = PathService.DatabasePath;
        _backupsPath = PathService.BackupsPath;
        _documentosPath = PathService.DocumentosPath;
        _templatesPath = PathService.TemplatesPath;

        // Garantir que pasta Backups existe
        Directory.CreateDirectory(_backupsPath);
    }

    public async Task<BackupResult> CreateBackupAsync(
        string? destinoPath = null,
        bool incluirDocumentos = true,
        bool incluirTemplates = true)
    {
        var stopwatch = Stopwatch.StartNew();
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var nomeZip = $"BioDeskBackup_{timestamp}.zip";
        var caminhoZip = Path.Combine(destinoPath ?? _backupsPath, nomeZip);

        try
        {
            _logger.LogInformation("📦 Iniciando backup completo para {Path}", caminhoZip);

            // Criar ZIP temporário com nome único
            var tempZip = Path.Combine(Path.GetTempPath(), $"BioDeskBackup_{Guid.NewGuid():N}.tmp");
            var ficheirosAdicionados = 0;

            using (var archive = ZipFile.Open(tempZip, ZipArchiveMode.Create))
            {
                // 1. Base de dados (SEMPRE incluído) - usar VACUUM INTO para backup seguro
                if (File.Exists(_databasePath))
                {
                    _logger.LogInformation("  📂 Adicionando biodesk.db...");

                    // Criar cópia temporária usando VACUUM INTO (funciona com BD aberta)
                    var tempDb = Path.Combine(Path.GetTempPath(), $"biodesk_backup_{Guid.NewGuid():N}.db");
                    try
                    {
                        using (var connection = new SqliteConnection($"Data Source={_databasePath}"))
                        {
                            await connection.OpenAsync();
                            using var command = connection.CreateCommand();
                            // VACUUM INTO cria uma cópia completa da BD mesmo com ela aberta
                            command.CommandText = "VACUUM INTO @backupPath";
                            command.Parameters.AddWithValue("@backupPath", tempDb);
                            await command.ExecuteNonQueryAsync();
                        }

                        // Adicionar cópia temporária ao ZIP
                        archive.CreateEntryFromFile(tempDb, "biodesk.db", CompressionLevel.Optimal);
                        ficheirosAdicionados++;

                        // Limpar cópia temporária
                        try { File.Delete(tempDb); } catch { /* Ignorar */ }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Erro ao criar backup da base de dados, tentando cópia direta");

                        // Fallback: tentar cópia direta (pode falhar se BD estiver aberta)
                        try
                        {
                            archive.CreateEntryFromFile(_databasePath, "biodesk.db", CompressionLevel.Optimal);
                            ficheirosAdicionados++;
                        }
                        catch
                        {
                            _logger.LogWarning("  ⚠️ Não foi possível adicionar biodesk.db (ficheiro em uso)");
                        }
                    }
                }
                else
                {
                    _logger.LogWarning("  ⚠️ biodesk.db não encontrado em {Path}", _databasePath);
                }

                // 2. Documentos/ (PDFs, prescrições, consentimentos)
                if (incluirDocumentos && Directory.Exists(_documentosPath))
                {
                    _logger.LogInformation("  📂 Adicionando Documentos/...");
                    ficheirosAdicionados += AddDirectoryToZip(archive, _documentosPath, "Documentos");
                }

                // 3. Templates/ (templates QuestPDF, Excel)
                if (incluirTemplates && Directory.Exists(_templatesPath))
                {
                    _logger.LogInformation("  📂 Adicionando Templates/...");
                    ficheirosAdicionados += AddDirectoryToZip(archive, _templatesPath, "Templates");
                }

                // 4. Metadata do backup (info.txt)
                var metadata = $"""
                    BioDeskPro 2.0 - Backup
                    Data: {DateTime.Now:dd/MM/yyyy HH:mm:ss}
                    Versão: 2.0.0
                    Ficheiros: {ficheirosAdicionados}
                    Base Dados: {File.Exists(_databasePath)}
                    Documentos: {incluirDocumentos}
                    Templates: {incluirTemplates}
                    """;

                var metadataEntry = archive.CreateEntry("backup_info.txt");
                using (var writer = new StreamWriter(metadataEntry.Open()))
                {
                    await writer.WriteAsync(metadata);
                }
                ficheirosAdicionados++;
            }

            // Mover ZIP para destino final
            File.Move(tempZip, caminhoZip, overwrite: true);

            // Limpar ficheiro temporário após sucesso
            if (File.Exists(tempZip))
            {
                try { File.Delete(tempZip); } catch { /* Ignorar */ }
            }

            var fileInfo = new FileInfo(caminhoZip);
            stopwatch.Stop();

            _logger.LogInformation("✅ Backup completo criado: {Ficheiros} ficheiros, {Tamanho} MB, {Tempo:N2}s",
                ficheirosAdicionados, fileInfo.Length / (1024.0 * 1024.0), stopwatch.Elapsed.TotalSeconds);

            return new BackupResult(
                Sucesso: true,
                CaminhoZip: caminhoZip,
                TamanhoBytes: fileInfo.Length,
                NumeroFicheiros: ficheirosAdicionados,
                Duracao: stopwatch.Elapsed);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "❌ Erro ao criar backup");

            // Limpar ficheiro temporário se existir
            try
            {
                var tempPattern = Path.Combine(Path.GetTempPath(), "BioDeskBackup_*.tmp");
                var tempFiles = Directory.GetFiles(Path.GetTempPath(), "BioDeskBackup_*.tmp");
                foreach (var tempFile in tempFiles)
                {
                    try { File.Delete(tempFile); } catch { /* Ignorar erro de limpeza */ }
                }
            }
            catch { /* Ignorar erro de limpeza */ }

            return new BackupResult(
                Sucesso: false,
                CaminhoZip: null,
                TamanhoBytes: 0,
                NumeroFicheiros: 0,
                Duracao: stopwatch.Elapsed,
                Erro: ex.Message);
        }
    }

    public async Task<RestoreResult> RestoreBackupAsync(string backupZipPath, bool validarIntegridade = true)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            _logger.LogInformation("📥 Iniciando restore de backup: {Path}", backupZipPath);

            if (!File.Exists(backupZipPath))
            {
                return new RestoreResult(false, 0, stopwatch.Elapsed, "Ficheiro de backup não encontrado");
            }

            // Validar ZIP
            if (validarIntegridade && !await ValidateBackupAsync(backupZipPath))
            {
                return new RestoreResult(false, 0, stopwatch.Elapsed, "Backup inválido ou corrompido");
            }

            // Criar backup de segurança ANTES de restaurar
            _logger.LogInformation("  🛡️ Criando backup de segurança atual...");
            var backupSeguranca = await CreateBackupAsync(
                Path.Combine(_backupsPath, "pre_restore"),
                incluirDocumentos: false,
                incluirTemplates: false);

            if (!backupSeguranca.Sucesso)
            {
                _logger.LogWarning("  ⚠️ Não foi possível criar backup de segurança");
            }

            // Extrair ZIP para pasta temporária
            var tempExtractPath = Path.Combine(Path.GetTempPath(), $"biodesk_restore_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempExtractPath);

            _logger.LogInformation("  📂 Extraindo backup...");
            ZipFile.ExtractToDirectory(backupZipPath, tempExtractPath, overwriteFiles: true);

            var ficheirosRestaurados = 0;

            // Restaurar biodesk.db
            var dbBackupPath = Path.Combine(tempExtractPath, "biodesk.db");
            if (File.Exists(dbBackupPath))
            {
                _logger.LogInformation("  💾 Restaurando biodesk.db...");

                // CRÍTICO: Fechar TODAS as conexões antes de sobrescrever BD
                SqliteConnection.ClearAllPools();
                GC.Collect(); // Forçar garbage collection
                GC.WaitForPendingFinalizers();
                await Task.Delay(1000); // Aguardar release de file handles

                try
                {
                    File.Copy(dbBackupPath, _databasePath, overwrite: true);
                    ficheirosRestaurados++;
                    _logger.LogInformation("  ✅ biodesk.db restaurado com sucesso");
                }
                catch (IOException ioEx) when (ioEx.Message.Contains("being used"))
                {
                    _logger.LogError("❌ Base de dados ainda está em uso. A aplicação precisa ser reiniciada.");
                    throw new InvalidOperationException("A aplicação precisa ser fechada para restaurar a base de dados. Por favor, feche e execute o restore novamente.", ioEx);
                }
            }
            else
            {
                _logger.LogWarning("  ⚠️ biodesk.db não encontrado no backup");
            }

            // Restaurar Documentos/
            var documentosBackupPath = Path.Combine(tempExtractPath, "Documentos");
            if (Directory.Exists(documentosBackupPath))
            {
                _logger.LogInformation("  📄 Restaurando Documentos/...");
                ficheirosRestaurados += RestoreDirectory(documentosBackupPath, _documentosPath);
            }

            // Restaurar Templates/
            var templatesBackupPath = Path.Combine(tempExtractPath, "Templates");
            if (Directory.Exists(templatesBackupPath))
            {
                _logger.LogInformation("  📋 Restaurando Templates/...");
                ficheirosRestaurados += RestoreDirectory(templatesBackupPath, _templatesPath);
            }

            // Limpar pasta temporária
            try
            {
                Directory.Delete(tempExtractPath, recursive: true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Não foi possível limpar pasta temporária: {Path}", tempExtractPath);
            }

            stopwatch.Stop();
            _logger.LogInformation("✅ Restore completo: {Ficheiros} ficheiros restaurados em {Tempo:N2}s",
                ficheirosRestaurados, stopwatch.Elapsed.TotalSeconds);
            _logger.LogWarning("⚠️ IMPORTANTE: Reinicie a aplicação para garantir que as alterações sejam carregadas corretamente!");

            return new RestoreResult(
                Sucesso: true,
                FicheirosRestaurados: ficheirosRestaurados,
                Duracao: stopwatch.Elapsed);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "❌ Erro ao restaurar backup");
            return new RestoreResult(
                Sucesso: false,
                FicheirosRestaurados: 0,
                Duracao: stopwatch.Elapsed,
                Erro: ex.Message);
        }
    }

    public async Task<List<BackupMetadata>> ListBackupsAsync()
    {
        await Task.CompletedTask; // Método síncrono, mas interface async

        try
        {
            if (!Directory.Exists(_backupsPath))
                return new List<BackupMetadata>();

            var backups = Directory.GetFiles(_backupsPath, "BioDeskBackup_*.zip")
                .Select(path =>
                {
                    var fileInfo = new FileInfo(path);
                    var temBD = false;
                    var temDocs = false;
                    var temTemplates = false;

                    try
                    {
                        using var archive = ZipFile.OpenRead(path);
                        temBD = archive.Entries.Any(e => e.Name == "biodesk.db");
                        temDocs = archive.Entries.Any(e => e.FullName.StartsWith("Documentos/"));
                        temTemplates = archive.Entries.Any(e => e.FullName.StartsWith("Templates/"));
                    }
                    catch
                    {
                        // ZIP corrompido, ignorar
                    }

                    return new BackupMetadata(
                        CaminhoCompleto: path,
                        NomeFicheiro: fileInfo.Name,
                        DataCriacao: fileInfo.CreationTime,
                        TamanhoBytes: fileInfo.Length,
                        TemBaseDados: temBD,
                        TemDocumentos: temDocs,
                        TemTemplates: temTemplates);
                })
                .OrderByDescending(b => b.DataCriacao)
                .ToList();

            _logger.LogInformation("📋 {Count} backups encontrados", backups.Count);
            return backups;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao listar backups");
            return new List<BackupMetadata>();
        }
    }

    public async Task<int> CleanOldBackupsAsync(int manterUltimos = 10)
    {
        try
        {
            var backups = await ListBackupsAsync();
            var paraRemover = backups.Skip(manterUltimos).ToList();

            foreach (var backup in paraRemover)
            {
                try
                {
                    File.Delete(backup.CaminhoCompleto);
                    _logger.LogInformation("🗑️ Backup antigo removido: {Nome}", backup.NomeFicheiro);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Erro ao remover backup {Nome}", backup.NomeFicheiro);
                }
            }

            return paraRemover.Count;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao limpar backups antigos");
            return 0;
        }
    }

    public async Task<bool> ValidateBackupAsync(string backupZipPath)
    {
        await Task.CompletedTask; // Método síncrono, mas interface async

        try
        {
            if (!File.Exists(backupZipPath))
                return false;

            // Tentar abrir ZIP e verificar conteúdo
            using var archive = ZipFile.OpenRead(backupZipPath);

            // Verificar se tem pelo menos biodesk.db
            var temDB = archive.Entries.Any(e => e.Name == "biodesk.db");

            if (!temDB)
            {
                _logger.LogWarning("⚠️ Backup {Path} não contém biodesk.db", backupZipPath);
                return false;
            }

            // TODO: Validar schema SQLite (extrair DB temp e verificar)

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao validar backup {Path}", backupZipPath);
            return false;
        }
    }

    #region Métodos Auxiliares

    private int AddDirectoryToZip(ZipArchive archive, string sourcePath, string entryPrefix)
    {
        var count = 0;
        var files = Directory.GetFiles(sourcePath, "*", SearchOption.AllDirectories);

        foreach (var file in files)
        {
            var relativePath = Path.GetRelativePath(sourcePath, file);
            var entryName = Path.Combine(entryPrefix, relativePath).Replace('\\', '/');

            archive.CreateEntryFromFile(file, entryName, CompressionLevel.Optimal);
            count++;
        }

        return count;
    }

    private int RestoreDirectory(string sourcePath, string destPath)
    {
        var count = 0;
        Directory.CreateDirectory(destPath);

        var files = Directory.GetFiles(sourcePath, "*", SearchOption.AllDirectories);

        foreach (var file in files)
        {
            var relativePath = Path.GetRelativePath(sourcePath, file);
            var destFile = Path.Combine(destPath, relativePath);

            Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);
            File.Copy(file, destFile, overwrite: true);
            count++;
        }

        return count;
    }

    #endregion
}
