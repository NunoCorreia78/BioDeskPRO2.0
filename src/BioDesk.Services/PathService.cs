using System;
using System.Diagnostics;
using System.IO;

namespace BioDesk.Services;

/// <summary>
/// Serviço centralizado para gestão de caminhos de ficheiros e pastas.
/// Modo DEBUG (VS Code): Usa pasta do projeto
/// Modo RELEASE (Instalado): Usa ProgramData (C:\ProgramData\BioDeskPro2)
/// </summary>
public static class PathService
{
    /// <summary>
    /// Detecta se está em modo debug (VS Code/Visual Studio)
    /// </summary>
    private static readonly bool IsDebugMode = Debugger.IsAttached;

    /// <summary>
    /// Pasta raiz de dados da aplicação
    /// DEBUG: [Projeto]\Data
    /// RELEASE: C:\ProgramData\BioDeskPro2
    /// </summary>
    public static string AppDataPath
    {
        get
        {
            if (IsDebugMode)
            {
                // Modo Debug: Pasta do projeto (desenvolvimento)
                var projectRoot = AppContext.BaseDirectory;
                // Se estiver em bin/Debug/net8.0-windows, sobe 3 níveis até src/BioDesk.App
                // Depois sobe mais 2 níveis até raiz do projeto
                if (projectRoot.Contains("bin"))
                {
                    projectRoot = Path.GetFullPath(Path.Combine(projectRoot, "..", "..", "..", "..", ".."));
                }
                return projectRoot;
            }
            else
            {
                // Modo Release: ProgramData (instalação)
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "BioDeskPro2");
            }
        }
    }

    /// <summary>
    /// Caminho completo para a base de dados SQLite
    /// </summary>
    public static string DatabasePath => Path.Combine(AppDataPath, "biodesk.db");

    /// <summary>
    /// Pasta raiz de documentos gerados (PDFs, consentimentos, etc.)
    /// </summary>
    public static string DocumentosPath => Path.Combine(AppDataPath, "Documentos");

    /// <summary>
    /// Pasta de documentos específicos de pacientes
    /// </summary>
    public static string PacientesPath => Path.Combine(DocumentosPath, "Pacientes");

    /// <summary>
    /// Pasta de prescrições geradas
    /// </summary>
    public static string PrescricoesPath => Path.Combine(DocumentosPath, "Prescricoes");

    /// <summary>
    /// Pasta de consentimentos assinados
    /// </summary>
    public static string ConsentimentosPath => Path.Combine(DocumentosPath, "Consentimentos");

    /// <summary>
    /// Pasta de templates (logos, cabeçalhos personalizados)
    /// </summary>
    public static string TemplatesPath => Path.Combine(DocumentosPath, "Templates");

    /// <summary>
    /// Pasta de backups da base de dados
    /// </summary>
    public static string BackupsPath => Path.Combine(AppDataPath, "Backups");

    /// <summary>
    /// Pasta de logs da aplicação
    /// </summary>
    public static string LogsPath => Path.Combine(AppDataPath, "Logs");

    /// <summary>
    /// Cria toda a estrutura de pastas necessária
    /// Chamado no arranque da aplicação (App.xaml.cs)
    /// </summary>
    public static void EnsureDirectories()
    {
        // Criar pasta raiz
        Directory.CreateDirectory(AppDataPath);

        // Criar subpastas de documentos
        Directory.CreateDirectory(DocumentosPath);
        Directory.CreateDirectory(PacientesPath);
        Directory.CreateDirectory(PrescricoesPath);
        Directory.CreateDirectory(ConsentimentosPath);
        Directory.CreateDirectory(TemplatesPath);

        // Criar pastas de sistema
        Directory.CreateDirectory(BackupsPath);
        Directory.CreateDirectory(LogsPath);

        // Log para debug
        if (IsDebugMode)
        {
            Console.WriteLine($"🔧 PathService [DEBUG MODE]");
            Console.WriteLine($"  📁 AppDataPath: {AppDataPath}");
            Console.WriteLine($"  🗄️ DatabasePath: {DatabasePath}");
        }
        else
        {
            Console.WriteLine($"📦 PathService [RELEASE MODE]");
            Console.WriteLine($"  📁 AppDataPath: {AppDataPath}");
        }
    }

    /// <summary>
    /// Retorna caminho completo para um documento de paciente
    /// </summary>
    public static string GetPacienteDocumentPath(string numeroProcesso, string nomeDocumento)
    {
        var pacientePath = Path.Combine(PacientesPath, numeroProcesso);
        Directory.CreateDirectory(pacientePath); // Criar pasta do paciente se não existir
        return Path.Combine(pacientePath, nomeDocumento);
    }

    /// <summary>
    /// Retorna caminho completo para uma prescrição
    /// </summary>
    public static string GetPrescricaoPath(string numeroProcesso, DateTime data)
    {
        var fileName = $"Prescricao_{numeroProcesso}_{data:yyyyMMdd_HHmmss}.pdf";
        return Path.Combine(PrescricoesPath, fileName);
    }

    /// <summary>
    /// Retorna caminho completo para um consentimento
    /// </summary>
    public static string GetConsentimentoPath(string tipoConsentimento, string nomePaciente, DateTime data)
    {
        var safeNome = string.Join("_", nomePaciente.Split(Path.GetInvalidFileNameChars()));
        var fileName = $"Consentimento_{tipoConsentimento}_{safeNome}_{data:yyyyMMdd_HHmmss}.pdf";
        return Path.Combine(ConsentimentosPath, fileName);
    }

    /// <summary>
    /// Retorna caminho para o logo da clínica
    /// </summary>
    public static string LogoPath => Path.Combine(TemplatesPath, "logo.png");

    /// <summary>
    /// Retorna informação de diagnóstico (para debug)
    /// </summary>
    public static string GetDiagnosticInfo()
    {
        return $@"
PathService Diagnostic Information
===================================
Modo: {(IsDebugMode ? "DEBUG" : "RELEASE")}
AppDataPath: {AppDataPath}
DatabasePath: {DatabasePath}
DatabaseExists: {File.Exists(DatabasePath)}

Documentos:
  - Pacientes: {PacientesPath}
  - Prescrições: {PrescricoesPath}
  - Consentimentos: {ConsentimentosPath}
  - Templates: {TemplatesPath}

Sistema:
  - Backups: {BackupsPath}
  - Logs: {LogsPath}
";
    }
}
