using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Documentos;

/// <summary>
/// Serviço de gestão de documentos organizados por paciente
/// Cria estrutura de pastas automática: C:\BioDeskPro2\Documentos\Pacientes\{Id}_Nome\{TipoDocumento}\
/// </summary>
public sealed class DocumentoService : IDocumentoService
{
    private readonly ILogger<DocumentoService> _logger;
    private readonly string _pastaRaiz;

    public DocumentoService(ILogger<DocumentoService> logger)
    {
        _logger = logger;

        // Pasta raiz: C:\BioDeskPro2\Documentos
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        _pastaRaiz = Path.Combine(appData, "BioDeskPro2", "Documentos");

        // Criar pasta raiz se não existir
        if (!Directory.Exists(_pastaRaiz))
        {
            Directory.CreateDirectory(_pastaRaiz);
            _logger.LogInformation("📂 Pasta raiz criada: {Pasta}", _pastaRaiz);
        }
    }

    /// <summary>
    /// Normaliza o nome do paciente para usar em pasta (remove caracteres inválidos)
    /// </summary>
    private string NormalizarNomePasta(string nome)
    {
        // Remove caracteres inválidos para nomes de pasta
        var invalidos = Path.GetInvalidFileNameChars();
        var limpo = string.Concat(nome.Where(c => !invalidos.Contains(c)));

        // Remove espaços múltiplos e trim
        limpo = Regex.Replace(limpo, @"\s+", "_").Trim('_');

        return limpo;
    }

    public string ObterPastaPaciente(int pacienteId, string nomePaciente)
    {
        var nomeNormalizado = NormalizarNomePasta(nomePaciente);
        var nomePasta = $"{pacienteId}_{nomeNormalizado}";
        return Path.Combine(_pastaRaiz, "Pacientes", nomePasta);
    }

    public string ObterSubpastaPaciente(int pacienteId, string nomePaciente, TipoDocumento subpasta)
    {
        var pastaPaciente = ObterPastaPaciente(pacienteId, nomePaciente);
        return Path.Combine(pastaPaciente, subpasta.ToString());
    }

    public async Task<bool> CriarEstruturaPastasPacienteAsync(int pacienteId, string nomePaciente)
    {
        try
        {
            var pastaPaciente = ObterPastaPaciente(pacienteId, nomePaciente);

            // Criar pasta raiz do paciente
            if (!Directory.Exists(pastaPaciente))
            {
                Directory.CreateDirectory(pastaPaciente);
                _logger.LogInformation("📂 Pasta paciente criada: {Pasta}", pastaPaciente);
            }

            // Criar subpastas para cada tipo de documento
            foreach (TipoDocumento tipo in Enum.GetValues<TipoDocumento>())
            {
                var subpasta = Path.Combine(pastaPaciente, tipo.ToString());
                if (!Directory.Exists(subpasta))
                {
                    Directory.CreateDirectory(subpasta);
                }
            }

            // Criar ficheiro README.txt com info do paciente
            var readmePath = Path.Combine(pastaPaciente, "README.txt");
            if (!File.Exists(readmePath))
            {
                var conteudo = $"""
                    📋 PASTA DOCUMENTAL - PACIENTE #{pacienteId}
                    ══════════════════════════════════════════════════════════════

                    Nome: {nomePaciente}
                    Data de Criação: {DateTime.Now:dd/MM/yyyy HH:mm}

                    🗂️ ESTRUTURA DE PASTAS:
                    ├── Declaracoes      → Declarações de Saúde
                    ├── Consentimentos   → Termos de Consentimento assinados
                    ├── Prescricoes      → Prescrições e planos terapêuticos
                    ├── Receitas         → Receitas médicas e naturopáticas
                    ├── Relatorios       → Relatórios de consultas
                    ├── Analises         → Resultados de análises clínicas
                    └── Outros           → Documentos diversos

                    ⚠️ IMPORTANTE:
                    - Esta pasta é gerida automaticamente pelo BioDeskPro2
                    - Os documentos são organizados por tipo nas subpastas
                    - Documentos gerados pelo sistema são copiados automaticamente
                    - Pode adicionar manualmente documentos nas subpastas apropriadas

                    📌 SISTEMA: BioDeskPro2 v2.0
                    """;

                await File.WriteAllTextAsync(readmePath, conteudo);
            }

            _logger.LogInformation("✅ Estrutura de pastas criada para paciente {Id}: {Pasta}", pacienteId, pastaPaciente);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao criar estrutura de pastas para paciente {Id}", pacienteId);
            return false;
        }
    }

    public async Task AbrirPastaPacienteAsync(int pacienteId, string nomePaciente, TipoDocumento? subpasta = null)
    {
        try
        {
            var caminho = subpasta.HasValue
                ? ObterSubpastaPaciente(pacienteId, nomePaciente, subpasta.Value)
                : ObterPastaPaciente(pacienteId, nomePaciente);

            // Criar pasta se não existir
            if (!Directory.Exists(caminho))
            {
                await CriarEstruturaPastasPacienteAsync(pacienteId, nomePaciente);
            }

            // Abrir no Windows Explorer (não bloquear UI)
            await Task.Run(() =>
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = caminho,
                    UseShellExecute = true,
                    Verb = "open"
                });
            });

            _logger.LogInformation("📂 Pasta aberta: {Caminho}", caminho);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao abrir pasta do paciente {Id}", pacienteId);
            throw;
        }
    }

    public async Task<List<FicheiroInfo>> ListarFicheirosPacienteAsync(int pacienteId, string nomePaciente, TipoDocumento? subpasta = null)
    {
        try
        {
            var caminho = subpasta.HasValue
                ? ObterSubpastaPaciente(pacienteId, nomePaciente, subpasta.Value)
                : ObterPastaPaciente(pacienteId, nomePaciente);

            if (!Directory.Exists(caminho))
            {
                return new List<FicheiroInfo>();
            }

            var ficheiros = new List<FicheiroInfo>();

            // Se subpasta específica, listar apenas dela
            if (subpasta.HasValue)
            {
                var files = Directory.GetFiles(caminho, "*.*", SearchOption.TopDirectoryOnly);
                ficheiros.AddRange(files.Select(f => CriarFicheiroInfo(f, subpasta.Value)));
            }
            else
            {
                // Listar de todas as subpastas
                foreach (TipoDocumento tipo in Enum.GetValues<TipoDocumento>())
                {
                    var subpastaCaminho = Path.Combine(caminho, tipo.ToString());
                    if (Directory.Exists(subpastaCaminho))
                    {
                        var files = Directory.GetFiles(subpastaCaminho, "*.*", SearchOption.TopDirectoryOnly);
                        ficheiros.AddRange(files.Select(f => CriarFicheiroInfo(f, tipo)));
                    }
                }
            }

            _logger.LogInformation("📋 Listados {Count} ficheiros do paciente {Id}", ficheiros.Count, pacienteId);
            return await Task.FromResult(ficheiros.OrderByDescending(f => f.DataModificacao).ToList());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao listar ficheiros do paciente {Id}", pacienteId);
            return new List<FicheiroInfo>();
        }
    }

    private FicheiroInfo CriarFicheiroInfo(string caminhoCompleto, TipoDocumento categoria)
    {
        var fileInfo = new FileInfo(caminhoCompleto);
        return new FicheiroInfo
        {
            Nome = fileInfo.Name,
            CaminhoCompleto = fileInfo.FullName,
            TamanhoBytes = fileInfo.Length,
            DataCriacao = fileInfo.CreationTime,
            DataModificacao = fileInfo.LastWriteTime,
            Categoria = categoria,
            Extensao = fileInfo.Extension
        };
    }

    public async Task<string> CopiarFicheiroParaPacienteAsync(string caminhoOrigem, int pacienteId, string nomePaciente, TipoDocumento subpasta)
    {
        try
        {
            if (!File.Exists(caminhoOrigem))
            {
                throw new FileNotFoundException("Ficheiro de origem não encontrado", caminhoOrigem);
            }

            // Garantir que estrutura de pastas existe
            await CriarEstruturaPastasPacienteAsync(pacienteId, nomePaciente);

            var pastaDestino = ObterSubpastaPaciente(pacienteId, nomePaciente, subpasta);
            var nomeOriginal = Path.GetFileName(caminhoOrigem);
            var caminhoDestino = Path.Combine(pastaDestino, nomeOriginal);

            // Se ficheiro já existe, adicionar timestamp
            if (File.Exists(caminhoDestino))
            {
                var nomeBase = Path.GetFileNameWithoutExtension(nomeOriginal);
                var extensao = Path.GetExtension(nomeOriginal);
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                nomeOriginal = $"{nomeBase}_{timestamp}{extensao}";
                caminhoDestino = Path.Combine(pastaDestino, nomeOriginal);
            }

            // Copiar ficheiro
            File.Copy(caminhoOrigem, caminhoDestino, overwrite: false);

            _logger.LogInformation("📄 Ficheiro copiado para paciente {Id}: {Destino}", pacienteId, caminhoDestino);
            return caminhoDestino;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao copiar ficheiro para paciente {Id}", pacienteId);
            throw;
        }
    }

    public bool PastaExiste(int pacienteId, string nomePaciente)
    {
        var caminho = ObterPastaPaciente(pacienteId, nomePaciente);
        return Directory.Exists(caminho);
    }
}
