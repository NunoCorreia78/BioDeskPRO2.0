using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Pdf;

/// <summary>
/// Serviço para geração de PDFs de Declarações de Saúde
/// Layout igual aos Consentimentos, com assinaturas do paciente e terapeuta
/// </summary>
public class DeclaracaoSaudePdfService
{
    private readonly ILogger<DeclaracaoSaudePdfService> _logger;

    public DeclaracaoSaudePdfService(ILogger<DeclaracaoSaudePdfService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Configurar licença QuestPDF (Community License)
        QuestPDF.Settings.License = LicenseType.Community;
    }

    /// <summary>
    /// Gera PDF de declaração de saúde
    /// </summary>
    public string GerarPdfDeclaracaoSaude(DadosDeclaracaoSaude dados)
    {
        _logger.LogInformation("📄 Gerando PDF de declaração de saúde para: {Nome}", dados.NomePaciente);

        try
        {
            // ✅ ESTRUTURA DE PASTAS DOCUMENTAIS: BaseDirectory\Pacientes\[Nome]\DeclaracoesSaude\
            // Subir da pasta bin/Debug/net8.0-windows até raiz do projeto
            var binDirectory = AppDomain.CurrentDomain.BaseDirectory;
            var baseDirectory = Path.GetFullPath(Path.Combine(binDirectory, "..", "..", "..", "..", ".."));
            var pastaPaciente = Path.Combine(baseDirectory, "Pacientes", dados.NomePaciente);
            var pastaDeclaracoes = Path.Combine(pastaPaciente, "DeclaracoesSaude");
            Directory.CreateDirectory(pastaDeclaracoes);

            var nomeArquivo = $"DeclaracaoSaude_{dados.NomePaciente}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var caminhoCompleto = Path.Combine(pastaDeclaracoes, nomeArquivo);

            _logger.LogInformation("📁 Pasta de destino: {Pasta}", pastaDeclaracoes);

            // Gerar PDF com QuestPDF
            Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4);
                    page.Margin(2, Unit.Centimetre);
                    page.PageColor(Colors.White);
                    page.DefaultTextStyle(x => x.FontSize(11).FontFamily("Arial"));

                    // Cabeçalho
                    page.Header().Element(CriarCabecalho);

                    // Conteúdo Principal
                    page.Content().Element(container => CriarConteudo(container, dados));

                    // Rodapé
                    page.Footer().AlignCenter().Text(text =>
                    {
                        text.Span("Gerado em: ");
                        text.Span($"{DateTime.Now:dd/MM/yyyy HH:mm}").FontSize(9).Italic();
                        text.Span(" | Nuno Correia - Terapias Naturais").FontSize(8).FontColor(Colors.Grey.Medium);
                    });
                });
            })
            .GeneratePdf(caminhoCompleto);

            _logger.LogInformation("✅ PDF gerado com sucesso: {Caminho}", caminhoCompleto);
            return caminhoCompleto;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao gerar PDF de declaração de saúde");
            throw;
        }
    }

    /// <summary>
    /// Abre o PDF no visualizador padrão do sistema
    /// </summary>
    public void AbrirPdf(string caminhoArquivo)
    {
        try
        {
            _logger.LogInformation("📂 Abrindo PDF: {Caminho}", caminhoArquivo);

            var processStartInfo = new ProcessStartInfo
            {
                FileName = caminhoArquivo,
                UseShellExecute = true
            };

            Process.Start(processStartInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao abrir PDF");
            throw;
        }
    }

    #region === LAYOUT DO PDF ===

    private void CriarCabecalho(IContainer container)
    {
        container.Column(mainColumn =>
        {
            mainColumn.Item().Row(row =>
            {
                // Logo/Título à esquerda
                row.RelativeItem().Column(column =>
                {
                    column.Item().Text("🌿 Nuno Correia - Terapias Naturais")
                        .FontSize(20)
                        .Bold()
                        .FontColor(Colors.Grey.Darken3);

                    column.Item().Text("Sistema de Gestão Médica Integrativa")
                        .FontSize(10)
                        .Italic()
                        .FontColor(Colors.Grey.Darken2);
                });

                // Data à direita
                row.ConstantItem(150).AlignRight().Column(column =>
                {
                    column.Item().Text($"Data: {DateTime.Now:dd/MM/yyyy}")
                        .FontSize(10)
                        .FontColor(Colors.Grey.Darken3);
                });
            });

            // Linha separadora
            mainColumn.Item().PaddingTop(10).BorderBottom(2).BorderColor(Colors.Green.Medium);
        });
    }

    private void CriarConteudo(IContainer container, DadosDeclaracaoSaude dados)
    {
        container.Column(column =>
        {
            column.Spacing(15);

            // === TÍTULO DO DOCUMENTO ===
            column.Item().PaddingTop(20).AlignCenter().Text("DECLARAÇÃO DE SAÚDE")
                .FontSize(18)
                .Bold()
                .FontColor(Colors.Grey.Darken3);

            column.Item().AlignCenter().Text("AVALIAÇÃO CLÍNICA INICIAL")
                .FontSize(14)
                .SemiBold()
                .FontColor(Colors.Green.Darken2);

            column.Item().PaddingBottom(10).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);

            // === DADOS DO PACIENTE ===
            column.Item().Background(Colors.Grey.Lighten3).Padding(15).Column(col =>
            {
                col.Item().Text("📋 DADOS DO PACIENTE").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                col.Item().PaddingTop(8).Row(row =>
                {
                    row.RelativeItem().Text(text =>
                    {
                        text.Span("Nome: ").SemiBold();
                        text.Span(dados.NomePaciente);
                    });
                    row.ConstantItem(100).Text(text =>
                    {
                        text.Span("Data: ").SemiBold();
                        text.Span(dados.DataDeclaracao.ToString("dd/MM/yyyy"));
                    });
                });
            });

            // === MOTIVOS DA CONSULTA ===
            if (!string.IsNullOrEmpty(dados.MotivoConsulta))
            {
                column.Item().PaddingTop(10).Text("1. MOTIVOS DA CONSULTA").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.MotivoConsulta)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === HISTÓRIA CLÍNICA PASSADA ===
            if (!string.IsNullOrEmpty(dados.HistoriaClinica))
            {
                column.Item().PaddingTop(10).Text("2. HISTÓRIA CLÍNICA PASSADA").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.HistoriaClinica)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === MEDICAÇÃO ATUAL ===
            if (!string.IsNullOrEmpty(dados.MedicacaoAtual))
            {
                column.Item().PaddingTop(10).Text("3. MEDICAÇÃO/SUPLEMENTAÇÃO ATUAL").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.MedicacaoAtual)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === ALERGIAS E REAÇÕES ADVERSAS ===
            if (!string.IsNullOrEmpty(dados.Alergias))
            {
                column.Item().PaddingTop(10).Background(Colors.Red.Lighten4).Padding(10).Column(col =>
                {
                    col.Item().Text("⚠️ 4. ALERGIAS E REAÇÕES ADVERSAS").FontSize(12).Bold().FontColor(Colors.Red.Darken2);
                    col.Item().PaddingTop(5).Text(dados.Alergias)
                        .FontSize(10)
                        .LineHeight(1.5f);
                });
            }

            // === ESTILO DE VIDA ===
            if (!string.IsNullOrEmpty(dados.EstiloVida))
            {
                column.Item().PaddingTop(10).Text("5. ESTILO DE VIDA").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.EstiloVida)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === HISTÓRIA FAMILIAR ===
            if (!string.IsNullOrEmpty(dados.HistoriaFamiliar))
            {
                column.Item().PaddingTop(10).Text("6. HISTÓRIA FAMILIAR").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.HistoriaFamiliar)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === OBSERVAÇÕES CLÍNICAS ===
            if (!string.IsNullOrEmpty(dados.ObservacoesClinicas))
            {
                column.Item().PaddingTop(15).Background(Colors.Blue.Lighten4).Padding(12).Column(col =>
                {
                    col.Item().Text("💡 OBSERVAÇÕES CLÍNICAS DO TERAPEUTA").FontSize(11).Bold().FontColor(Colors.Blue.Darken2);
                    col.Item().PaddingTop(8).Text(dados.ObservacoesClinicas)
                        .FontSize(10)
                        .LineHeight(1.5f);
                });
            }

            // === DECLARAÇÃO ===
            column.Item().PaddingTop(15).Text("DECLARAÇÃO").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
            column.Item().PaddingTop(5).Column(col =>
            {
                col.Item().Text("Declaro que as informações acima prestadas são verdadeiras e completas. " +
                               "Estou ciente de que a omissão ou falsidade destas informações pode comprometer o diagnóstico e tratamento.")
                    .FontSize(10)
                    .LineHeight(1.5f);

                col.Item().PaddingTop(8).Text("✓ Autorizo o uso destas informações para fins clínicos e de acompanhamento médico.")
                    .FontSize(10)
                    .LineHeight(1.4f);

                col.Item().PaddingTop(5).Text("✓ Comprometo-me a informar qualquer alteração relevante no meu estado de saúde.")
                    .FontSize(10)
                    .LineHeight(1.4f);
            });

            // === ASSINATURAS ===
            column.Item().PaddingTop(30).Row(row =>
            {
                row.RelativeItem().Column(col =>
                {
                    // 🖼️ RENDERIZAR ASSINATURA DO PACIENTE
                    if (!string.IsNullOrEmpty(dados.AssinaturaPacienteBase64))
                    {
                        try
                        {
                            byte[] imageBytes = Convert.FromBase64String(dados.AssinaturaPacienteBase64);
                            col.Item()
                                .Border(1)
                                .BorderColor(Colors.Grey.Lighten2)
                                .Padding(5)
                                .Height(80)  // ✅ Altura fixa
                                .AlignCenter()  // Centraliza o container
                                .AlignMiddle()  // Centraliza verticalmente
                                .Image(imageBytes, ImageScaling.FitWidth);  // ✅ CORRIGIDO: FitWidth em vez de FitArea
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "❌ Erro ao renderizar assinatura do paciente");
                            col.Item().LineHorizontal(1).LineColor(Colors.Black);
                            col.Item().PaddingTop(5).AlignCenter().Text("[Erro ao carregar assinatura]")
                                .FontSize(8)
                                .Italic()
                                .FontColor(Colors.Red.Medium);
                        }
                    }
                    else
                    {
                        col.Item().LineHorizontal(1).LineColor(Colors.Black);
                        col.Item().PaddingTop(5).AlignCenter().Text("[Assinatura não capturada]")
                            .FontSize(8)
                            .Italic()
                            .FontColor(Colors.Red.Medium);
                    }

                    col.Item().PaddingTop(5).AlignCenter().Text("Assinatura do Paciente")
                        .FontSize(9)
                        .Italic();
                    col.Item().AlignCenter().Text(dados.NomePaciente)
                        .FontSize(8)
                        .FontColor(Colors.Grey.Darken1);
                });

                row.ConstantItem(50);

                row.RelativeItem().Column(col =>
                {
                    // 👨‍⚕️ RENDERIZAR ASSINATURA DO TERAPEUTA
                    string caminhoAssinatura = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "Images", "assinatura.png");
                    if (System.IO.File.Exists(caminhoAssinatura))
                    {
                        try
                        {
                            byte[] assinaturaTerapeuta = System.IO.File.ReadAllBytes(caminhoAssinatura);
                            col.Item()
                                .Border(1)
                                .BorderColor(Colors.Grey.Lighten2)
                                .Padding(5)
                                .Height(80)
                                .AlignCenter()  // Centraliza horizontalmente
                                .AlignMiddle()  // Centraliza verticalmente
                                .Image(assinaturaTerapeuta)
                                .FitArea();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "❌ Erro ao carregar assinatura do terapeuta: {Path}", caminhoAssinatura);
                            col.Item().LineHorizontal(1).LineColor(Colors.Black);
                            col.Item().PaddingTop(5).AlignCenter().Text("[Erro ao carregar assinatura]")
                                .FontSize(8)
                                .Italic()
                                .FontColor(Colors.Red.Medium);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("⚠️ Assinatura do terapeuta não encontrada: {Path}", caminhoAssinatura);
                        col.Item().LineHorizontal(1).LineColor(Colors.Black);
                    }

                    col.Item().PaddingTop(5).AlignCenter().Text("Profissional Responsável")
                        .FontSize(9)
                        .Italic();
                    col.Item().AlignCenter().Text(dados.NomeTerapeuta)
                        .FontSize(8)
                        .FontColor(Colors.Grey.Darken1);
                });
            });

            // === RGPD E CONSENTIMENTO ===
            column.Item().PaddingTop(20).Background(Colors.Green.Lighten4).Padding(10).Text(
                "✓ RGPD: Declaro que fui informado(a) sobre a utilização e tratamento dos meus dados pessoais, " +
                "de acordo com o Regulamento Geral de Proteção de Dados (RGPD - Lei 58/2019). " +
                "Autorizo o tratamento dos meus dados para fins clínicos e de acompanhamento médico.")
                .FontSize(8)
                .LineHeight(1.4f)
                .FontColor(Colors.Green.Darken3);

            // === NOTA LEGAL ===
            column.Item().PaddingTop(10).Background(Colors.Yellow.Lighten3).Padding(10).Text(
                "⚠️ Este documento tem validade legal e deve ser guardado em local seguro. " +
                "Em caso de dúvidas ou necessidade de atualização, contacte a clínica.")
                .FontSize(8)
                .Italic()
                .FontColor(Colors.Orange.Darken3);
        });
    }

    #endregion
}

/// <summary>
/// Dados necessários para gerar PDF de declaração de saúde
/// </summary>
public class DadosDeclaracaoSaude
{
    public string NomePaciente { get; set; } = string.Empty;
    public DateTime DataDeclaracao { get; set; } = DateTime.Now;

    // === SECÇÕES DO QUESTIONÁRIO ===
    public string? MotivoConsulta { get; set; }
    public string? HistoriaClinica { get; set; }
    public string? MedicacaoAtual { get; set; }
    public string? Alergias { get; set; }
    public string? EstiloVida { get; set; }
    public string? HistoriaFamiliar { get; set; }
    public string? ObservacoesClinicas { get; set; }

    // === ASSINATURAS ===
    /// <summary>
    /// Assinatura do paciente capturada como imagem PNG em Base64
    /// </summary>
    public string? AssinaturaPacienteBase64 { get; set; }

    /// <summary>
    /// Caminho para a assinatura do terapeuta (ficheiro estático)
    /// </summary>
    public string AssinaturaTerapeutaPath { get; set; } = "Assets/Images/assinatura.png";

    /// <summary>
    /// Nome do terapeuta responsável
    /// </summary>
    public string NomeTerapeuta { get; set; } = "Nuno Correia";
}
