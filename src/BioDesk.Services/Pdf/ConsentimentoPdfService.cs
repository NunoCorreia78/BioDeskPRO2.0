using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Extensions.Logging;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Pdf;

/// <summary>
/// Serviço para geração de PDFs de Consentimentos Informados
/// Usa QuestPDF para criar documentos profissionais com assinatura digital
/// </summary>
public class ConsentimentoPdfService
{
    private readonly ILogger<ConsentimentoPdfService> _logger;
    private readonly IUnitOfWork _unitOfWork;

    public ConsentimentoPdfService(
        IUnitOfWork unitOfWork,
        ILogger<ConsentimentoPdfService> logger)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Configurar licença QuestPDF (Community License - grátis para uso pessoal/pequenos negócios)
        QuestPDF.Settings.License = LicenseType.Community;
    }

    /// <summary>
    /// Gera PDF de consentimento informado
    /// </summary>
    public string GerarPdfConsentimento(DadosConsentimento dados)
    {
        _logger.LogInformation("📄 Gerando PDF de consentimento para: {Nome}", dados.NomePaciente);

        try
        {
            // 🏥 CARREGAR CONFIGURAÇÃO DA CLÍNICA (logo + dados)
            ConfiguracaoClinica? config = null;
            string? logoPath = null;

            try
            {
                config = _unitOfWork.ConfiguracaoClinica.GetByIdAsync(1).Result;
                if (config?.LogoPath != null)
                {
                    logoPath = Path.Combine(PathService.AppDataPath, config.LogoPath);
                    if (!File.Exists(logoPath))
                    {
                        _logger.LogWarning("⚠️ Logo configurado mas ficheiro não existe: {LogoPath}", logoPath);
                        logoPath = null;
                    }
                    else
                    {
                        _logger.LogInformation("✅ Logo da clínica carregado: {LogoPath}", logoPath);
                    }
                }
            }
            catch (Exception exConfig)
            {
                _logger.LogWarning(exConfig, "⚠️ Erro ao carregar configuração - PDF continuará sem logo");
            }

            // ✅ USAR PathService PARA GARANTIR COMPATIBILIDADE DEBUG/RELEASE
            var pastaPaciente = PathService.GetPacienteDocumentPath(dados.NomePaciente, "");
            var pastaConsentimentos = Path.Combine(pastaPaciente, "Consentimentos");
            Directory.CreateDirectory(pastaConsentimentos);

            var nomeArquivo = $"Consentimento_{dados.TipoTratamento}_{dados.NomePaciente}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var caminhoCompleto = Path.Combine(pastaConsentimentos, nomeArquivo);

            _logger.LogInformation("📁 Pasta de destino: {Pasta}", pastaConsentimentos);

            // Gerar PDF com QuestPDF
            Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4);
                    page.Margin(2, Unit.Centimetre);
                    page.PageColor(Colors.White);
                    page.DefaultTextStyle(x => x.FontSize(11).FontFamily("Arial"));

                    // Cabeçalho (passa config e logoPath)
                    page.Header().Element(c => CriarCabecalho(c, config, logoPath));

                    // Conteúdo Principal
                    page.Content().Element(container => CriarConteudo(container, dados));

                    // Rodapé - Contactos e Redes Sociais
                    page.Footer().AlignCenter().Column(col =>
                    {
                        col.Item().Text(text =>
                        {
                            text.Span("📧 nunocorreiaterapiasnaturais@gmail.com  |  ")
                                .FontSize(8)
                                .FontColor(Colors.Grey.Darken2);
                            text.Span("☎ 964 860 387")
                                .FontSize(8)
                                .FontColor(Colors.Grey.Darken2);
                        });

                        col.Item().PaddingTop(3).Text(text =>
                        {
                            text.Span("Instagram: @nunocorreia.naturopata  |  ")
                                .FontSize(7)
                                .FontColor(Colors.Grey.Medium);
                            text.Span("Facebook: facebook.com/nunocorreia.naturopata")
                                .FontSize(7)
                                .FontColor(Colors.Grey.Medium);
                        });

                        col.Item().PaddingTop(3).Text("Gerado em: " + $"{DateTime.Now:dd/MM/yyyy HH:mm}")
                            .FontSize(7)
                            .FontColor(Colors.Grey.Medium)
                            .Italic();
                    });
                });
            })
            .GeneratePdf(caminhoCompleto);

            _logger.LogInformation("✅ PDF gerado com sucesso: {Caminho}", caminhoCompleto);
            return caminhoCompleto;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao gerar PDF de consentimento");
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

    private void CriarCabecalho(IContainer container, ConfiguracaoClinica? config, string? logoPath)
    {
        container.Column(mainColumn =>
        {
            // ✅ LOGO CENTRADO - AUMENTADO PARA 150px (solicitado pelo utilizador)
            if (!string.IsNullOrEmpty(logoPath) && File.Exists(logoPath))
            {
                mainColumn.Item().AlignCenter().MaxHeight(150).Image(logoPath);
            }

            // ✅ CONTACTOS CENTRADOS POR BAIXO DO LOGO (conforme solicitado)
            mainColumn.Item().AlignCenter().PaddingTop(10).Text(text =>
            {
                text.Span("☎ 964 860 387  |  ")
                    .FontSize(10)
                    .FontColor(Colors.Grey.Darken2);
                text.Span("✉ nunocorreiaterapiasnaturais@gmail.com")
                    .FontSize(10)
                    .FontColor(Colors.Grey.Darken2);
            });

            // Morada centrada (se disponível)
            if (!string.IsNullOrWhiteSpace(config?.Morada))
            {
                mainColumn.Item().AlignCenter().PaddingTop(3).Text(config.Morada)
                    .FontSize(9)
                    .FontColor(Colors.Grey.Medium);
            }

            // Data centrada
            mainColumn.Item().AlignCenter().PaddingTop(8).Text($"Data: {DateTime.Now:dd/MM/yyyy} | Hora: {DateTime.Now:HH:mm}")
                .FontSize(9)
                .FontColor(Colors.Grey.Medium);

            // Linha separadora
            mainColumn.Item().PaddingTop(10).BorderBottom(2).BorderColor(Colors.Green.Medium);
        });
    }

    private void CriarConteudo(IContainer container, DadosConsentimento dados)
    {
        container.Column(column =>
        {
            column.Spacing(15);

            // === TÍTULO DO DOCUMENTO ===
            column.Item().PaddingTop(20).AlignCenter().Text("CONSENTIMENTO INFORMADO")
                .FontSize(18)
                .Bold()
                .FontColor(Colors.Grey.Darken3);

            column.Item().AlignCenter().Text(dados.TipoTratamento.ToUpper())
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
                        text.Span(dados.DataConsentimento.ToString("dd/MM/yyyy"));
                    });
                });
            });

            // === DESCRIÇÃO DO TRATAMENTO ===
            column.Item().PaddingTop(10).Text("DESCRIÇÃO DO TRATAMENTO").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
            column.Item().PaddingTop(5).Text(dados.DescricaoTratamento)
                .FontSize(10)
                .LineHeight(1.5f);

            // === INFORMAÇÕES ADICIONAIS ===
            if (!string.IsNullOrEmpty(dados.InformacoesAdicionais))
            {
                column.Item().PaddingTop(10).Text("INFORMAÇÕES ADICIONAIS").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.InformacoesAdicionais)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === DURAÇÃO E CUSTOS ===
            if (dados.NumeroSessoes.HasValue || dados.CustoPorSessao.HasValue)
            {
                column.Item().PaddingTop(15).Padding(12).Row(row =>
                {
                    if (dados.NumeroSessoes.HasValue)
                    {
                        row.RelativeItem().Column(c =>
                        {
                            c.Item().Text($"Nº de Sessões: {dados.NumeroSessoes.Value}").FontSize(10);
                        });
                    }

                    if (dados.CustoPorSessao.HasValue)
                    {
                        row.RelativeItem().Column(c =>
                        {
                            c.Item().Text($"Custo/Sessão: {dados.CustoPorSessao.Value:C}").FontSize(10);
                        });
                    }
                });
            }

            // === TERMOS DO CONSENTIMENTO ===
            column.Item().PaddingTop(15).Text("DECLARAÇÃO DE CONSENTIMENTO").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
            column.Item().PaddingTop(5).Column(col =>
            {
                col.Item().Text("✓ Fui informado(a) sobre os benefícios, riscos e alternativas ao tratamento proposto.")
                    .FontSize(10)
                    .LineHeight(1.4f);

                col.Item().PaddingTop(5).Text("✓ Tive a oportunidade de esclarecer todas as minhas dúvidas.")
                    .FontSize(10)
                    .LineHeight(1.4f);

                col.Item().PaddingTop(5).Text("✓ Aceito os riscos e benefícios descritos neste documento.")
                    .FontSize(10)
                    .LineHeight(1.4f);

                col.Item().PaddingTop(5).Text("✓ Consinto o tratamento proposto de forma livre e esclarecida.")
                    .FontSize(10)
                    .LineHeight(1.4f);
            });

            // === ASSINATURA ===
            column.Item().PaddingTop(30).Row(row =>
            {
                row.RelativeItem().Column(col =>
                {
                    // 🖼️ RENDERIZAR ASSINATURA SE EXISTIR
                    if (!string.IsNullOrEmpty(dados.AssinaturaDigitalBase64))
                    {
                        try
                        {
                            byte[] imageBytes = Convert.FromBase64String(dados.AssinaturaDigitalBase64);
                            col.Item()
                                .Border(1)
                                .BorderColor(Colors.Grey.Lighten2)
                                .Padding(5)
                                .Height(80)
                                .AlignCenter()
                                .AlignMiddle()
                                .Image(imageBytes)
                                .FitArea();
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
                        // Fallback: linha horizontal se não houver assinatura
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
                                .AlignCenter()
                                .AlignMiddle()
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
                        // Fallback: linha horizontal
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

            // === NOTA LEGAL ===
            column.Item().PaddingTop(20).Background(Colors.Yellow.Lighten3).Padding(10).Text(
                "⚠️ Este documento tem validade legal e deve ser guardado em local seguro. " +
                "Em caso de dúvidas ou para revogar este consentimento, contacte a clínica.")
                .FontSize(8)
                .Italic()
                .FontColor(Colors.Orange.Darken3);
        });
    }

    #endregion
}

/// <summary>
/// Dados necessários para gerar PDF de consentimento
/// </summary>
public class DadosConsentimento
{
    public string NomePaciente { get; set; } = string.Empty;
    public string TipoTratamento { get; set; } = string.Empty;
    public string DescricaoTratamento { get; set; } = string.Empty;
    public string InformacoesAdicionais { get; set; } = string.Empty;
    public DateTime DataConsentimento { get; set; } = DateTime.Now;
    public int? NumeroSessoes { get; set; }
    public decimal? CustoPorSessao { get; set; }

    /// <summary>
    /// Assinatura do paciente capturada como imagem PNG em Base64
    /// </summary>
    public string? AssinaturaDigitalBase64 { get; set; }

    /// <summary>
    /// Caminho para a assinatura do terapeuta (ficheiro estático)
    /// </summary>
    public string AssinaturaTerapeutaPath { get; set; } = "Assets/Images/assinatura.png";

    /// <summary>
    /// Nome do terapeuta responsável
    /// </summary>
    public string NomeTerapeuta { get; set; } = "Nuno Correia";
}
