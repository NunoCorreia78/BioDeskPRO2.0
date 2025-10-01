using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Pdf;

/// <summary>
/// Serviço para geração de PDFs de Consentimentos Informados
/// Usa QuestPDF para criar documentos profissionais com assinatura digital
/// </summary>
public class ConsentimentoPdfService
{
    private readonly ILogger<ConsentimentoPdfService> _logger;

    public ConsentimentoPdfService(ILogger<ConsentimentoPdfService> logger)
    {
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
            // Caminho para salvar o PDF
            var pastaDocumentos = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var pastaBioDesk = Path.Combine(pastaDocumentos, "BioDeskPro2", "Consentimentos");
            Directory.CreateDirectory(pastaBioDesk);

            var nomeArquivo = $"Consentimento_{dados.TipoTratamento.Replace(" ", "_")}_{dados.NomePaciente.Replace(" ", "_")}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var caminhoCompleto = Path.Combine(pastaBioDesk, nomeArquivo);

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
                        text.Span(" | BioDeskPro 2.0").FontSize(8).FontColor(Colors.Grey.Medium);
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

    private void CriarCabecalho(IContainer container)
    {
        container.Row(row =>
        {
            // Logo/Título à esquerda
            row.RelativeItem().Column(column =>
            {
                column.Item().Text("🌿 BioDeskPro 2.0")
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
        container.PaddingTop(10).BorderBottom(2).BorderColor(Colors.Green.Medium);
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
                column.Item().PaddingTop(15).Background(Colors.Green.Lighten3).Padding(12).Row(row =>
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
                    col.Item().LineHorizontal(1).LineColor(Colors.Black);
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
                    col.Item().LineHorizontal(1).LineColor(Colors.Black);
                    col.Item().PaddingTop(5).AlignCenter().Text("Profissional Responsável")
                        .FontSize(9)
                        .Italic();
                    col.Item().AlignCenter().Text("BioDeskPro 2.0")
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
}
