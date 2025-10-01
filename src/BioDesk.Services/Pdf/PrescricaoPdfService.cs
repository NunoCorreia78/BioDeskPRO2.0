using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Pdf;

/// <summary>
/// Serviço para geração de PDFs de Prescrições Médicas
/// Template profissional com medicamentos, dosagens e instruções
/// </summary>
public class PrescricaoPdfService
{
    private readonly ILogger<PrescricaoPdfService> _logger;

    public PrescricaoPdfService(ILogger<PrescricaoPdfService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Configurar licença QuestPDF (Community License)
        QuestPDF.Settings.License = LicenseType.Community;
    }

    /// <summary>
    /// Gera PDF de prescrição médica em pasta temporária
    /// </summary>
    public string GerarPdfPrescricao(DadosPrescricao dados)
    {
        _logger.LogInformation("📋 Gerando PDF de prescrição para: {Nome}", dados.NomePaciente);

        try
        {
            // ⭐ GERAR EM PASTA TEMPORÁRIA (será copiado depois)
            var pastaTemp = Path.GetTempPath();
            var nomeArquivo = $"Prescricao_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var caminhoCompleto = Path.Combine(pastaTemp, nomeArquivo);

            _logger.LogInformation("🔧 Caminho temporário: {Caminho}", caminhoCompleto);

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
                        text.Span(" | Nuno Correia - Terapias Naturais - Prescrição").FontSize(8).FontColor(Colors.Grey.Medium);
                    });
                });
            })
            .GeneratePdf(caminhoCompleto);

            _logger.LogInformation("✅ PDF de prescrição gerado: {Caminho}", caminhoCompleto);
            return caminhoCompleto;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao gerar PDF de prescrição");
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
        container.Column(col =>
        {
            // Cabeçalho com logo e data
            col.Item().Row(row =>
            {
                // Logo/Título à esquerda
                row.RelativeItem().Column(column =>
                {
                    column.Item().Text("🌿 Nuno Correia - Terapias Naturais")
                        .FontSize(20)
                        .Bold()
                        .FontColor(Colors.Grey.Darken3);

                    column.Item().Text("Prescrição de Medicina Complementar")
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

            // Linha separadora DENTRO do Column
            col.Item().PaddingTop(10).BorderBottom(2).BorderColor(Colors.Teal.Medium);
        });
    }

    private void CriarConteudo(IContainer container, DadosPrescricao dados)
    {
        container.Column(column =>
        {
            column.Spacing(15);

            // === TÍTULO DO DOCUMENTO ===
            column.Item().PaddingTop(20).AlignCenter().Text("PRESCRIÇÃO MÉDICA")
                .FontSize(18)
                .Bold()
                .FontColor(Colors.Grey.Darken3);

            column.Item().PaddingBottom(10).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);

            // === DADOS DO PACIENTE ===
            column.Item().Background(Colors.Grey.Lighten3).Padding(15).Column(col =>
            {
                col.Item().Text("👤 DADOS DO PACIENTE").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
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
                        text.Span(dados.DataPrescricao.ToString("dd/MM/yyyy"));
                    });
                });
            });

            // === DIAGNÓSTICO/OBSERVAÇÕES ===
            if (!string.IsNullOrEmpty(dados.Diagnostico))
            {
                column.Item().PaddingTop(10).Text("📋 DIAGNÓSTICO/OBSERVAÇÕES").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.Diagnostico)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === TABELA DE MEDICAMENTOS/SUPLEMENTOS ===
            if (dados.Itens.Count > 0)
            {
                column.Item().PaddingTop(15).Text("💊 PRESCRIÇÃO").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);

                column.Item().PaddingTop(10).Table(table =>
                {
                    // Definir colunas
                    table.ColumnsDefinition(columns =>
                    {
                        columns.ConstantColumn(40);  // Nº
                        columns.RelativeColumn(3);   // Medicamento/Suplemento
                        columns.RelativeColumn(2);   // Dosagem
                        columns.RelativeColumn(2);   // Frequência
                        columns.RelativeColumn(3);   // Observações
                    });

                    // Cabeçalho da tabela
                    table.Header(header =>
                    {
                        header.Cell().Background(Colors.Teal.Medium).Padding(5).Text("Nº").FontSize(10).Bold().FontColor(Colors.White);
                        header.Cell().Background(Colors.Teal.Medium).Padding(5).Text("Medicamento/Suplemento").FontSize(10).Bold().FontColor(Colors.White);
                        header.Cell().Background(Colors.Teal.Medium).Padding(5).Text("Dosagem").FontSize(10).Bold().FontColor(Colors.White);
                        header.Cell().Background(Colors.Teal.Medium).Padding(5).Text("Frequência").FontSize(10).Bold().FontColor(Colors.White);
                        header.Cell().Background(Colors.Teal.Medium).Padding(5).Text("Observações").FontSize(10).Bold().FontColor(Colors.White);
                    });

                    // Linhas de dados
                    int contador = 1;
                    foreach (var item in dados.Itens)
                    {
                        var backgroundColor = contador % 2 == 0 ? Colors.Grey.Lighten4 : Colors.White;

                        table.Cell().Background(backgroundColor).BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(contador.ToString()).FontSize(10);
                        table.Cell().Background(backgroundColor).BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(item.Nome).FontSize(10);
                        table.Cell().Background(backgroundColor).BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(item.Dosagem).FontSize(10);
                        table.Cell().Background(backgroundColor).BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(item.Frequencia).FontSize(10);
                        table.Cell().Background(backgroundColor).BorderBottom(1).BorderColor(Colors.Grey.Lighten2).Padding(5).Text(item.Observacoes).FontSize(10);

                        contador++;
                    }
                });
            }

            // === INSTRUÇÕES GERAIS ===
            if (!string.IsNullOrEmpty(dados.InstrucoesGerais))
            {
                column.Item().PaddingTop(15).Text("📝 INSTRUÇÕES GERAIS").FontSize(12).Bold().FontColor(Colors.Grey.Darken3);
                column.Item().PaddingTop(5).Text(dados.InstrucoesGerais)
                    .FontSize(10)
                    .LineHeight(1.5f);
            }

            // === ASSINATURA DO TERAPEUTA ===
            column.Item().PaddingTop(30).Row(row =>
            {
                row.RelativeItem().Column(col =>
                {
                    // 👨‍⚕️ RENDERIZAR ASSINATURA DO TERAPEUTA
                    string assinaturaTerapeutaPath = "Assets/Images/assinatura.png";
                    if (System.IO.File.Exists(assinaturaTerapeutaPath))
                    {
                        try
                        {
                            byte[] assinaturaTerapeuta = System.IO.File.ReadAllBytes(assinaturaTerapeutaPath);
                            col.Item()
                                .Border(1)
                                .BorderColor(Colors.Grey.Lighten2)
                                .Padding(5)
                                .Height(80)
                                .Image(assinaturaTerapeuta)
                                .FitArea();
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "❌ Erro ao carregar assinatura do terapeuta: {Path}", assinaturaTerapeutaPath);
                            col.Item().LineHorizontal(1).LineColor(Colors.Black);
                        }
                    }
                    else
                    {
                        // Fallback: linha horizontal
                        _logger.LogWarning("⚠️ Assinatura do terapeuta não encontrada: {Path}", assinaturaTerapeutaPath);
                        col.Item().LineHorizontal(1).LineColor(Colors.Black);
                    }
                    
                    col.Item().PaddingTop(5).AlignCenter().Text("Profissional Responsável")
                        .FontSize(9)
                        .Italic();
                    col.Item().AlignCenter().Text("Nuno Correia - Terapias Naturais")
                        .FontSize(8)
                        .FontColor(Colors.Grey.Darken1);
                });
            });

            // === NOTA LEGAL ===
            column.Item().PaddingTop(20).Background(Colors.Yellow.Lighten3).Padding(10).Text(
                "⚠️ Esta prescrição tem validade de 30 dias. Mantenha este documento em local seguro. " +
                "Em caso de dúvidas ou reações adversas, contacte imediatamente o profissional responsável.")
                .FontSize(8)
                .Italic()
                .FontColor(Colors.Orange.Darken3);
        });
    }

    #endregion
}

/// <summary>
/// Dados necessários para gerar PDF de prescrição
/// </summary>
public class DadosPrescricao
{
    public string NomePaciente { get; set; } = string.Empty;
    public DateTime DataPrescricao { get; set; } = DateTime.Now;
    public string Diagnostico { get; set; } = string.Empty;
    public List<ItemPrescricao> Itens { get; set; } = new();
    public string InstrucoesGerais { get; set; } = string.Empty;
    public string DuracaoTratamento { get; set; } = string.Empty;
}

/// <summary>
/// Item individual da prescrição (medicamento ou suplemento)
/// </summary>
public class ItemPrescricao
{
    public string Nome { get; set; } = string.Empty;
    public string Dosagem { get; set; } = string.Empty;
    public string Frequencia { get; set; } = string.Empty;
    public string Observacoes { get; set; } = string.Empty;
}
