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
/// Serviço para geração de PDFs de Declarações de Saúde
/// Layout igual aos Consentimentos, com assinaturas do paciente e terapeuta
/// </summary>
public class DeclaracaoSaudePdfService
{
    private readonly ILogger<DeclaracaoSaudePdfService> _logger;
    private readonly IUnitOfWork _unitOfWork;

    public DeclaracaoSaudePdfService(
        IUnitOfWork unitOfWork,
        ILogger<DeclaracaoSaudePdfService> logger)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
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
            // 🏥 CARREGAR CONFIGURAÇÃO DA CLÍNICA (logo + dados)
            ConfiguracaoClinica? config = null;
            string? logoPath = null;

            try
            {
                config = _unitOfWork.ConfiguracaoClinica.GetByIdAsync(1).Result;

                // ✅ LOGO FIXO: Usar sempre o logo da pasta Assets
                var assetsLogoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "Images", "Logo.png");

                if (File.Exists(assetsLogoPath))
                {
                    logoPath = assetsLogoPath;
                    _logger.LogInformation("✅ Logo carregado de Assets: {LogoPath}", logoPath);
                }
                else
                {
                    // Fallback: tentar logo da configuração
                    if (config?.LogoPath != null)
                    {
                        logoPath = Path.Combine(PathService.AppDataPath, config.LogoPath);
                        if (!File.Exists(logoPath))
                        {
                            _logger.LogWarning("⚠️ Logo não encontrado em Assets nem configuração: {LogoPath}", logoPath);
                            logoPath = null;
                        }
                        else
                        {
                            _logger.LogInformation("✅ Logo da clínica carregado (fallback): {LogoPath}", logoPath);
                        }
                    }
                }
            }
            catch (Exception exConfig)
            {
                _logger.LogWarning(exConfig, "⚠️ Erro ao carregar configuração - PDF continuará sem logo");
            }

            // ✅ USAR PathService PARA GARANTIR COMPATIBILIDADE DEBUG/RELEASE
            var pastaPaciente = PathService.GetPacienteDocumentPath(dados.NomePaciente, "");
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

    private void CriarConteudo(IContainer container, DadosDeclaracaoSaude dados)
    {
        container.Column(column =>
        {
            column.Spacing(15);

            // === TÍTULO DO DOCUMENTO ===
            column.Item().AlignCenter().Text("DECLARAÇÃO DE SAÚDE")
                .FontSize(18)
                .Bold()
                .FontColor(Colors.Grey.Darken3);

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

            // ✅ HELPER: Mostrar "Não respondido" se vazio
            Func<string?, string> FormatarCampo = (valor) =>
                string.IsNullOrWhiteSpace(valor) ? "Não respondido" : valor;

            // === MOTIVOS DA CONSULTA ===
            column.Item().PaddingTop(12).Column(col =>
            {
                col.Item().Text("1. MOTIVOS DA CONSULTA").FontSize(11).Bold().FontColor(Colors.Grey.Darken3);
                col.Item().PaddingTop(6).Text(FormatarCampo(dados.MotivoConsulta))
                    .FontSize(9).LineHeight(1.4f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.MotivoConsulta) ? Colors.Grey.Medium : Colors.Black);
            });

            // === HISTÓRIA CLÍNICA PASSADA ===
            column.Item().PaddingTop(12).Column(col =>
            {
                col.Item().Text("2. HISTÓRIA CLÍNICA PASSADA").FontSize(11).Bold().FontColor(Colors.Grey.Darken3);
                col.Item().PaddingTop(6).Text(FormatarCampo(dados.HistoriaClinica))
                    .FontSize(9).LineHeight(1.4f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.HistoriaClinica) ? Colors.Grey.Medium : Colors.Black);
            });

            // === MEDICAÇÃO ATUAL ===
            column.Item().PaddingTop(12).Column(col =>
            {
                col.Item().Text("3. MEDICAÇÃO/SUPLEMENTAÇÃO ATUAL").FontSize(11).Bold().FontColor(Colors.Grey.Darken3);
                col.Item().PaddingTop(6).Text(FormatarCampo(dados.MedicacaoAtual))
                    .FontSize(9).LineHeight(1.4f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.MedicacaoAtual) ? Colors.Grey.Medium : Colors.Black);
            });

            // === ALERGIAS E REAÇÕES ADVERSAS ===
            column.Item().PaddingTop(12).Background(Colors.Yellow.Lighten4).Padding(8).Column(col =>
            {
                col.Item().Text("⚠️ 4. ALERGIAS E REAÇÕES ADVERSAS").FontSize(11).Bold().FontColor(Colors.Grey.Darken3);
                col.Item().PaddingTop(6).Text(FormatarCampo(dados.Alergias))
                    .FontSize(9).LineHeight(1.4f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.Alergias) ? Colors.Grey.Medium : Colors.Black);
            });

            // === ESTILO DE VIDA ===
            column.Item().PaddingTop(12).Column(col =>
            {
                col.Item().Text("5. ESTILO DE VIDA").FontSize(11).Bold().FontColor(Colors.Grey.Darken3);
                col.Item().PaddingTop(6).Text(FormatarCampo(dados.EstiloVida))
                    .FontSize(9).LineHeight(1.4f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.EstiloVida) ? Colors.Grey.Medium : Colors.Black);
            });

            // === HISTÓRIA FAMILIAR ===
            column.Item().PaddingTop(12).Column(col =>
            {
                col.Item().Text("6. HISTÓRIA FAMILIAR").FontSize(11).Bold().FontColor(Colors.Grey.Darken3);
                col.Item().PaddingTop(6).Text(FormatarCampo(dados.HistoriaFamiliar))
                    .FontSize(9).LineHeight(1.4f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.HistoriaFamiliar) ? Colors.Grey.Medium : Colors.Black);
            });

            // === OBSERVAÇÕES CLÍNICAS ===
            column.Item().PaddingTop(12).Background(Colors.Blue.Lighten4).Padding(10).Column(col =>
            {
                col.Item().Text("💡 OBSERVAÇÕES CLÍNICAS DO TERAPEUTA")
                    .FontSize(10).Bold().FontColor(Colors.Blue.Darken2);
                col.Item().PaddingTop(5).Text(FormatarCampo(dados.ObservacoesClinicas))
                    .FontSize(9).LineHeight(1.4f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.ObservacoesClinicas) ? Colors.Grey.Medium : Colors.Black);
            });

            // === DADOS ADICIONAIS ===
            column.Item().PaddingTop(20).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);
            column.Item().PaddingTop(12).Text("INFORMAÇÕES COMPLEMENTARES")
                .FontSize(12).Bold().FontColor(Colors.Grey.Darken3);

            // Cirurgias
            column.Item().PaddingTop(8).Column(col =>
            {
                col.Item().Text("Cirurgias Anteriores").FontSize(10).SemiBold().FontColor(Colors.Grey.Darken2);
                col.Item().PaddingTop(3).Text(FormatarCampo(dados.DadosCirurgias))
                    .FontSize(9).LineHeight(1.3f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.DadosCirurgias) ? Colors.Grey.Medium : Colors.Black);
            });

            // Hospitalizações
            column.Item().PaddingTop(8).Column(col =>
            {
                col.Item().Text("Hospitalizações").FontSize(10).SemiBold().FontColor(Colors.Grey.Darken2);
                col.Item().PaddingTop(3).Text(FormatarCampo(dados.DadosHospitalizacoes))
                    .FontSize(9).LineHeight(1.3f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.DadosHospitalizacoes) ? Colors.Grey.Medium : Colors.Black);
            });

            // Medicamentos Atuais
            column.Item().PaddingTop(8).Column(col =>
            {
                col.Item().Text("Medicamentos Atuais (Detalhado)").FontSize(10).SemiBold().FontColor(Colors.Grey.Darken2);
                col.Item().PaddingTop(3).Text(FormatarCampo(dados.DadosMedicamentosAtuais))
                    .FontSize(9).LineHeight(1.3f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.DadosMedicamentosAtuais) ? Colors.Grey.Medium : Colors.Black);
            });

            // Alergias Detalhadas
            column.Item().PaddingTop(8).Column(col =>
            {
                col.Item().Text("Alergias Detalhadas").FontSize(10).SemiBold().FontColor(Colors.Grey.Darken2);
                col.Item().PaddingTop(3).Text(FormatarCampo(dados.DadosAlergiasDetalhadas))
                    .FontSize(9).LineHeight(1.3f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.DadosAlergiasDetalhadas) ? Colors.Grey.Medium : Colors.Black);
            });

            // Intolerâncias
            column.Item().PaddingTop(8).Column(col =>
            {
                col.Item().Text("Intolerâncias Alimentares").FontSize(10).SemiBold().FontColor(Colors.Grey.Darken2);
                col.Item().PaddingTop(3).Text(FormatarCampo(dados.DadosIntoleranciaAlimentar))
                    .FontSize(9).LineHeight(1.3f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.DadosIntoleranciaAlimentar) ? Colors.Grey.Medium : Colors.Black);
            });

            // Doenças Crónicas
            // Doenças Crónicas
            column.Item().PaddingTop(8).Column(col =>
            {
                col.Item().Text("Doenças Crónicas (Detalhado)").FontSize(10).SemiBold().FontColor(Colors.Grey.Darken2);
                col.Item().PaddingTop(3).Text(FormatarCampo(dados.DadosDoencasCronicas))
                    .FontSize(9).LineHeight(1.3f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.DadosDoencasCronicas) ? Colors.Grey.Medium : Colors.Black);
            });

            // Observações Adicionais
            column.Item().PaddingTop(8).Column(col =>
            {
                col.Item().Text("Observações Adicionais").FontSize(10).SemiBold().FontColor(Colors.Grey.Darken2);
                col.Item().PaddingTop(3).Text(FormatarCampo(dados.ObservacoesAdicionais))
                    .FontSize(9).LineHeight(1.3f)
                    .FontColor(string.IsNullOrWhiteSpace(dados.ObservacoesAdicionais) ? Colors.Grey.Medium : Colors.Black);
            });

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
                                .Image(imageBytes)  // ✅ ATUALIZADO: Nova API QuestPDF 2023.5+ (sem ImageScaling obsoleto)
                                .FitWidth();  // ✅ Método moderno para ajustar largura
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

    // === DADOS ADICIONAIS ESPERADOS NA UI ===
    public string? DadosCirurgias { get; set; }
    public string? DadosHospitalizacoes { get; set; }
    public string? DadosMedicamentosAtuais { get; set; }
    public string? DadosAlergiasDetalhadas { get; set; }
    public string? DadosIntoleranciaAlimentar { get; set; }
    public string? DadosDoencasCronicas { get; set; }
    public string? ObservacoesAdicionais { get; set; }

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
