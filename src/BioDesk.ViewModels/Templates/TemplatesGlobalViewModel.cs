using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Domain.Entities;
using BioDesk.Services;
using BioDesk.Services.Templates;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Templates
{
    /// <summary>
    /// ViewModel para gestão de templates globais e documentos externos importados.
    /// Usada na View de Configurações → Tab "Templates & Documentos"
    /// </summary>
    public partial class TemplatesGlobalViewModel : ObservableObject
    {
        private readonly ITemplateGlobalService _templateService;
        private readonly ILogger<TemplatesGlobalViewModel> _logger;

        [ObservableProperty]
        private ObservableCollection<TemplateGlobal> _templates = new();

        [ObservableProperty]
        private TemplateGlobal? _templateSelecionado;

        [ObservableProperty]
        private string _filtroNome = string.Empty;

        [ObservableProperty]
        private string? _filtroTipo; // null = todos, "TemplateApp", "DocumentoExterno"

        [ObservableProperty]
        private string? _filtroCategoria;

        [ObservableProperty]
        private bool _isLoading;

        [ObservableProperty]
        private string? _errorMessage;

        public TemplatesGlobalViewModel(
            ITemplateGlobalService templateService,
            ILogger<TemplatesGlobalViewModel> logger)
        {
            _templateService = templateService ?? throw new ArgumentNullException(nameof(templateService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Inicializa o ViewModel carregando todos os templates disponíveis
        /// </summary>
        public async Task InicializarAsync()
        {
            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;
                var templates = await _templateService.GetAllTemplatesAsync();
                Templates = new ObservableCollection<TemplateGlobal>(templates);
                _logger.LogInformation("Templates carregados: {Count}", Templates.Count);
            });
        }

        /// <summary>
        /// Filtra templates por nome, tipo ou categoria
        /// </summary>
        partial void OnFiltroNomeChanged(string value)
        {
            AplicarFiltros();
        }

        partial void OnFiltroTipoChanged(string? value)
        {
            AplicarFiltros();
        }

        partial void OnFiltroCategoriaChanged(string? value)
        {
            AplicarFiltros();
        }

        private async void AplicarFiltros()
        {
            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;
                var todosTemplates = await _templateService.GetAllTemplatesAsync();

                var filtrados = todosTemplates.AsEnumerable();

                if (!string.IsNullOrWhiteSpace(FiltroNome))
                {
                    filtrados = filtrados.Where(t => t.Nome.Contains(FiltroNome, StringComparison.OrdinalIgnoreCase));
                }

                if (!string.IsNullOrWhiteSpace(FiltroTipo))
                {
                    filtrados = filtrados.Where(t => t.Tipo == FiltroTipo);
                }

                if (!string.IsNullOrWhiteSpace(FiltroCategoria))
                {
                    filtrados = filtrados.Where(t => t.Categoria == FiltroCategoria);
                }

                Templates = new ObservableCollection<TemplateGlobal>(filtrados);
            });
        }

        /// <summary>
        /// Importa um documento externo como template global
        /// </summary>
        [RelayCommand]
        private async Task ImportarDocumentoExternoAsync(string? caminhoArquivo)
        {
            if (string.IsNullOrWhiteSpace(caminhoArquivo))
            {
                ErrorMessage = "Caminho do arquivo é obrigatório";
                return;
            }

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;

                // Dialogo para solicitar nome, categoria e disponibilidade para email
                // (será implementado na View)
                var template = await _templateService.ImportarDocumentoExternoAsync(
                    caminhoArquivo,
                    nome: System.IO.Path.GetFileNameWithoutExtension(caminhoArquivo),
                    categoria: "Geral",
                    disponivelEmail: true
                );

                Templates.Add(template);
                _logger.LogInformation("Documento externo importado: {Nome}", template.Nome);
            });
        }

        /// <summary>
        /// Alterna a disponibilidade de um template para anexação em emails
        /// </summary>
        [RelayCommand]
        private async Task AlterarDisponibilidadeEmailAsync(TemplateGlobal? template)
        {
            if (template == null)
                return;

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                template.DisponivelEmail = !template.DisponivelEmail;
                await _templateService.AtualizarTemplateAsync(template);
                _logger.LogInformation("Disponibilidade email alterada: {Nome} = {Disponivel}",
                    template.Nome, template.DisponivelEmail);
            });
        }

        /// <summary>
        /// Remove um template (soft delete)
        /// </summary>
        [RelayCommand]
        private async Task RemoverTemplateAsync(TemplateGlobal? template)
        {
            if (template == null)
                return;

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;
                await _templateService.RemoverTemplateAsync(template.Id);
                Templates.Remove(template);
                _logger.LogInformation("Template removido: {Nome}", template.Nome);
            });
        }

        /// <summary>
        /// Abre o arquivo do template no visualizador padrão do sistema
        /// </summary>
        [RelayCommand]
        private void VisualizarTemplate(TemplateGlobal? template)
        {
            if (template == null)
                return;

            try
            {
                var caminhoCompleto = System.IO.Path.Combine(PathService.TemplatesPath, template.CaminhoArquivo);
                if (System.IO.File.Exists(caminhoCompleto))
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = caminhoCompleto,
                        UseShellExecute = true
                    });
                }
                else
                {
                    ErrorMessage = $"Arquivo não encontrado: {caminhoCompleto}";
                    _logger.LogWarning("Arquivo de template não encontrado: {Caminho}", caminhoCompleto);
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Erro ao abrir arquivo: {ex.Message}";
                _logger.LogError(ex, "Erro ao visualizar template: {Nome}", template.Nome);
            }
        }

        /// <summary>
        /// Padrão de error handling obrigatório (conforme copilot-instructions.md)
        /// </summary>
        private async Task ExecuteWithErrorHandlingAsync(Func<Task> action)
        {
            try
            {
                ErrorMessage = null;
                await action();
            }
            catch (Exception ex)
            {
                ErrorMessage = ex.Message;
                _logger.LogError(ex, "Erro em TemplatesGlobalViewModel");
            }
            finally
            {
                IsLoading = false;
            }
        }
    }
}
