using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Domain.Entities;
using BioDesk.Services.Documentos;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Documentos
{
    /// <summary>
    /// ViewModel para gestão de documentos externos de um paciente específico.
    /// Usada na FichaPacienteView → Tab "Documentos Externos"
    /// </summary>
    public partial class DocumentosExternosViewModel : ObservableObject
    {
        private readonly IDocumentoExternoPacienteService _documentoService;
        private readonly ILogger<DocumentosExternosViewModel> _logger;

        [ObservableProperty]
        private int _pacienteId;

        [ObservableProperty]
        private ObservableCollection<DocumentoExternoPaciente> _documentos = new();

        [ObservableProperty]
        private DocumentoExternoPaciente? _documentoSelecionado;

        [ObservableProperty]
        private string? _filtroNome; // Pesquisa por nome de arquivo

        [ObservableProperty]
        private string? _filtroCategoria; // null = todos

        [ObservableProperty]
        private bool _isLoading;

        [ObservableProperty]
        private string? _errorMessage;

        /// <summary>
        /// Coleção filtrada de documentos baseada nos filtros aplicados
        /// </summary>
        public ObservableCollection<DocumentoExternoPaciente> DocumentosFiltrados
        {
            get
            {
                var query = Documentos.AsEnumerable();

                // Filtro por nome
                if (!string.IsNullOrWhiteSpace(FiltroNome))
                {
                    query = query.Where(d => d.NomeArquivo.Contains(FiltroNome, StringComparison.OrdinalIgnoreCase));
                }

                // Filtro por categoria
                if (!string.IsNullOrWhiteSpace(FiltroCategoria) && FiltroCategoria != "Todas")
                {
                    query = query.Where(d => d.Categoria == FiltroCategoria);
                }

                return new ObservableCollection<DocumentoExternoPaciente>(query);
            }
        }

        public DocumentosExternosViewModel(
            IDocumentoExternoPacienteService documentoService,
            ILogger<DocumentosExternosViewModel> logger)
        {
            _documentoService = documentoService ?? throw new ArgumentNullException(nameof(documentoService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Inicializa o ViewModel para um paciente específico
        /// </summary>
        public async Task InicializarParaPacienteAsync(int pacienteId)
        {
            PacienteId = pacienteId;
            await CarregarDocumentosAsync();
        }

        /// <summary>
        /// Carrega todos os documentos do paciente atual
        /// </summary>
        private async Task CarregarDocumentosAsync()
        {
            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;
                var documentos = await _documentoService.GetDocumentosPorPacienteAsync(PacienteId);

                if (!string.IsNullOrWhiteSpace(FiltroCategoria))
                {
                    documentos = documentos.Where(d => d.Categoria == FiltroCategoria).ToList();
                }

                Documentos = new ObservableCollection<DocumentoExternoPaciente>(documentos);
                _logger.LogInformation("Documentos carregados para PacienteId {PacienteId}: {Count}", PacienteId, Documentos.Count);
                OnPropertyChanged(nameof(DocumentosFiltrados)); // Notificar mudança na coleção filtrada
            });
        }

        /// <summary>
        /// Filtro por nome de arquivo
        /// </summary>
        partial void OnFiltroNomeChanged(string? value)
        {
            OnPropertyChanged(nameof(DocumentosFiltrados));
        }

        /// <summary>
        /// Filtro por categoria
        /// </summary>
        partial void OnFiltroCategoriaChanged(string? value)
        {
            OnPropertyChanged(nameof(DocumentosFiltrados));
        }

        /// <summary>
        /// Adiciona um novo documento externo ao paciente
        /// </summary>
        [RelayCommand]
        private async Task AdicionarDocumentoAsync(string? caminhoOrigem)
        {
            if (string.IsNullOrWhiteSpace(caminhoOrigem))
            {
                ErrorMessage = "Caminho do arquivo é obrigatório";
                return;
            }

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;

                // Dialogo para solicitar categoria e data do documento
                // (será implementado na View com OpenFileDialog + dialog de metadados)
                var documento = await _documentoService.AdicionarDocumentoAsync(
                    pacienteId: PacienteId,
                    caminhoOrigem: caminhoOrigem,
                    categoria: "Geral",
                    descricao: null,
                    dataDocumento: DateTime.Now
                );

                Documentos.Add(documento);
                _logger.LogInformation("Documento adicionado ao paciente {PacienteId}: {Nome}", PacienteId, documento.NomeArquivo);
            });
        }

        /// <summary>
        /// Atualiza metadados de um documento existente
        /// </summary>
        [RelayCommand]
        private async Task AtualizarDocumentoAsync(DocumentoExternoPaciente? documento)
        {
            if (documento == null)
                return;

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;
                await _documentoService.AtualizarDocumentoAsync(documento);
                _logger.LogInformation("Documento atualizado: {Nome}", documento.NomeArquivo);
            });
        }

        /// <summary>
        /// Remove um documento (soft delete + delete físico)
        /// </summary>
        [RelayCommand]
        private async Task RemoverDocumentoAsync(DocumentoExternoPaciente? documento)
        {
            if (documento == null)
                return;

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                IsLoading = true;
                await _documentoService.RemoverDocumentoAsync(documento.Id);
                Documentos.Remove(documento);
                _logger.LogInformation("Documento removido: {Nome}", documento.NomeArquivo);
            });
        }

        /// <summary>
        /// Abre o documento no visualizador padrão do sistema
        /// </summary>
        [RelayCommand]
        private void VisualizarDocumento(DocumentoExternoPaciente? documento)
        {
            if (documento == null)
                return;

            try
            {
                var caminhoCompleto = _documentoService.GetCaminhoCompletoDocumento(documento);
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
                    _logger.LogWarning("Arquivo de documento não encontrado: {Caminho}", caminhoCompleto);
                }
            }
            catch (Exception ex)
            {
                ErrorMessage = $"Erro ao abrir arquivo: {ex.Message}";
                _logger.LogError(ex, "Erro ao visualizar documento: {Nome}", documento.NomeArquivo);
            }
        }

        /// <summary>
        /// Formata o tamanho do arquivo para exibição (KB/MB)
        /// </summary>
        public static string FormatarTamanho(long bytes)
        {
            if (bytes < 1024)
                return $"{bytes} B";
            if (bytes < 1024 * 1024)
                return $"{bytes / 1024} KB";
            return $"{bytes / (1024 * 1024)} MB";
        }

        /// <summary>
        /// Padrão de error handling obrigatório
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
                _logger.LogError(ex, "Erro em DocumentosExternosViewModel");
            }
            finally
            {
                IsLoading = false;
            }
        }
    }
}
