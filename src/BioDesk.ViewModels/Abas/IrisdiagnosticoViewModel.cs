using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Models;
using BioDesk.Services;
using BioDesk.Services.Debug;
using BioDesk.Services.Iridology;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel MINIMALISTA para Irisdiagnóstico (Tab 5)
/// Responsabilidade: Gerir lista de imagens de íris do paciente atual
/// </summary>
public partial class IrisdiagnosticoViewModel : ObservableObject, IDisposable
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<IrisdiagnosticoViewModel> _logger;
    private readonly IIridologyService _iridologyService;
    private readonly IDragDebugService _dragDebugService;
    private readonly IrisOverlayService _overlayService;
    private readonly SemaphoreSlim _carregarImagensSemaphore = new(1, 1); // ✅ CORREÇÃO CONCORRÊNCIA: 1 operação por vez

    [ObservableProperty]
    private Paciente? _pacienteAtual;

    [ObservableProperty]
    private ObservableCollection<IrisImagem> _irisImagens = new();

    [ObservableProperty]
    private bool _debugArrastoAtivo = true;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoverImagemCommand))]
    private IrisImagem? _irisImagemSelecionada;

    [ObservableProperty]
    private string _olhoSelecionado = "Direito"; // Default Direito

    [ObservableProperty]
    private string? _observacoesImagem;

    // === FASE 2: ZOOM/PAN ===
    [ObservableProperty]
    private double _zoomLevel = 1.0;

    [ObservableProperty]
    private double _translateX = 0.0;

    [ObservableProperty]
    private double _translateY = 0.0;

    private const double MinZoom = 1.0;
    private const double MaxZoom = 5.0;
    private const double ZoomStep = 0.2;

    // === FASE 2: MARCAÇÕES ===
    [ObservableProperty]
    private ObservableCollection<IrisMarca> _marcasImagem = new();

    [ObservableProperty]
    private string _corMarcaSelecionada = "#C85959"; // Vermelho terroso default

    [ObservableProperty]
    private IrisMarca? _marcaSelecionada;

    // === FASE 3: CONTADORES POR COR (Paleta Terrosa) ===
    public int CountVermelho => MarcasImagem.Count(m => m.Cor == "#C85959");
    public int CountVerde => MarcasImagem.Count(m => m.Cor == "#6B8E63");
    public int CountAzul => MarcasImagem.Count(m => m.Cor == "#5B7C99");
    public int CountAmarelo => MarcasImagem.Count(m => m.Cor == "#D4A849");
    public int CountTotal => MarcasImagem.Count;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    // === FASE 4: MAPA IRIDOLÓGICO ===
    [ObservableProperty]
    private bool _mostrarMapaIridologico = false;

    [ObservableProperty]
    private IridologyZone? _zonaDetectada;

    [ObservableProperty]
    private IridologyMap? _mapaAtual;

    /// <summary>
    /// Classe auxiliar para renderizar polígonos no WPF
    /// </summary>
    public class ZonaPoligono
    {
        public string Nome { get; set; } = string.Empty;
        public string Descricao { get; set; } = string.Empty;
        public PointCollection Pontos { get; set; } = new();
        public string CorPreenchimento { get; set; } = "#6B8E63"; // Verde musgo terroso
    }

    [ObservableProperty]
    private ObservableCollection<ZonaPoligono> _poligonosZonas = new();

    // === SISTEMA NOVO: OVERLAY INFALÍVEL (3-CLICK + OPENCV) ===

    /// <summary>
    /// Indica se o sistema de alinhamento está ativo (aguardando 3 cliques)
    /// </summary>
    [ObservableProperty]
    private bool _isAlignmentActive = false;

    /// <summary>
    /// Indica se os 3 cliques foram completados (habilita Auto-Fit/Confirmar)
    /// </summary>
    [ObservableProperty]
    private bool _hasThreeClicks = false;

    /// <summary>
    /// Texto de instrução contextual para o utilizador durante alinhamento
    /// </summary>
    [ObservableProperty]
    private string _alignmentInstructionText = string.Empty;

    /// <summary>
    /// Transformação aplicada ao MapaOverlayCanvas (resultado do IrisOverlayService)
    /// </summary>
    [ObservableProperty]
    private System.Windows.Media.Transform _overlayTransform = System.Windows.Media.Transform.Identity;

    // === FASE 5: CALIBRAÇÃO AVANÇADA ===

    /// <summary>
    /// Opacidade do mapa (0-100%)
    /// </summary>
    [ObservableProperty]
    private double _opacidadeMapa = 50.0;

    /// <summary>
    /// ✅ RAIOS NOMINAIS FIXOS (usados como referência para renderização)
    /// </summary>
    private const double RAIO_NOMINAL_IRIS = 270.0;

    // === FERRAMENTA DE DESENHO (CANETA) ===
    [ObservableProperty]
    private bool _modoDesenhoAtivo = false;

    [ObservableProperty]
    private string _corDesenho = "#C85959"; // Vermelho terroso default

    [ObservableProperty]
    private double _espessuraDesenho = 2.0;

    [ObservableProperty]
    private ObservableCollection<StrokeModel> _strokes = new();

    public IrisdiagnosticoViewModel(
        IUnitOfWork unitOfWork,
        ILogger<IrisdiagnosticoViewModel> logger,
        IIridologyService iridologyService,
        IDragDebugService dragDebugService,
        IrisOverlayService overlayService)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _iridologyService = iridologyService ?? throw new ArgumentNullException(nameof(iridologyService));
        _dragDebugService = dragDebugService ?? throw new ArgumentNullException(nameof(dragDebugService));
        _overlayService = overlayService ?? throw new ArgumentNullException(nameof(overlayService));

        if (DebugArrastoAtivo)
        {
            _dragDebugService.RecordEvent(DragDebugEventType.DragStart, "IrisdiagnosticoViewModel inicializado");
        }
    }

    /// <summary>
    /// Carrega dados do paciente (chamado pelo FichaPacienteViewModel)
    /// </summary>
    public async Task CarregarDadosAsync(Paciente paciente)
    {
        if (paciente == null)
        {
            _logger.LogWarning("⚠️ Tentativa de carregar dados com paciente nulo");
            return;
        }

        _logger.LogInformation("� Carregando dados de íris para paciente: {Nome} (ID={Id})", paciente.NomeCompleto, paciente.Id);

        PacienteAtual = paciente;

        _logger.LogInformation("🔍 DEBUG: PacienteAtual setado. Chamando CarregarImagensAsync...");

        await CarregarImagensAsync();

        _logger.LogInformation("🔍 DEBUG: CarregarDadosAsync COMPLETO. Total de imagens: {Count}", IrisImagens.Count);
    }

    /// <summary>
    /// Carrega imagens de íris do paciente atual
    /// </summary>
    private async Task CarregarImagensAsync()
    {
        if (PacienteAtual == null)
        {
            _logger.LogWarning("⚠️ CarregarImagensAsync: PacienteAtual é NULL");
            return;
        }

        // ✅ CORREÇÃO CONCORRÊNCIA: Aguardar semaphore antes de acessar DbContext
        await _carregarImagensSemaphore.WaitAsync();

        try
        {
            _logger.LogInformation("🔍 Carregando imagens para Paciente ID={Id}, Nome={Nome}", PacienteAtual.Id, PacienteAtual.NomeCompleto);

            var todasImagens = await _unitOfWork.IrisImagens.GetAllAsync();
            _logger.LogInformation("🔍 Total de imagens na BD: {Count}", todasImagens.Count());

            var imagensDoPaciente = todasImagens
                .Where(i => i.PacienteId == PacienteAtual.Id)
                .OrderByDescending(i => i.DataCaptura)
                .ToList();

            _logger.LogInformation("🔍 Imagens filtradas para Paciente {Id}: {Count}", PacienteAtual.Id, imagensDoPaciente.Count);

            // ✅ AUDITADO: Log detalhado de cada imagem + verificação de existência de ficheiro
            foreach (var img in imagensDoPaciente)
            {
                var existe = System.IO.File.Exists(img.CaminhoImagem);
                _logger.LogInformation("  📷 Imagem ID={Id}, Olho={Olho}, Caminho={Caminho}, Data={Data}, Existe={Existe}",
                    img.Id, img.Olho, img.CaminhoImagem, img.DataCaptura, existe);

                if (!existe)
                {
                    _logger.LogWarning("  ⚠️ ALERTA: Ficheiro não encontrado no disco!");
                }
            }

            IrisImagens = new ObservableCollection<IrisImagem>(imagensDoPaciente);

            _logger.LogInformation("✅ Carregadas {Count} imagens de íris para ObservableCollection", IrisImagens.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar imagens de íris");
            ErrorMessage = "Erro ao carregar imagens.";
        }
        finally
        {
            // ✅ SEMPRE libertar o semaphore, mesmo com erro
            _carregarImagensSemaphore.Release();
        }
    }

    /// <summary>
    /// Comando para adicionar nova imagem de íris
    /// FASE 1: Captura de foto, validação, salvamento na BD e filesystem
    /// </summary>
    [RelayCommand]
    private async Task AdicionarImagemAsync()
    {
        // 🔥 GUARD: Validar paciente ativo
        if (PacienteAtual == null || PacienteAtual.Id == 0)
        {
            ErrorMessage = "Nenhum paciente selecionado ou paciente não foi salvo.";
            _logger.LogWarning("⚠️ Tentativa de adicionar imagem sem paciente válido");
            return;
        }

        try
        {
            IsLoading = true;
            ErrorMessage = null;

            // 1️⃣ OpenFileDialog para selecionar imagem
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Selecionar Imagem de Íris",
                Filter = "Imagens|*.jpg;*.jpeg;*.png;*.bmp|Todos os ficheiros|*.*",
                Multiselect = false
            };

            if (openFileDialog.ShowDialog() != true)
            {
                _logger.LogInformation("Seleção de imagem cancelada pelo utilizador");
                return;
            }

            // 2️⃣ Validar formato e tamanho (máx 10MB)
            var fileInfo = new System.IO.FileInfo(openFileDialog.FileName);
            if (fileInfo.Length > 10 * 1024 * 1024)
            {
                ErrorMessage = "Imagem muito grande (máximo 10MB)";
                _logger.LogWarning("⚠️ Imagem rejeitada: {Size}MB", fileInfo.Length / 1024.0 / 1024.0);
                return;
            }

            // 3️⃣ Criar estrutura de pastas: Documents/BioDeskPro2/Pacientes/{NomePaciente}/IrisImagens/
            var nomePaciente = PacienteAtual.NomeCompleto; // Manter espaços para consistência com outros documentos
            var pastaPaciente = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "BioDeskPro2", "Pacientes", nomePaciente, "IrisImagens"
            );

            System.IO.Directory.CreateDirectory(pastaPaciente);

            // 4️⃣ Gerar nome único: Iris_{Olho}_{Timestamp}{Extensão}
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var extensao = System.IO.Path.GetExtension(openFileDialog.FileName);
            var nomeArquivo = $"Iris_{OlhoSelecionado}_{timestamp}{extensao}";
            var caminhoDestino = System.IO.Path.Combine(pastaPaciente, nomeArquivo);

            // 5️⃣ Copiar imagem para o destino
            System.IO.File.Copy(openFileDialog.FileName, caminhoDestino, true);
            _logger.LogInformation("📁 Imagem copiada para: {Caminho}", caminhoDestino);

            // 6️⃣ Criar entidade IrisImagem
            var novaImagem = new IrisImagem
            {
                PacienteId = PacienteAtual.Id,
                Olho = OlhoSelecionado,
                DataCaptura = DateTime.Now,
                CaminhoImagem = caminhoDestino,
                Observacoes = string.IsNullOrWhiteSpace(ObservacoesImagem) ? null : ObservacoesImagem
            };

            // 7️⃣ Salvar no banco de dados
            await _unitOfWork.IrisImagens.AddAsync(novaImagem);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("✅ Imagem de íris adicionada: {Olho}, ID: {Id}", OlhoSelecionado, novaImagem.Id);

            // 8️⃣ Recarregar lista e limpar campos
            await CarregarImagensAsync();
            ObservacoesImagem = null; // Limpar observações para próxima captura

            // 9️⃣ Selecionar automaticamente a imagem recém-adicionada
            IrisImagemSelecionada = IrisImagens.FirstOrDefault(i => i.Id == novaImagem.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao adicionar imagem de íris");
            ErrorMessage = $"Erro ao adicionar imagem: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Comando para remover imagem selecionada
    /// FASE 1: Confirmação, remoção de ficheiro físico e BD
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanRemoverImagem))]
    private async Task RemoverImagemAsync()
    {
        if (IrisImagemSelecionada == null)
        {
            _logger.LogWarning("⚠️ Tentativa de remover imagem sem seleção");
            return;
        }

        try
        {
            // 1️⃣ Confirmação com MessageBox
            var resultado = System.Windows.MessageBox.Show(
                $"Deseja remover a imagem do olho {IrisImagemSelecionada.Olho}?\n\n" +
                $"Data: {IrisImagemSelecionada.DataCaptura:dd/MM/yyyy HH:mm}\n" +
                $"Esta ação não pode ser desfeita.",
                "Confirmar Remoção",
                System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Question
            );

            if (resultado != System.Windows.MessageBoxResult.Yes)
            {
                return;
            }

            IsLoading = true;
            ErrorMessage = null;

            var imagemId = IrisImagemSelecionada.Id;
            var caminhoImagem = IrisImagemSelecionada.CaminhoImagem;

            // 🔓 Limpar seleção para liberar binding (converter já carregou em memória)
            IrisImagemSelecionada = null;

            // 2️⃣ Remover arquivo físico (se existir)
            if (System.IO.File.Exists(caminhoImagem))
            {
                System.IO.File.Delete(caminhoImagem);
                _logger.LogInformation("🗑️ Arquivo físico removido: {Caminho}", caminhoImagem);
            }
            else
            {
                _logger.LogWarning("⚠️ Arquivo físico não encontrado: {Caminho}", caminhoImagem);
            }

            // 3️⃣ Remover do banco de dados (cascade delete remove IrisMarcas automaticamente)
            var imagemParaRemover = await _unitOfWork.IrisImagens.GetByIdAsync(imagemId);

            if (imagemParaRemover == null)
            {
                ErrorMessage = "Imagem não encontrada na base de dados.";
                _logger.LogError("❌ Imagem ID {Id} não encontrada na BD", imagemId);
                return;
            }

            _unitOfWork.IrisImagens.Remove(imagemParaRemover);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("✅ Imagem de íris removida: ID {Id}, Olho {Olho}", imagemId, imagemParaRemover.Olho);

            // 4️⃣ Recarregar lista
            await CarregarImagensAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao remover imagem de íris");
            ErrorMessage = $"Erro ao remover imagem: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private bool CanRemoverImagem()
    {
        return IrisImagemSelecionada != null;
    }

    /// <summary>
    /// Carrega imagem capturada da câmara USB (chamado pelo UserControl)
    /// </summary>
    public async Task CarregarImagemCapturadaAsync(string caminhoImagemCapturada)
    {
        if (PacienteAtual == null || PacienteAtual.Id == 0)
        {
            ErrorMessage = "Nenhum paciente selecionado.";
            _logger.LogWarning("⚠️ Tentativa de carregar imagem capturada sem paciente válido");
            return;
        }

        try
        {
            IsLoading = true;
            ErrorMessage = null;

            // 1️⃣ Criar estrutura de pastas do paciente
            var nomePaciente = PacienteAtual.NomeCompleto; // Manter espaços para consistência
            var pastaPaciente = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "BioDeskPro2", "Pacientes", nomePaciente, "IrisImagens"
            );

            System.IO.Directory.CreateDirectory(pastaPaciente);

            // 2️⃣ Gerar nome final: Iris_{Olho}_{Timestamp}.jpg
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var nomeArquivo = $"Iris_{OlhoSelecionado}_{timestamp}.jpg";
            var caminhoDestino = System.IO.Path.Combine(pastaPaciente, nomeArquivo);

            // 3️⃣ Mover imagem da pasta temporária para pasta do paciente
            System.IO.File.Move(caminhoImagemCapturada, caminhoDestino, true);
            _logger.LogInformation("📁 Imagem capturada movida para: {Caminho}", caminhoDestino);

            // 4️⃣ Criar entidade IrisImagem
            var novaImagem = new IrisImagem
            {
                PacienteId = PacienteAtual.Id,
                Olho = OlhoSelecionado,
                DataCaptura = DateTime.Now,
                CaminhoImagem = caminhoDestino,
                Observacoes = string.IsNullOrWhiteSpace(ObservacoesImagem) ? null : ObservacoesImagem
            };

            // 5️⃣ Salvar no banco de dados
            await _unitOfWork.IrisImagens.AddAsync(novaImagem);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("✅ Imagem capturada adicionada: {Olho}, ID: {Id}", OlhoSelecionado, novaImagem.Id);

            // 6️⃣ Recarregar lista e selecionar nova imagem
            await CarregarImagensAsync();
            ObservacoesImagem = null;
            IrisImagemSelecionada = IrisImagens.FirstOrDefault(i => i.Id == novaImagem.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar imagem capturada");
            ErrorMessage = $"Erro ao carregar imagem: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    // ========================================
    // FASE 2: COMANDOS DE ZOOM/PAN
    // ========================================

    /// <summary>
    /// Aumenta o nível de zoom
    /// </summary>
    [RelayCommand]
    private void ZoomIn()
    {
        if (ZoomLevel < MaxZoom)
        {
            ZoomLevel = Math.Min(ZoomLevel + ZoomStep, MaxZoom);
            _logger.LogDebug("🔍 Zoom aumentado: {Zoom}x", ZoomLevel);
        }
    }

    /// <summary>
    /// Diminui o nível de zoom
    /// </summary>
    [RelayCommand]
    private void ZoomOut()
    {
        if (ZoomLevel > MinZoom)
        {
            ZoomLevel = Math.Max(ZoomLevel - ZoomStep, MinZoom);
            _logger.LogDebug("🔍 Zoom diminuído: {Zoom}x", ZoomLevel);
        }
    }

    /// <summary>
    /// Reseta zoom e pan para valores iniciais
    /// </summary>
    [RelayCommand]
    private void ResetZoom()
    {
        ZoomLevel = 1.0;
        TranslateX = 0.0;
        TranslateY = 0.0;
        _logger.LogDebug("🔄 Zoom resetado");
    }

    // ========================================
    // FASE 2: COMANDOS DE MARCAÇÕES
    // ========================================

    /// <summary>
    /// Adiciona marca na posição especificada (chamado pelo Canvas via Command Parameter)
    /// </summary>
    [RelayCommand]
    private async Task AdicionarMarcaAsync((double X, double Y, string? Observacao) parametros)
    {
        if (IrisImagemSelecionada == null)
        {
            _logger.LogWarning("⚠️ Tentativa de adicionar marca sem imagem selecionada");
            return;
        }

        try
        {
            var novaMarca = new IrisMarca
            {
                IrisImagemId = IrisImagemSelecionada.Id,
                X = parametros.X,
                Y = parametros.Y,
                Cor = CorMarcaSelecionada,
                Observacoes = parametros.Observacao ?? string.Empty,
                DataCriacao = DateTime.Now
            };

            // Salvar na BD
            await _unitOfWork.IrisMarcas.AddAsync(novaMarca);
            await _unitOfWork.SaveChangesAsync();

            // Adicionar à coleção local
            MarcasImagem.Add(novaMarca);

            // Atualizar contadores (FASE 3)
            NotificarMudancaContadores();

            _logger.LogInformation("✅ Marca adicionada: X={X}, Y={Y}, Cor={Cor}", parametros.X, parametros.Y, CorMarcaSelecionada);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao adicionar marca");
            ErrorMessage = $"Erro ao adicionar marca: {ex.Message}";
        }
    }

    /// <summary>
    /// Remove marca selecionada
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanRemoverMarca))]
    private async Task RemoverMarcaAsync()
    {
        if (MarcaSelecionada == null) return;

        try
        {
            // Remover da BD
            _unitOfWork.IrisMarcas.Remove(MarcaSelecionada);
            await _unitOfWork.SaveChangesAsync();

            // Remover da coleção local
            MarcasImagem.Remove(MarcaSelecionada);

            // Atualizar contadores (FASE 3)
            NotificarMudancaContadores();

            _logger.LogInformation("🗑️ Marca removida: ID {Id}", MarcaSelecionada.Id);
            MarcaSelecionada = null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao remover marca");
            ErrorMessage = $"Erro ao remover marca: {ex.Message}";
        }
    }

    private bool CanRemoverMarca() => MarcaSelecionada != null;

    /// <summary>
    /// Edita observações de uma marca existente (FASE 3)
    /// </summary>
    /// <summary>
    /// Evento para solicitar abertura de dialog de edição de observações
    /// </summary>
    public event EventHandler<IrisMarca>? SolicitarEdicaoObservacoes;

    /// <summary>
    /// Editar observações de uma marca - Dispara evento para a View abrir o dialog
    /// </summary>
    [RelayCommand]
    private void EditarObservacoesMarca(IrisMarca marca)
    {
        if (marca == null) return;

        _logger.LogInformation("📝 Solicitando edição de observações da marca ID {Id}", marca.Id);

        // Disparar evento para a View tratar (MVVM pattern)
        SolicitarEdicaoObservacoes?.Invoke(this, marca);
    }

    /// <summary>
    /// Atualizar observações de uma marca (chamado pela View após dialog)
    /// </summary>
    public async Task AtualizarObservacoesMarcaAsync(IrisMarca marca)
    {
        try
        {
            // Salvar na BD
            await _unitOfWork.SaveChangesAsync();
            _logger.LogInformation("✅ Observações da marca ID {Id} atualizadas", marca.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao atualizar observações da marca");
            ErrorMessage = $"Erro ao atualizar observações: {ex.Message}";
        }
    }

    /// <summary>
    /// Muda cor de uma marca existente (FASE 3)
    /// </summary>
    [RelayCommand]
    private async Task MudarCorMarcaAsync((IrisMarca Marca, string NovaCor) parametros)
    {
        if (parametros.Marca == null) return;

        try
        {
            parametros.Marca.Cor = parametros.NovaCor;
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("🎨 Cor da marca alterada para {Cor}", parametros.NovaCor);

            // Forçar atualização visual + contadores (FASE 3)
            OnPropertyChanged(nameof(MarcasImagem));
            NotificarMudancaContadores();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao mudar cor da marca");
            ErrorMessage = $"Erro ao mudar cor: {ex.Message}";
        }
    }

    /// <summary>
    /// Remove marca específica (alternativa ao RemoverMarcaAsync que usa MarcaSelecionada)
    /// </summary>
    [RelayCommand]
    private async Task RemoverMarcaEspecificaAsync(IrisMarca marca)
    {
        if (marca == null) return;

        try
        {
            // Remover da BD
            _unitOfWork.IrisMarcas.Remove(marca);
            await _unitOfWork.SaveChangesAsync();

            // Remover da coleção local
            MarcasImagem.Remove(marca);

            // Atualizar contadores (FASE 3)
            NotificarMudancaContadores();

            _logger.LogInformation("🗑️ Marca removida: ID {Id}", marca.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao remover marca");
            ErrorMessage = $"Erro ao remover marca: {ex.Message}";
        }
    }

    /// <summary>
    /// Carrega marcas da imagem selecionada
    /// </summary>
    private async Task CarregarMarcasAsync()
    {
        if (IrisImagemSelecionada == null)
        {
            MarcasImagem.Clear();
            return;
        }

        try
        {
            var todasMarcas = await _unitOfWork.IrisMarcas.GetAllAsync();
            var marcasDaImagem = todasMarcas
                .Where(m => m.IrisImagemId == IrisImagemSelecionada.Id)
                .OrderBy(m => m.DataCriacao)
                .ToList();

            MarcasImagem = new ObservableCollection<IrisMarca>(marcasDaImagem);

            // Atualizar contadores (FASE 3)
            NotificarMudancaContadores();

            _logger.LogInformation("📌 Carregadas {Count} marcas da imagem", MarcasImagem.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar marcas");
            MarcasImagem.Clear();
        }
    }

    /// <summary>
    /// Hook para quando a imagem selecionada mudar → carregar marcas
    /// ✅ AUDITADO: Logging detalhado para diagnóstico de imagens não visíveis
    /// </summary>
    partial void OnIrisImagemSelecionadaChanged(IrisImagem? value)
    {
        if (value != null)
        {
            var existe = System.IO.File.Exists(value.CaminhoImagem);
            _logger.LogInformation("🔍 SELEÇÃO MUDOU → Olho: {Olho}, ID: {Id}, Caminho: {Caminho}, Existe: {Existe}",
                value.Olho, value.Id, value.CaminhoImagem, existe);

            if (!existe)
            {
                _logger.LogError("❌ CRÍTICO: Ficheiro da imagem selecionada NÃO EXISTE no disco!");
                ErrorMessage = $"Ficheiro de imagem não encontrado: {System.IO.Path.GetFileName(value.CaminhoImagem)}";
            }
        }
        else
        {
            _logger.LogInformation("🔍 SELEÇÃO MUDOU → NULL (nenhuma imagem selecionada)");
        }

        if (value != null)
        {
            // Reset zoom/pan ao mudar de imagem
            ResetZoom();

            // Carregar marcas da nova imagem (fire-and-forget é seguro aqui)
            _ = CarregarMarcasAsync();

            // FASE 4: Carregar mapa iridológico automaticamente
            if (MostrarMapaIridologico)
            {
                _ = CarregarMapaIridologicoAsync();
            }
        }
        else
        {
            MarcasImagem.Clear();
        }
    }

    /// <summary>
    /// Notifica mudanças nos contadores de marcas por cor (FASE 3)
    /// </summary>
    private void NotificarMudancaContadores()
    {
        OnPropertyChanged(nameof(CountVermelho));
        OnPropertyChanged(nameof(CountVerde));
        OnPropertyChanged(nameof(CountAzul));
        OnPropertyChanged(nameof(CountAmarelo));
        OnPropertyChanged(nameof(CountTotal));
    }

    // === COMANDOS FERRAMENTA DE DESENHO ===

    /// <summary>
    /// Limpa todos os desenhos do canvas
    /// </summary>
    [RelayCommand]
    private void LimparDesenhos()
    {
        try
        {
            Strokes.Clear();
            _logger.LogInformation("🗑️ Todos os desenhos foram limpos");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao limpar desenhos");
        }
    }

    /// <summary>
    /// Desfaz o último desenho
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanDesfazerDesenho))]
    private void DesfazerDesenho()
    {
        try
        {
            if (Strokes.Count > 0)
            {
                var ultimoStroke = Strokes[Strokes.Count - 1];
                Strokes.RemoveAt(Strokes.Count - 1);
                _logger.LogInformation("↶ Desenho desfeito: {Count} pontos", ultimoStroke.Points.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao desfazer desenho");
        }
    }

    private bool CanDesfazerDesenho() => Strokes.Count > 0;

    /// <summary>
    /// Adiciona um novo stroke à coleção
    /// </summary>
    public void AdicionarStroke(StrokeModel stroke)
    {
        if (stroke == null || stroke.Points.Count == 0)
        {
            _logger.LogWarning("⚠️ Tentativa de adicionar stroke vazio ou nulo");
            return;
        }

        try
        {
            Strokes.Add(stroke);
            DesfazerDesenhoCommand.NotifyCanExecuteChanged();
            _logger.LogDebug("✏️ Stroke adicionado: {Count} pontos, cor {Color}", stroke.Points.Count, stroke.Color);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao adicionar stroke");
        }
    }

    // === COMANDOS OVERLAY INFALÍVEL (3-CLICK + OPENCV) ===

    /// <summary>
    /// Inicia o processo de alinhamento do overlay (3 cliques: Centro → Direita → Topo)
    /// </summary>
    [RelayCommand]
    private void StartOverlayAlignment()
    {
        try
        {
            // ✅ Auto-ativar o mapa se ainda não estiver visível
            if (!MostrarMapaIridologico)
            {
                MostrarMapaIridologico = true;
                _logger.LogInformation("🔍 Mapa iridológico ativado automaticamente");
            }

            _overlayService.StartAlignment();
            IsAlignmentActive = true;
            AlignmentInstructionText = "1️⃣ Clique no CENTRO da pupila";
            _logger.LogInformation("🎯 Sistema de alinhamento iniciado");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao iniciar alinhamento overlay");
        }
    }

    /// <summary>
    /// Executa detecção automática OpenCV para ajustar o mapa às bordas da íris
    /// </summary>
    [RelayCommand]
    private async Task AutoFitOverlay()
    {
        try
        {
            if (IrisImagemSelecionada == null)
            {
                _logger.LogWarning("⚠️ Auto-Fit sem imagem selecionada");
                return;
            }

            // Carregar a imagem como BitmapSource
            var bitmap = new System.Windows.Media.Imaging.BitmapImage();
            bitmap.BeginInit();
            bitmap.UriSource = new Uri(IrisImagemSelecionada.CaminhoImagem, UriKind.Absolute);
            bitmap.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
            bitmap.EndInit();
            bitmap.Freeze(); // Thread-safe

            var success = await _overlayService.AutoFitAsync(bitmap);

            if (success)
            {
                var transform = _overlayService.GetCurrentTransform();
                if (transform != null)
                {
                    OverlayTransform = transform;
                    AlignmentInstructionText = "✅ Auto-Fit concluído! Clique em Confirmar para salvar.";
                    _logger.LogInformation("🤖 Auto-Fit OpenCV executado com sucesso");
                }
            }
            else
            {
                AlignmentInstructionText = "⚠️ Auto-Fit falhou. Continue manualmente ou reinicie.";
                _logger.LogWarning("⚠️ Auto-Fit não conseguiu detectar a íris");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao executar Auto-Fit");
            AlignmentInstructionText = "❌ Erro no Auto-Fit. Continue manualmente.";
        }
    }

    /// <summary>
    /// Confirma o alinhamento atual e finaliza o processo
    /// </summary>
    [RelayCommand]
    private void ConfirmAlignment()
    {
        try
        {
            IsAlignmentActive = false;
            HasThreeClicks = false; // ✅ LIMPAR FLAG
            AlignmentInstructionText = string.Empty;
            _logger.LogInformation("✅ Alinhamento confirmado pelo utilizador");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao confirmar alinhamento");
        }
    }

    /// <summary>
    /// Reinicia o processo de alinhamento (reset completo)
    /// </summary>
    [RelayCommand]
    private void ResetAlignment()
    {
        try
        {
            _overlayService.ResetAlignment();
            OverlayTransform = System.Windows.Media.Transform.Identity;
            IsAlignmentActive = false;
            HasThreeClicks = false; // ✅ LIMPAR FLAG
            AlignmentInstructionText = string.Empty;
            _logger.LogInformation("↻ Alinhamento reiniciado");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao reiniciar alinhamento");
        }
    }

    /// <summary>
    /// Processa um clique no MapaOverlayCanvas durante o alinhamento (chamado pelo code-behind)
    /// </summary>
    public void ProcessOverlayClick(System.Windows.Point clickPosition)
    {
        if (!IsAlignmentActive) return;

        try
        {
            var allClicksCompleted = _overlayService.ProcessClick(clickPosition);

            // Atualizar texto de instrução baseado na fase atual do serviço
            AlignmentInstructionText = _overlayService.InstructionText;

            // Se os 3 cliques foram completados, obter a transformação calculada
            if (allClicksCompleted)
            {
                HasThreeClicks = true; // ✅ HABILITAR Auto-Fit/Confirmar
                var transform = _overlayService.GetCurrentTransform();
                if (transform != null)
                {
                    OverlayTransform = transform;
                    _logger.LogInformation("✅ 3 cliques completos - Transformação aplicada");
                }
            }

            _logger.LogDebug("🖱️ Clique processado - Estado: {Instruction}", AlignmentInstructionText);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao processar clique no overlay");
            AlignmentInstructionText = "❌ Erro ao processar clique. Reinicie o alinhamento.";
        }
    }

    partial void OnDebugArrastoAtivoChanged(bool value)
    {
        if (value)
        {
            _dragDebugService.RecordEvent(DragDebugEventType.DragStart, "Debug de arrasto ativado");
        }
    }

    private void RecordDragEvent(
        DragDebugEventType type,
        string message,
        IReadOnlyDictionary<string, double>? metrics = null,
        IReadOnlyDictionary<string, string>? context = null)
    {
        if (!DebugArrastoAtivo)
        {
            return;
        }

        try
        {
            _dragDebugService.RecordEvent(type, message, metrics, context);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao registar evento de debug: {Message}", ex.Message);
        }
    }

    // ========================================
    // FASE 4: MAPA IRIDOLÓGICO
    // ========================================

    /// <summary>
    /// Observador para quando MostrarMapaIridologico mudar via binding
    /// </summary>
    partial void OnMostrarMapaIridologicoChanged(bool value)
    {
        _logger.LogInformation("🗺️ Mapa iridológico mudou para: {Estado}", value ? "VISÍVEL" : "OCULTO");

        if (value && IrisImagemSelecionada != null)
        {
            _ = CarregarMapaIridologicoAsync();
        }
        else
        {
            // Limpar polígonos ao ocultar
            PoligonosZonas.Clear();
            ZonaDetectada = null;
        }
    }

    /// <summary>
    /// Carrega e renderiza mapa iridológico baseado no olho da imagem
    /// </summary>
    private async Task CarregarMapaIridologicoAsync()
    {
        if (IrisImagemSelecionada == null)
        {
            _logger.LogWarning("⚠️ Tentativa de carregar mapa sem imagem selecionada");
            return;
        }

        try
        {
            IsLoading = true;
            ErrorMessage = null;

            // Carregar JSON baseado no olho (Esquerdo → esq, Direito → drt)
            MapaAtual = await _iridologyService.CarregarMapaAsync(IrisImagemSelecionada.Olho);

            if (MapaAtual == null)
            {
                ErrorMessage = "Erro ao carregar mapa iridológico.";
                _logger.LogError("❌ Falha ao carregar mapa para olho: {Olho}", IrisImagemSelecionada.Olho);
                return;
            }

            _logger.LogInformation("✅ Mapa iridológico carregado: {TotalZonas} zonas, Tipo: {Tipo}",
                MapaAtual.Metadata.TotalZonas,
                MapaAtual.Metadata.Tipo);

            // Renderizar polígonos
            RenderizarPoligonos();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar mapa iridológico");
            ErrorMessage = $"Erro ao carregar mapa: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Renderiza todas as zonas do mapa como polígonos WPF
    /// NOVO: Usa canvas fixo 600x600px para mapa centralizado
    /// </summary>
    private void RenderizarPoligonos()
    {
        if (MapaAtual?.Zonas == null) return;

        PoligonosZonas.Clear();

        var cores = new[] { "#6B8E63", "#9CAF97", "#5B7C99", "#D4A849" };
        var corIndex = 0;

        foreach (var zona in MapaAtual.Zonas)
        {
            // 🎨 NOVA LÓGICA: Círculos perfeitos + OverlayTransform do Sistema Infalível
            foreach (var parte in zona.Partes)
            {
                var pontos = new System.Windows.Media.PointCollection();

                foreach (var coordenada in parte)
                {
                    double normalizedRadius = Math.Clamp(coordenada.Raio, 0.0, 1.0);
                    double angulo = (coordenada.Angulo + 270.0) * Math.PI / 180.0;
                    angulo = NormalizeAngleRadians(angulo);

                    double raio = normalizedRadius * RAIO_NOMINAL_IRIS;
                    double x = 200.0 + raio * Math.Cos(angulo); // Centro em (200, 200) - canvas 400x400
                    double y = 200.0 - raio * Math.Sin(angulo);

                    pontos.Add(new System.Windows.Point(x, y));
                }

                if (pontos.Count > 0)
                {
                    PoligonosZonas.Add(new ZonaPoligono
                    {
                        Nome = zona.Nome,
                        Descricao = zona.Descricao,
                        Pontos = pontos,
                        CorPreenchimento = cores[corIndex % cores.Length]
                    });
                }
            }

            corIndex++;
        }

        _logger.LogInformation("🎨 Renderizados {Count} polígonos para {Zonas}",
            PoligonosZonas.Count,
            MapaAtual.Zonas.Count);
    }

    /// <summary>
    /// Normaliza ângulo para 0 a 2π radianos
    /// </summary>
    private static double NormalizeAngleRadians(double angulo)
    {
        while (angulo < 0) angulo += 2 * Math.PI;
        while (angulo >= 2 * Math.PI) angulo -= 2 * Math.PI;
        return angulo;
    }

    /// <summary>
    /// Detecta zona ao clicar (chamado pelo UserControl)
    /// </summary>
    public void DetectarZonaNoClique(double x, double y)
    {
        if (MapaAtual == null || !MostrarMapaIridologico) return;

        ZonaDetectada = _iridologyService.DetectarZonaClique(x, y, MapaAtual);

        if (ZonaDetectada != null)
        {
            _logger.LogInformation("🎯 Zona detectada no clique: {Nome}", ZonaDetectada.Nome);
        }
    }

    // === MÉTODOS DE RENDERIZAÇÃO OVERLAY ===

    /// <summary>
    /// Recalcula polígonos com deformação baseada em handlers
    /// (Implementação simplificada - pode ser expandida)
    /// </summary>
    public void RecalcularPoligonosComDeformacao()
    {
        RecalcularPoligonosComDeformacao(throttle: false);
    }

    /// <summary>
    /// Recalcula polígonos com deformação baseada em handlers
    /// <summary>
    /// Recalcula e renderiza os polígonos das zonas iridológicas.
    /// Agora usa apenas círculos perfeitos + transformação overlay do Sistema Infalível.
    /// </summary>
    public void RecalcularPoligonosComDeformacao(bool throttle = false)
    {
        if (MapaAtual == null) return;

        RenderizarPoligonos();

        _logger.LogInformation("🔄 Polígonos recalculados");
    }

    // ✅ DISPOSE PATTERN: Liberar SemaphoreSlim (CA1001 compliant)
    private bool _disposed = false;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _carregarImagensSemaphore?.Dispose();
        }
        _disposed = true;
    }
}

