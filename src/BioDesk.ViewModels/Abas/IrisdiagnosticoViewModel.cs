using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Media;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Models;
using BioDesk.Services;
using BioDesk.Services.Debug;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel MINIMALISTA para Irisdiagnóstico (Tab 5)
/// Responsabilidade: Gerir lista de imagens de íris do paciente atual
/// </summary>
public partial class IrisdiagnosticoViewModel : ObservableObject
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<IrisdiagnosticoViewModel> _logger;
    private readonly IIridologyService _iridologyService;
    private readonly IDragDebugService _dragDebugService;

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

    // === FASE 5: CALIBRAÇÃO AVANÇADA ===

    /// <summary>
    /// Opacidade do mapa (0-100%)
    /// </summary>
    [ObservableProperty]
    private double _opacidadeMapa = 50.0;

    /// <summary>
    /// Modo calibração ativo (mostra handlers)
    /// </summary>
    [ObservableProperty]
    private bool _modoCalibracaoAtivo = false;

    /// <summary>
    /// Tipo de calibração: Pupila
    /// </summary>
    [ObservableProperty]
    private bool _tipoCalibracaoPupila = false;

    /// <summary>
    /// Tipo de calibração: Íris
    /// </summary>
    [ObservableProperty]
    private bool _tipoCalibracaoIris = true;

    /// <summary>
    /// Tipo de calibração: Ambos
    /// </summary>
    [ObservableProperty]
    private bool _tipoCalibracaoAmbos = false;

    /// <summary>
    /// Modo mover mapa ativo (drag global do overlay)
    /// </summary>
    [ObservableProperty]
    private bool _modoMoverMapa = false;

    /// <summary>
    /// Classe para representar um handler (ponto de controle)
    /// </summary>
    public partial class CalibrationHandler : ObservableObject
    {
        [ObservableProperty]
        private double _x;

        [ObservableProperty]
        private double _y;

        [ObservableProperty]
        private double _angulo; // 0-360°

        [ObservableProperty]
        private string _tipo = "Iris"; // "Pupila" ou "Iris"
    }

    /// <summary>
    /// Handlers da pupila (circuito interno)
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<CalibrationHandler> _handlersPupila = new();

    /// <summary>
    /// Handlers da íris (moldura externa)
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<CalibrationHandler> _handlersIris = new();

    /// <summary>
    /// Quantidade de handlers para a íris (mínimo 8 para estabilidade)
    /// </summary>
    [ObservableProperty]
    private int _quantidadeHandlersIris = 12;

    /// <summary>
    /// Quantidade de handlers para a pupila (mínimo 8 por padrão)
    /// </summary>
    [ObservableProperty]
    private int _quantidadeHandlersPupila = 12;

    private bool _atualizandoContagemHandlers;
    private bool _suspendHandlerUpdates;
    private bool _isDragging = false;  // ⭐ Flag para prevenir renderização durante arrasto

    /// <summary>
    /// Layer 3: Suspende visibilidade visual dos polígonos durante arrasto (previne atualizações assíncronas WPF)
    /// </summary>
    [ObservableProperty]
    private bool _mostrarPoligonosDuranteArrasto = true;

    /// <summary>
    /// Centro da pupila X
    /// </summary>
    [ObservableProperty]
    private double _centroPupilaX = 300;

    /// <summary>
    /// Centro da pupila Y
    /// </summary>
    [ObservableProperty]
    private double _centroPupilaY = 300;

    /// <summary>
    /// Raio da pupila
    /// </summary>
    [ObservableProperty]
    private double _raioPupila = 54;

    [ObservableProperty]
    private double _raioPupilaHorizontal = RAIO_NOMINAL_PUPILA;

    [ObservableProperty]
    private double _raioPupilaVertical = RAIO_NOMINAL_PUPILA;

    /// <summary>
    /// Centro da íris X
    /// </summary>
    [ObservableProperty]
    private double _centroIrisX = 300;

    /// <summary>
    /// Centro da íris Y
    /// </summary>
    [ObservableProperty]
    private double _centroIrisY = 300;

    /// <summary>
    /// Raio da íris
    /// </summary>
    [ObservableProperty]
    private double _raioIris = 270;

    [ObservableProperty]
    private double _raioIrisHorizontal = RAIO_NOMINAL_IRIS;

    [ObservableProperty]
    private double _raioIrisVertical = RAIO_NOMINAL_IRIS;

    [ObservableProperty]
    private double _escalaIrisX = 1.0;

    [ObservableProperty]
    private double _escalaIrisY = 1.0;

    [ObservableProperty]
    private double _escalaPupilaX = 1.0;

    [ObservableProperty]
    private double _escalaPupilaY = 1.0;

    /// <summary>
    /// ✅ RAIOS NOMINAIS FIXOS (usados como referência para cálculo de deformação)
    /// Previne erros de baseline móvel durante drag de handlers
    /// </summary>
    private const double RAIO_NOMINAL_PUPILA = 54.0;
    private const double RAIO_NOMINAL_IRIS = 270.0;
    private const double PUPILA_NORMALIZED_THRESHOLD = RAIO_NOMINAL_PUPILA / RAIO_NOMINAL_IRIS;
    private const double PUPILA_TRANSITION_WIDTH = 0.04;

    private const double MAPA_ZOOM_MIN = 0.6;
    private const double MAPA_ZOOM_MAX = 1.6;
    private const double MAPA_ZOOM_STEP = 0.1;

    [ObservableProperty]
    private double _mapaZoom = 1.0;

    public IrisdiagnosticoViewModel(
        IUnitOfWork unitOfWork,
        ILogger<IrisdiagnosticoViewModel> logger,
        IIridologyService iridologyService,
        IDragDebugService dragDebugService)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _iridologyService = iridologyService ?? throw new ArgumentNullException(nameof(iridologyService));
        _dragDebugService = dragDebugService ?? throw new ArgumentNullException(nameof(dragDebugService));

        HandlersIris.CollectionChanged += OnHandlersCollectionChanged;
        HandlersPupila.CollectionChanged += OnHandlersCollectionChanged;

        if (DebugArrastoAtivo)
        {
            _dragDebugService.StartSession("IrisdiagnosticoViewModel inicializado");
            RegistarEstadoAtual("VM inicializada");
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

            // Log detalhado de cada imagem
            foreach (var img in imagensDoPaciente)
            {
                _logger.LogInformation("  📷 Imagem ID={Id}, Olho={Olho}, Caminho={Caminho}, Data={Data}",
                    img.Id, img.Olho, img.CaminhoImagem, img.DataCaptura);
            }

            IrisImagens = new ObservableCollection<IrisImagem>(imagensDoPaciente);

            _logger.LogInformation("✅ Carregadas {Count} imagens de íris para ObservableCollection", IrisImagens.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar imagens de íris");
            ErrorMessage = "Erro ao carregar imagens.";
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

    [RelayCommand]
    private void AumentarMapa()
    {
        AjustarMapaZoom(MapaZoom + MAPA_ZOOM_STEP);
    }

    [RelayCommand]
    private void DiminuirMapa()
    {
        AjustarMapaZoom(MapaZoom - MAPA_ZOOM_STEP);
    }

    [RelayCommand]
    private void ResetMapa()
    {
        AjustarMapaZoom(1.0);
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
    [RelayCommand]
    private async Task EditarObservacoesMarcaAsync(IrisMarca marca)
    {
        if (marca == null) return;

        try
        {
            // TODO: Integração do dialog deve ser feita na camada View (IrisdiagnosticoUserControl)
            // ViewModels não devem referenciar Views/Dialogs (violação MVVM)
            // Por agora, apenas log para confirmar que comando executa
            _logger.LogInformation("📝 Editar observações da marca ID {Id}", marca.Id);

            // Salvar na BD
            await _unitOfWork.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao editar observações da marca");
            ErrorMessage = $"Erro ao editar observações: {ex.Message}";
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
    /// </summary>
    partial void OnIrisImagemSelecionadaChanged(IrisImagem? value)
    {
        _logger.LogInformation($"🔍 DEBUG: Seleção mudou! Valor: {value?.Olho ?? "NULL"}");

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

    partial void OnDebugArrastoAtivoChanged(bool value)
    {
        if (value)
        {
            _dragDebugService.StartSession("Debug de arrasto ativado");
            RegistarEstadoAtual("Debug toggle ON");
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

    private Dictionary<string, double> ConstruirMetricasCentros()
    {
        return new Dictionary<string, double>
        {
            ["centroPupilaX"] = CentroPupilaX,
            ["centroPupilaY"] = CentroPupilaY,
            ["raioPupila"] = RaioPupila,
            ["centroIrisX"] = CentroIrisX,
            ["centroIrisY"] = CentroIrisY,
            ["raioIris"] = RaioIris
        };
    }

    private Dictionary<string, string> ConstruirContextoPadrao()
    {
        return new Dictionary<string, string>
        {
            ["modoCalibracaoAtivo"] = ModoCalibracaoAtivo.ToString(),
            ["tipoCalibracaoPupila"] = TipoCalibracaoPupila.ToString(),
            ["tipoCalibracaoIris"] = TipoCalibracaoIris.ToString(),
            ["tipoCalibracaoAmbos"] = TipoCalibracaoAmbos.ToString(),
            ["modoMoverMapa"] = ModoMoverMapa.ToString(),
            ["mostrarMapaIridologico"] = MostrarMapaIridologico.ToString()
        };
    }

    private void RegistarEstadoAtual(string origem)
    {
        var contexto = ConstruirContextoPadrao();
        contexto["origem"] = origem;

        RecordDragEvent(
            DragDebugEventType.ViewModelUpdate,
            "Snapshot do estado atual",
            ConstruirMetricasCentros(),
            contexto);
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
            ModoMoverMapa = false;
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
        if (MapaAtual == null) return;

        PoligonosZonas.Clear();

        var cores = new[] { "#6B8E63", "#9CAF97", "#5B7C99", "#D4A849" };
        var corIndex = 0;

        foreach (var zona in MapaAtual.Zonas)
        {
            var poligonos = InterpolateZoneWithHandlers(zona, aplicarDeformacaoLocal: false);

            foreach (var pontos in poligonos)
            {
                PoligonosZonas.Add(new ZonaPoligono
                {
                    Nome = zona.Nome,
                    Descricao = zona.Descricao,
                    Pontos = pontos,
                    CorPreenchimento = cores[corIndex % cores.Length]
                });
            }

            corIndex++;
        }

        _logger.LogInformation("🎨 Renderizados {Count} polígonos para {Zonas}",
            PoligonosZonas.Count,
            MapaAtual.Zonas.Count);
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

    // === MÉTODOS DE CALIBRAÇÃO ===

    /// <summary>
    /// Inicializa handlers da pupila e íris usando parâmetros configuráveis
    /// </summary>
    /// <param name="quantidadeIris">Quantidade de handlers para a íris (mínimo 6)</param>
    /// <param name="quantidadePupila">Quantidade de handlers para a pupila (mínimo 6)</param>
    /// <param name="offsetGraus">Offset angular aplicado a ambos os conjuntos</param>
    public void InicializarHandlers(int? quantidadeIris = null, int? quantidadePupila = null, double offsetGraus = 0)
    {
        if (_atualizandoContagemHandlers)
        {
            return;
        }

        _atualizandoContagemHandlers = true;

        try
        {
            var totalIris = Math.Max(6, quantidadeIris ?? QuantidadeHandlersIris);
            var totalPupila = Math.Max(6, quantidadePupila ?? QuantidadeHandlersPupila);

            LimparHandlers(HandlersPupila);
            LimparHandlers(HandlersIris);

            CriarHandlers(
                HandlersPupila,
                totalPupila,
                CentroPupilaX,
                CentroPupilaY,
                raioHorizontal: RaioPupilaHorizontal,
                raioVertical: RaioPupilaVertical,
                tipo: "Pupila",
                offsetGraus: offsetGraus);

            CriarHandlers(
                HandlersIris,
                totalIris,
                CentroIrisX,
                CentroIrisY,
                raioHorizontal: RaioIrisHorizontal,
                raioVertical: RaioIrisVertical,
                tipo: "Iris",
                offsetGraus: offsetGraus);

            if (QuantidadeHandlersIris != totalIris)
            {
                QuantidadeHandlersIris = totalIris;
            }

            if (QuantidadeHandlersPupila != totalPupila)
            {
                QuantidadeHandlersPupila = totalPupila;
            }

            AtualizarTransformacoesGlobais();

            MapaZoom = 1.0;
            ModoMoverMapa = false;

            RegistrarCalibracao(
                "Handlers inicializados: Pupila={0}, Íris={1}, Offset={2}°",
                HandlersPupila.Count,
                HandlersIris.Count,
                offsetGraus);

            RecordDragEvent(
                DragDebugEventType.HandlerTranslation,
                "Handlers inicializados",
                ConstruirMetricasCentros(),
                ConstruirContextoPadrao());
        }
        finally
        {
            _atualizandoContagemHandlers = false;
        }
    }

    partial void OnQuantidadeHandlersIrisChanged(int value)
    {
        if (_atualizandoContagemHandlers)
        {
            return;
        }

        var clamped = Math.Max(6, value);
        if (clamped != value)
        {
            _atualizandoContagemHandlers = true;
            try
            {
                QuantidadeHandlersIris = clamped;
            }
            finally
            {
                _atualizandoContagemHandlers = false;
            }

            InicializarHandlers(clamped, null);
            return;
        }

        InicializarHandlers(clamped, null);
    }

    partial void OnQuantidadeHandlersPupilaChanged(int value)
    {
        if (_atualizandoContagemHandlers)
        {
            return;
        }

        var clamped = Math.Max(6, value);
        if (clamped != value)
        {
            _atualizandoContagemHandlers = true;
            try
            {
                QuantidadeHandlersPupila = clamped;
            }
            finally
            {
                _atualizandoContagemHandlers = false;
            }

            InicializarHandlers(null, clamped);
            return;
        }

        InicializarHandlers(null, clamped);
    }

    /// <summary>
    /// Cria handlers distribuídos de forma uniforme em torno do centro indicado
    /// </summary>
    private void CriarHandlers(
        ObservableCollection<CalibrationHandler> destino,
        int quantidade,
        double centroX,
        double centroY,
        double raioHorizontal,
        double raioVertical,
        string tipo,
        double offsetGraus)
    {
        if (quantidade <= 0) return;

        var passoAngular = 360.0 / quantidade;

        for (int i = 0; i < quantidade; i++)
        {
            var anguloGraus = NormalizeAngleDegrees(offsetGraus + i * passoAngular);
            var anguloRad = anguloGraus * Math.PI / 180.0;

            // Permitir elipse (ajustes independentes eixo X/Y futuros)
            var x = centroX + raioHorizontal * Math.Cos(anguloRad);
            var y = centroY + raioVertical * Math.Sin(anguloRad);

            destino.Add(new CalibrationHandler
            {
                X = x - 8, // centralizar ellipse 16x16
                Y = y - 8,
                Angulo = anguloGraus,
                Tipo = tipo
            });
        }
    }

    private static double NormalizeAngleDegrees(double angulo)
    {
        while (angulo < 0) angulo += 360;
        while (angulo >= 360) angulo -= 360;
        return angulo;
    }

    private static double NormalizeAngleRadians(double angulo)
    {
        while (angulo < 0) angulo += 2 * Math.PI;
        while (angulo >= 2 * Math.PI) angulo -= 2 * Math.PI;
        return angulo;
    }

    private void LimparHandlers(ObservableCollection<CalibrationHandler> handlers)
    {
        foreach (var handler in handlers)
        {
            handler.PropertyChanged -= OnHandlerPropertyChanged;
        }

        handlers.Clear();
    }

    private void OnHandlersCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (_suspendHandlerUpdates)
        {
            return;
        }

        if (e.OldItems != null)
        {
            foreach (CalibrationHandler handler in e.OldItems)
            {
                handler.PropertyChanged -= OnHandlerPropertyChanged;
            }
        }

        if (e.NewItems != null)
        {
            foreach (CalibrationHandler handler in e.NewItems)
            {
                handler.PropertyChanged += OnHandlerPropertyChanged;
            }
        }

        if (e.Action == NotifyCollectionChangedAction.Reset && sender is IEnumerable<CalibrationHandler> handlers)
        {
            foreach (var handler in handlers)
            {
                handler.PropertyChanged -= OnHandlerPropertyChanged;
                handler.PropertyChanged += OnHandlerPropertyChanged;
            }
        }

        if (_atualizandoContagemHandlers)
        {
            return;
        }

        AtualizarTransformacoesGlobais();
    }

    private void OnHandlerPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_suspendHandlerUpdates)
        {
            return;
        }

        if (_atualizandoContagemHandlers)
        {
            return;
        }

        if (e.PropertyName is nameof(CalibrationHandler.X) or nameof(CalibrationHandler.Y))
        {
            AtualizarTransformacoesGlobais();
        }
    }

    private void AtualizarTransformacoesGlobais()
    {
        _logger.LogDebug($"🔄 [TRANSFORM GLOBAL] Iniciando atualização...");

        AtualizarTransformacaoIris();
        AtualizarTransformacaoPupila();

        if (MapaAtual != null && MostrarMapaIridologico)
        {
            // ⭐ REGRA 1: Não renderizar durante drag ativo (performance + previne esticamento)
            if (_isDragging)
            {
#if DEBUG
                _logger.LogDebug("⏭️ RENDERIZAÇÃO ADIADA - _isDragging = TRUE");
#endif
                // Renderização será feita no EndDrag()
            }
            // ⭐ REGRA 2: Modo "Mover Mapa" SEMPRE usa renderização simples (previne esticamento)
            // Deformação só deve ser usada quando editando handlers MANUALMENTE em modo calibração
            else if (ModoCalibracaoAtivo && !ModoMoverMapa)
            {
#if DEBUG
                _logger.LogDebug("🎨 Renderizando polígonos COM deformação (calibração manual)");
#endif
                RenderizarPoligonosComDeformacao();
            }
            else
            {
#if DEBUG
                _logger.LogDebug("🎨 Renderizando polígonos SEM deformação (mover mapa ou modo normal)");
#if DEBUG
                _logger.LogDebug("🎨 Renderizando polígonos SEM deformação (mover mapa ou modo normal)");
#endif
                RenderizarPoligonos();
            }
        }

        _logger.LogDebug($"✅ [TRANSFORM GLOBAL] Concluída");

        RecordDragEvent(
            DragDebugEventType.ViewModelUpdate,
            "AtualizarTransformacoesGlobais concluída",
            ConstruirMetricasCentros(),
            ConstruirContextoPadrao());
    }

    private void RegistrarCalibracao(string mensagem, params object[] args)
    {
        _logger.LogDebug(mensagem, args);

        try
        {
            var formatado = args?.Length > 0
                ? string.Format(CultureInfo.InvariantCulture, mensagem, args)
                : mensagem;

            Console.WriteLine($"[Calibração] {formatado}");
        }
        catch (FormatException)
        {
            Console.WriteLine($"[Calibração] {mensagem}");
        }
    }

    private void AtualizarTransformacaoIris()
    {
        if (HandlersIris.Count == 0)
        {
            CentroIrisX = 300;
            CentroIrisY = 300;
            RaioIrisHorizontal = RAIO_NOMINAL_IRIS;
            RaioIrisVertical = RAIO_NOMINAL_IRIS;
            RaioIris = RAIO_NOMINAL_IRIS;
            EscalaIrisX = 1.0;
            EscalaIrisY = 1.0;
            _logger.LogDebug($"⚪ [ÍRIS] Sem handlers, valores default aplicados");
            return;
        }

        var pontos = HandlersIris.Select(h => (X: h.X + 8, Y: h.Y + 8)).ToList();

        var centroX = pontos.Average(p => p.X);
        var centroY = pontos.Average(p => p.Y);

        var raioHorizontal = pontos.Max(p => Math.Abs(p.X - centroX));
        var raioVertical = pontos.Max(p => Math.Abs(p.Y - centroY));

        raioHorizontal = Math.Max(1.0, raioHorizontal);
        raioVertical = Math.Max(1.0, raioVertical);

        _logger.LogDebug($"🟢 [ÍRIS] Centro calculado: ({centroX:F2}, {centroY:F2}) - Anterior: ({CentroIrisX:F2}, {CentroIrisY:F2})");
        _logger.LogDebug($"   Raios: H={raioHorizontal:F2}, V={raioVertical:F2}");

        CentroIrisX = centroX;
        CentroIrisY = centroY;
        RaioIrisHorizontal = raioHorizontal;
        RaioIrisVertical = raioVertical;
        RaioIris = (raioHorizontal + raioVertical) / 2.0;
        EscalaIrisX = raioHorizontal / RAIO_NOMINAL_IRIS;
        EscalaIrisY = raioVertical / RAIO_NOMINAL_IRIS;

        RegistrarCalibracao(
            "Íris → Centro=({0:F1},{1:F1}) EscalaX={2:F3} EscalaY={3:F3}",
            CentroIrisX,
            CentroIrisY,
            EscalaIrisX,
            EscalaIrisY);
    }

    private void AtualizarTransformacaoPupila()
    {
        if (HandlersPupila.Count == 0)
        {
            CentroPupilaX = 300;
            CentroPupilaY = 300;
            RaioPupilaHorizontal = RAIO_NOMINAL_PUPILA;
            RaioPupilaVertical = RAIO_NOMINAL_PUPILA;
            RaioPupila = RAIO_NOMINAL_PUPILA;
            EscalaPupilaX = 1.0;
            EscalaPupilaY = 1.0;
            _logger.LogDebug($"⚪ [PUPILA] Sem handlers, valores default aplicados");
            return;
        }

        var pontos = HandlersPupila.Select(h => (X: h.X + 8, Y: h.Y + 8)).ToList();

        var centroX = pontos.Average(p => p.X);
        var centroY = pontos.Average(p => p.Y);

        var raioHorizontal = pontos.Max(p => Math.Abs(p.X - centroX));
        var raioVertical = pontos.Max(p => Math.Abs(p.Y - centroY));

        raioHorizontal = Math.Max(0.5, raioHorizontal);
        raioVertical = Math.Max(0.5, raioVertical);

        _logger.LogDebug($"🔵 [PUPILA] Centro calculado: ({centroX:F2}, {centroY:F2}) - Anterior: ({CentroPupilaX:F2}, {CentroPupilaY:F2})");
        _logger.LogDebug($"   Raios: H={raioHorizontal:F2}, V={raioVertical:F2}");

        CentroPupilaX = centroX;
        CentroPupilaY = centroY;
        RaioPupilaHorizontal = raioHorizontal;
        RaioPupilaVertical = raioVertical;
        RaioPupila = (raioHorizontal + raioVertical) / 2.0;
        EscalaPupilaX = raioHorizontal / RAIO_NOMINAL_PUPILA;
        EscalaPupilaY = raioVertical / RAIO_NOMINAL_PUPILA;

        RegistrarCalibracao(
            "Pupila → Centro=({0:F1},{1:F1}) EscalaX={2:F3} EscalaY={3:F3}",
            CentroPupilaX,
            CentroPupilaY,
            EscalaPupilaX,
            EscalaPupilaY);
    }

    /// <summary>
    /// Reset de calibração: restaura posições padrão
    /// </summary>
    [RelayCommand]
    private void ResetCalibracao()
    {
        CentroPupilaX = 300;
        CentroPupilaY = 300;
        RaioPupila = 54;
        RaioPupilaHorizontal = RAIO_NOMINAL_PUPILA;
        RaioPupilaVertical = RAIO_NOMINAL_PUPILA;

        CentroIrisX = 300;
        CentroIrisY = 300;
        RaioIris = 270;
        RaioIrisHorizontal = RAIO_NOMINAL_IRIS;
        RaioIrisVertical = RAIO_NOMINAL_IRIS;
        EscalaIrisX = 1.0;
        EscalaIrisY = 1.0;
        EscalaPupilaX = 1.0;
        EscalaPupilaY = 1.0;
        MapaZoom = 1.0;
        ModoMoverMapa = false;

        OpacidadeMapa = 50.0;

        InicializarHandlers();

        // Recalcular polígonos
        if (MostrarMapaIridologico && MapaAtual != null)
        {
            RenderizarPoligonos();
        }

        _logger.LogInformation("🔄 Calibração resetada para valores padrão");

        RecordDragEvent(
            DragDebugEventType.ViewModelUpdate,
            "ResetCalibracao",
            ConstruirMetricasCentros(),
            ConstruirContextoPadrao());
    }

    /// <summary>
    /// Translada os handlers (pupila, íris ou ambos) preservando offsets relativos
    /// </summary>
    /// <param name="tipo">"Pupila", "Iris" ou "Ambos"</param>
    /// <param name="deltaX">Deslocamento em X</param>
    /// <param name="deltaY">Deslocamento em Y</param>
    /// <summary>
    /// Inicia sessão de drag - previne renderizações intermédias
    /// ✅ NOVO: Em modo "Mover Mapa", mantém polígonos visíveis para feedback visual em tempo real
    /// </summary>
    public void BeginDrag()
    {
        _isDragging = true;
        _suspendHandlerUpdates = true;  // Layer 2: Suspender PropertyChanged de handlers
        
        // ✅ NOVO: Só oculta polígonos em modo calibração (handlers), não em modo "Mover Mapa"
        if (ModoCalibracaoAtivo && !ModoMoverMapa)
        {
            MostrarPoligonosDuranteArrasto = false;  // ⭐ Layer 3: OCULTAR polígonos durante arrasto (apenas calibração)
#if DEBUG
            _logger.LogDebug("🖱️ [DRAG] INÍCIO - Modo Calibração (polígonos ocultos)");
#endif
        }
        else if (ModoMoverMapa)
        {
            // ✅ Em modo "Mover Mapa", mantém polígonos VISÍVEIS (MostrarPoligonosDuranteArrasto fica true)
#if DEBUG
            _logger.LogDebug("🖱️ [DRAG] INÍCIO - Modo Mover Mapa (polígonos VISÍVEIS)");
#endif
        }
    }

    /// <summary>
    /// Finaliza sessão de drag - força renderização final com valores atualizados
    /// </summary>
    public void EndDrag()
    {
        _isDragging = false;
        _suspendHandlerUpdates = false;  // Layer 2: Reativar PropertyChanged de handlers

#if DEBUG
        _logger.LogDebug("🖱️ [DRAG] FIM - Renderizando posição final...");
#endif

        // Força renderização ANTES de reativar visibilidade (evita frames intermédios)
        if (MapaAtual != null && MostrarMapaIridologico)
        {
            if (ModoCalibracaoAtivo && !ModoMoverMapa)
            {
#if DEBUG
                _logger.LogDebug("🖱️ [DRAG] → Renderizando COM deformação");
#endif
                RenderizarPoligonosComDeformacao();
            }
            else
            {
#if DEBUG
                _logger.LogDebug("🖱️ [DRAG] → Renderizando SEM deformação");
#endif
                RenderizarPoligonos();
            }
        }

        // ⭐ Layer 3: REATIVAR visibilidade APÓS renderização completa
        MostrarPoligonosDuranteArrasto = true;
#if DEBUG
        _logger.LogDebug("🖱️ [DRAG] ✅ Layer 3 reativada - polígonos visíveis");
#endif
    }

    public void TransladarCalibracao(string? tipo, double deltaX, double deltaY)
    {
        if (Math.Abs(deltaX) < 0.001 && Math.Abs(deltaY) < 0.001)
        {
            _logger.LogDebug("⏭️ [TRANSLADAR] Delta muito pequeno, ignorado");
            return;
        }

        var modo = (tipo ?? "Ambos").Trim().ToLowerInvariant();
        if (modo.Contains("í"))
        {
            modo = modo.Replace("í", "i", StringComparison.InvariantCulture);
        }

        _logger.LogDebug($"🔵 [TRANSLADAR] Tipo: {modo}, Delta: ({deltaX:F2}, {deltaY:F2})");
        _logger.LogDebug($"   Centro PRÉ - Pupila: ({CentroPupilaX:F2}, {CentroPupilaY:F2}), Íris: ({CentroIrisX:F2}, {CentroIrisY:F2})");
        _logger.LogDebug($"   Handlers - Pupila: {HandlersPupila.Count}, Íris: {HandlersIris.Count}");

        var contextoPre = ConstruirContextoPadrao();
        contextoPre["modo"] = modo;

        var metricasPre = ConstruirMetricasCentros();
        metricasPre["deltaX"] = deltaX;
        metricasPre["deltaY"] = deltaY;

        RecordDragEvent(
            DragDebugEventType.DragMovePreTransform,
            $"Pré-translação ({modo})",
            metricasPre,
            contextoPre);

        // ⚡ CRÍTICO: Preservar estado anterior de _suspendHandlerUpdates
        // Se já estava suspenso (por BeginDrag), não deve ser reativado no finally
        var previousSuspendState = _suspendHandlerUpdates;
        _suspendHandlerUpdates = true;
        try
        {
            if (modo is "pupila" or "ambos")
            {
                int handlersMovidos = 0;
                foreach (var handler in HandlersPupila)
                {
                    handler.X += deltaX;
                    handler.Y += deltaY;
                    handlersMovidos++;
                }
                _logger.LogDebug($"   ↔️ Movidos {handlersMovidos} handlers de pupila");
            }

            if (modo is "iris" or "ambos")
            {
                int handlersMovidos = 0;
                foreach (var handler in HandlersIris)
                {
                    handler.X += deltaX;
                    handler.Y += deltaY;
                    handlersMovidos++;
                }
                _logger.LogDebug($"   ↔️ Movidos {handlersMovidos} handlers de íris");
            }
        }
        finally
        {
            // ⚡ CRÍTICO: Restaurar estado anterior em vez de forçar false
            _suspendHandlerUpdates = previousSuspendState;
        }

        AtualizarTransformacoesGlobais();

        _logger.LogDebug($"   Centro PÓS - Pupila: ({CentroPupilaX:F2}, {CentroPupilaY:F2}), Íris: ({CentroIrisX:F2}, {CentroIrisY:F2})");

        var contextoPos = ConstruirContextoPadrao();
        contextoPos["modo"] = modo;

        RecordDragEvent(
            DragDebugEventType.DragMovePostTransform,
            $"Pós-translação ({modo})",
            ConstruirMetricasCentros(),
            contextoPos);
    }

    private void AjustarMapaZoom(double novoValor)
    {
        var clamped = Math.Clamp(novoValor, MAPA_ZOOM_MIN, MAPA_ZOOM_MAX);

        if (Math.Abs(clamped - MapaZoom) < 0.0001)
        {
            return;
        }

        double multiplicador = clamped / MapaZoom;
        AplicarEscalaMapa(multiplicador);
        MapaZoom = clamped;
    }

    private void AplicarEscalaMapa(double multiplicador)
    {
        if (Math.Abs(multiplicador - 1.0) < 0.0001)
        {
            return;
        }

        _suspendHandlerUpdates = true;
        try
        {
            if (HandlersPupila.Count > 0)
            {
                var centroX = CentroPupilaX;
                var centroY = CentroPupilaY;

                foreach (var handler in HandlersPupila)
                {
                    double offsetX = (handler.X + 8) - centroX;
                    double offsetY = (handler.Y + 8) - centroY;

                    handler.X = centroX + offsetX * multiplicador - 8;
                    handler.Y = centroY + offsetY * multiplicador - 8;
                }
            }

            if (HandlersIris.Count > 0)
            {
                var centroX = CentroIrisX;
                var centroY = CentroIrisY;

                foreach (var handler in HandlersIris)
                {
                    double offsetX = (handler.X + 8) - centroX;
                    double offsetY = (handler.Y + 8) - centroY;

                    handler.X = centroX + offsetX * multiplicador - 8;
                    handler.Y = centroY + offsetY * multiplicador - 8;
                }
            }
        }
        finally
        {
            _suspendHandlerUpdates = false;
        }

        AtualizarTransformacoesGlobais();
    }

    /// <summary>
    /// Recalcula polígonos com deformação baseada em handlers
    /// (Implementação simplificada - pode ser expandida)
    /// </summary>
    public void RecalcularPoligonosComDeformacao()
    {
        if (MapaAtual == null) return;

        // 🔧 DEFORMAÇÃO COM HANDLERS: Usar posições reais dos handlers para calcular raios deformados
        if (ModoCalibracaoAtivo && (HandlersPupila.Count > 0 || HandlersIris.Count > 0))
        {
            RenderizarPoligonosComDeformacao();
        }
        else
        {
            // Círculos perfeitos (sem calibração)
            RenderizarPoligonos();
        }

        _logger.LogInformation("🔄 Polígonos recalculados com nova calibração");
    }

    /// <summary>
    /// Renderiza polígonos DEFORMADOS usando posições reais dos handlers
    /// </summary>
    private void RenderizarPoligonosComDeformacao()
    {
        if (MapaAtual == null) return;

        PoligonosZonas.Clear();

        var cores = new[] { "#6B8E63", "#9CAF97", "#5B7C99", "#D4A849" };
        var corIndex = 0;

        foreach (var zona in MapaAtual.Zonas)
        {
            // 🎯 NOVA LÓGICA: Interpolar pontos usando handlers
            var poligonosDeformados = InterpolateZoneWithHandlers(zona);

            foreach (var pontos in poligonosDeformados)
            {
                PoligonosZonas.Add(new ZonaPoligono
                {
                    Nome = zona.Nome,
                    Descricao = zona.Descricao,
                    Pontos = pontos,
                    CorPreenchimento = cores[corIndex % cores.Length]
                });
            }

            corIndex++;
        }

        _logger.LogInformation("🎨 Renderizados {Count} polígonos DEFORMADOS", PoligonosZonas.Count);
    }

    /// <summary>
    /// Interpola pontos da zona usando posições reais dos handlers (deformação)
    /// </summary>
    private List<System.Windows.Media.PointCollection> InterpolateZoneWithHandlers(IridologyZone zona, bool aplicarDeformacaoLocal = true)
    {
        var result = new List<System.Windows.Media.PointCollection>();

        foreach (var parte in zona.Partes)
        {
            var pontos = new System.Windows.Media.PointCollection();

            foreach (var coordenada in parte)
            {
                double normalizedRadius = Math.Clamp(coordenada.Raio, 0.0, 1.0);
                double angulo = (coordenada.Angulo + 270.0) * Math.PI / 180.0;
                angulo = NormalizeAngleRadians(angulo);

                var (pesoPupila, pesoIris) = CalcularPesosRadiais(normalizedRadius);

                double raioOriginalIris = normalizedRadius * RAIO_NOMINAL_IRIS;
                double raioOriginalPupila = ConverterRaioParaPupila(normalizedRadius);

                double raioDeformadoIris = raioOriginalIris;
                double raioDeformadoPupila = raioOriginalPupila;

                if (aplicarDeformacaoLocal)
                {
                    if (pesoIris > 0.0001 && HandlersIris.Count > 0)
                    {
                        raioDeformadoIris = InterpolateRadiusFromHandlers(
                            angulo,
                            raioOriginalIris,
                            HandlersIris,
                            CentroIrisX,
                            CentroIrisY,
                            EscalaIrisX,
                            EscalaIrisY,
                            RAIO_NOMINAL_IRIS);
                    }

                    if (pesoPupila > 0.0001 && HandlersPupila.Count > 0)
                    {
                        raioDeformadoPupila = InterpolateRadiusFromHandlers(
                            angulo,
                            raioOriginalPupila,
                            HandlersPupila,
                            CentroPupilaX,
                            CentroPupilaY,
                            EscalaPupilaX,
                            EscalaPupilaY,
                            RAIO_NOMINAL_PUPILA);
                    }
                }

                double raioDeformado = (pesoPupila * raioDeformadoPupila) + (pesoIris * raioDeformadoIris);
                double escalaX = (pesoPupila * EscalaPupilaX) + (pesoIris * EscalaIrisX);
                double escalaY = (pesoPupila * EscalaPupilaY) + (pesoIris * EscalaIrisY);
                double centroX = (pesoPupila * CentroPupilaX) + (pesoIris * CentroIrisX);
                double centroY = (pesoPupila * CentroPupilaY) + (pesoIris * CentroIrisY);

                double raioHorizontal = raioDeformado * escalaX;
                double raioVertical = raioDeformado * escalaY;
                double x = centroX + raioHorizontal * Math.Cos(angulo);
                double y = centroY - raioVertical * Math.Sin(angulo);

                pontos.Add(new System.Windows.Point(x, y));
            }

            if (pontos.Count > 0)
            {
                result.Add(pontos);
            }
        }

        return result;
    }

    /// <summary>
    /// ✅ RAIO NOMINAL FIXO (baseline imutável para cálculo de deformação)
    /// Previne erro de "baseline móvel" onde GetRaioNominal() retorna valor que muda durante drag
    /// </summary>
    private static double GetRaioNominalFixo(string tipo) =>
        tipo == "Pupila" ? RAIO_NOMINAL_PUPILA : RAIO_NOMINAL_IRIS;

    private static (double pesoPupila, double pesoIris) CalcularPesosRadiais(double normalizedRadius)
    {
        double limiteInferior = Math.Clamp(PUPILA_NORMALIZED_THRESHOLD - PUPILA_TRANSITION_WIDTH, 0.0, 1.0);
        double limiteSuperior = Math.Clamp(PUPILA_NORMALIZED_THRESHOLD + PUPILA_TRANSITION_WIDTH, 0.0, 1.0);

        if (normalizedRadius <= limiteInferior)
        {
            return (1.0, 0.0);
        }

        if (normalizedRadius >= limiteSuperior)
        {
            return (0.0, 1.0);
        }

        double intervalo = limiteSuperior - limiteInferior;
        if (intervalo < 1e-6)
        {
            return (0.0, 1.0);
        }

        double pesoIris = Math.Clamp((normalizedRadius - limiteInferior) / intervalo, 0.0, 1.0);
        return (1.0 - pesoIris, pesoIris);
    }

    private static double ConverterRaioParaPupila(double normalizedRadius)
    {
        double fatorNormalizado = PUPILA_NORMALIZED_THRESHOLD <= double.Epsilon
            ? 0.0
            : normalizedRadius / PUPILA_NORMALIZED_THRESHOLD;

        fatorNormalizado = Math.Clamp(fatorNormalizado, 0.0, 1.0);
        return fatorNormalizado * RAIO_NOMINAL_PUPILA;
    }

    /// <summary>
    /// Interpola raio baseado nas posições dos handlers
    /// DEFORMAÇÃO RADIAL: Cada handler afeta zona de ±45° (90° total) com peso gaussiano
    /// FIX CRÍTICO: Eixo Y invertido para compatibilidade WPF (Y cresce para BAIXO)
    /// </summary>
    private double InterpolateRadiusFromHandlers(
        double angulo,
        double raioOriginal,
        ObservableCollection<CalibrationHandler> handlers,
        double centroX,
        double centroY,
        double escalaX,
        double escalaY,
        double raioNominalBase)
    {
        if (handlers.Count == 0) return raioOriginal;

        // Calcular posições e ângulos de todos os handlers
        var handlersComAngulo = handlers
            .Select(h =>
            {
                var escalaNormX = Math.Abs(escalaX) < 1e-6 ? 1.0 : escalaX;
                var escalaNormY = Math.Abs(escalaY) < 1e-6 ? 1.0 : escalaY;

                var dx = (h.X + 8 - centroX) / escalaNormX;
                var dy = (h.Y + 8 - centroY) / escalaNormY;
                // ✅ Orientação WPF: 0° à direita, ângulos positivos no sentido horário
                var anguloHandler = Math.Atan2(dy, dx);

                if (anguloHandler < 0)
                    anguloHandler += 2 * Math.PI;

                var raioHandler = Math.Sqrt(dx * dx + dy * dy);

                return new { Handler = h, Angulo = anguloHandler, Raio = raioHandler };
            })
            .ToList();

        if (handlersComAngulo.Count == 0) return raioOriginal;

        // 🎯 NOVA LÓGICA: SOMA PONDERADA DE TODOS OS HANDLERS
        // Cada handler contribui baseado na distância angular (zona de influência ±45°)
        double somaFatores = 0;
        double somaPesos = 0;

        var passoAngular = (2 * Math.PI) / handlersComAngulo.Count;
        var zonaInfluencia = passoAngular; // ±passo (cobertura contínua em torno do círculo)

        foreach (var h in handlersComAngulo)
        {
            // Calcular diferença angular (considerar wrap-around em 0°/360°)
            double diff = angulo - h.Angulo;

            // Normalizar para [-π, π]
            while (diff > Math.PI) diff -= 2 * Math.PI;
            while (diff < -Math.PI) diff += 2 * Math.PI;

            double diffAbs = Math.Abs(diff);

            if (diffAbs <= zonaInfluencia)
            {
                // Peso suavizado: coseno escalado para chegar a zero na borda da zona de influência
                double peso = Math.Cos((diffAbs / zonaInfluencia) * (Math.PI / 2.0));

                // Fator de deformação deste handler
                double fatorHandler = h.Raio / raioNominalBase;

                somaFatores += fatorHandler * peso;
                somaPesos += peso;
            }
        }

        // Se nenhum handler influencia, usar raio original
        if (somaPesos < 0.0001)
            return raioOriginal;

        // Média ponderada dos fatores
        double fatorDeformacaoFinal = somaFatores / somaPesos;

        // Aplicar deformação ao raio original
        return raioOriginal * fatorDeformacaoFinal;
    }

    /// <summary>
    /// Obtém raio nominal (círculo perfeito) para o tipo de handler
    /// </summary>
    private double GetRaioNominal(string tipo)
    {
        return tipo == "Pupila" ? RaioPupila : RaioIris;
    }

    /// <summary>
    /// Normaliza ângulo para -π a +π
    /// </summary>
    private double NormalizarAngulo(double angulo)
    {
        while (angulo > Math.PI) angulo -= 2 * Math.PI;
        while (angulo < -Math.PI) angulo += 2 * Math.PI;
        return angulo;
    }

    /// <summary>
    /// Observador: quando modo calibração ativa, inicializa handlers
    /// </summary>
    partial void OnModoCalibracaoAtivoChanged(bool value)
    {
        if (value)
        {
            InicializarHandlers();
            _logger.LogInformation("🔧 Modo calibração ATIVADO");
        }
        else
        {
            _logger.LogInformation("🔧 Modo calibração DESATIVADO");
        }
    }
}

