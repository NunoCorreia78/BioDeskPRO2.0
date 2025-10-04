using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Media;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Models;
using BioDesk.Services;
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

    [ObservableProperty]
    private Paciente? _pacienteAtual;

    [ObservableProperty]
    private ObservableCollection<IrisImagem> _irisImagens = new();

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
    /// Handlers da pupila (8 pontos no círculo interno)
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<CalibrationHandler> _handlersPupila = new();

    /// <summary>
    /// Handlers da íris (8 pontos no círculo externo)
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<CalibrationHandler> _handlersIris = new();

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

    public IrisdiagnosticoViewModel(
        IUnitOfWork unitOfWork,
        ILogger<IrisdiagnosticoViewModel> logger,
        IIridologyService iridologyService)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _iridologyService = iridologyService ?? throw new ArgumentNullException(nameof(iridologyService));
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
            var nomePaciente = PacienteAtual.NomeCompleto.Replace(" ", "_"); // Remover espaços
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
            var nomePaciente = PacienteAtual.NomeCompleto.Replace(" ", "_");
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
        if (MapaAtual == null) return;

        PoligonosZonas.Clear();

        // NOVO: Usar método de canvas fixo (600x600px)
        var cores = new[] { "#6B8E63", "#9CAF97", "#5B7C99", "#D4A849" }; // Paleta terrosa
        var corIndex = 0;

        foreach (var zona in MapaAtual.Zonas)
        {
            // Usar método dedicado para canvas fixo
            var poligonosWpf = _iridologyService.ConverterZonaParaPoligonosCanvasFixo(zona, canvasWidth: 600, canvasHeight: 600);

            foreach (var pontos in poligonosWpf)
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

        _logger.LogInformation("🎨 Renderizados {Count} polígonos para {Zonas} zonas",
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
    /// Inicializa handlers da pupila e íris (8 pontos cada)
    /// </summary>
    public void InicializarHandlers()
    {
        HandlersPupila.Clear();
        HandlersIris.Clear();

        // 8 handlers uniformemente espaçados (0°, 45°, 90°, 135°, 180°, 225°, 270°, 315°)
        for (int i = 0; i < 8; i++)
        {
            double angulo = i * 45; // 0, 45, 90, ...

            // Handler da PUPILA
            double anguloRad = angulo * Math.PI / 180.0;
            double xPupila = CentroPupilaX + RaioPupila * Math.Cos(anguloRad) - 8; // -8 para centralizar ellipse 16x16
            double yPupila = CentroPupilaY + RaioPupila * Math.Sin(anguloRad) - 8;

            HandlersPupila.Add(new CalibrationHandler
            {
                X = xPupila,
                Y = yPupila,
                Angulo = angulo,
                Tipo = "Pupila"
            });

            // Handler da ÍRIS
            double xIris = CentroIrisX + RaioIris * Math.Cos(anguloRad) - 8; // -8 para centralizar
            double yIris = CentroIrisY + RaioIris * Math.Sin(anguloRad) - 8;

            HandlersIris.Add(new CalibrationHandler
            {
                X = xIris,
                Y = yIris,
                Angulo = angulo,
                Tipo = "Iris"
            });
        }

        _logger.LogInformation("✅ Handlers inicializados: {Pupila} pupila, {Iris} íris", 
            HandlersPupila.Count, HandlersIris.Count);
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

        CentroIrisX = 300;
        CentroIrisY = 300;
        RaioIris = 270;

        OpacidadeMapa = 50.0;

        InicializarHandlers();

        // Recalcular polígonos
        if (MostrarMapaIridologico && MapaAtual != null)
        {
            RenderizarPoligonos();
        }

        _logger.LogInformation("🔄 Calibração resetada para valores padrão");
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
    private List<System.Windows.Media.PointCollection> InterpolateZoneWithHandlers(IridologyZone zona)
    {
        var result = new List<System.Windows.Media.PointCollection>();

        // Calcular raio médio da zona baseado nos pontos
        double raioMedioZona = 100.0; // Default
        if (zona.Partes.Count > 0 && zona.Partes[0].Count > 0)
        {
            raioMedioZona = zona.Partes[0].Average(p => p.Raio) * 300.0; // Raio normalizado * metade canvas
        }

        // Usar handlers da pupila se raio < threshold, senão íris
        var handlers = raioMedioZona < 80 ? HandlersPupila : HandlersIris;
        
        // 🔧 CORREÇÃO CRÍTICA: Usar o centro REAL dos handlers (não fixo 300,300)
        var zonaCentroX = raioMedioZona < 80 ? CentroPupilaX : CentroIrisX;
        var zonaCentroY = raioMedioZona < 80 ? CentroPupilaY : CentroIrisY;

        if (handlers.Count == 0)
        {
            // Fallback: usar conversão normal se não há handlers
            return _iridologyService.ConverterZonaParaPoligonosCanvasFixo(zona, 600, 600);
        }

        // Criar polígono deformado interpolando entre handlers
        foreach (var parte in zona.Partes)
        {
            var pontos = new System.Windows.Media.PointCollection();

            foreach (var coordenada in parte)
            {
                // Converter coordenada polar (ângulo, raio) para cartesiano DEFORMADO
                double angulo = coordenada.Angulo * Math.PI / 180.0;
                double raioOriginal = coordenada.Raio * 300.0; // Raio normalizado → pixels

                // 🎯 INTERPOLAÇÃO: Encontrar raio deformado baseado nos handlers mais próximos
                double raioDeformado = InterpolateRadiusFromHandlers(angulo, raioOriginal, handlers, zonaCentroX, zonaCentroY);

                // Converter para cartesiano com raio deformado
                double x = zonaCentroX + raioDeformado * Math.Cos(angulo);
                double y = zonaCentroY + raioDeformado * Math.Sin(angulo);

                pontos.Add(new System.Windows.Point(x, y));
            }

            if (pontos.Count > 0)
                result.Add(pontos);
        }

        return result;
    }

    /// <summary>
    /// Interpola raio baseado nas posições dos handlers
    /// DEFORMAÇÃO LOCAL: Cada handler estica/encolhe sua zona (±45°)
    /// </summary>
    private double InterpolateRadiusFromHandlers(double angulo, double raioOriginal, ObservableCollection<CalibrationHandler> handlers, double centroX, double centroY)
    {
        if (handlers.Count == 0) return raioOriginal;

        // Encontrar os 2 handlers adjacentes ao ângulo (antes e depois)
        var handlersComAngulo = handlers
            .Select(h =>
            {
                var dx = h.X + 8 - centroX;
                var dy = h.Y + 8 - centroY;
                var anguloHandler = Math.Atan2(dy, dx);
                var raioHandler = Math.Sqrt(dx * dx + dy * dy);
                var diferencaAngulo = NormalizarAngulo(angulo - anguloHandler);
                return new { Handler = h, Angulo = anguloHandler, Raio = raioHandler, Diferenca = diferencaAngulo };
            })
            .OrderBy(h => h.Angulo)
            .ToList();

        if (handlersComAngulo.Count == 0) return raioOriginal;

        // Encontrar handler ANTERIOR (ângulo menor ou igual)
        var handlerAnterior = handlersComAngulo.LastOrDefault(h => h.Angulo <= angulo) 
                              ?? handlersComAngulo[^1]; // Wrap-around

        // Encontrar handler POSTERIOR (ângulo maior)
        var handlerPosterior = handlersComAngulo.FirstOrDefault(h => h.Angulo > angulo) 
                               ?? handlersComAngulo[0]; // Wrap-around

        // Calcular raio nominal (círculo perfeito) para comparação
        var raioNominal = GetRaioNominal(handlerAnterior.Handler.Tipo);

        // Fatores de deformação de cada handler (quanto esticou/encolheu)
        var fatorAnterior = handlerAnterior.Raio / raioNominal;
        var fatorPosterior = handlerPosterior.Raio / raioNominal;

        // Interpolar entre os 2 handlers com base na posição angular
        var anguloAnterior = handlerAnterior.Angulo;
        var anguloPosterior = handlerPosterior.Angulo;

        // Ajustar wrap-around (0°/360°)
        if (anguloPosterior < anguloAnterior)
            anguloPosterior += 2 * Math.PI;
        if (angulo < anguloAnterior)
            angulo += 2 * Math.PI;

        // Fator de interpolação (0.0 = anterior, 1.0 = posterior)
        var rangeAngulo = anguloPosterior - anguloAnterior;
        var t = rangeAngulo > 0.0001 ? (angulo - anguloAnterior) / rangeAngulo : 0.5;
        t = Math.Clamp(t, 0, 1);

        // Interpolar o fator de deformação entre os 2 handlers
        var fatorDeformacao = fatorAnterior * (1 - t) + fatorPosterior * t;

        // Aplicar deformação ao raio original
        return raioOriginal * fatorDeformacao;
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

