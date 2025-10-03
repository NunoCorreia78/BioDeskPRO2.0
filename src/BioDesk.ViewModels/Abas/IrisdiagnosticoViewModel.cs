using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
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

    public IrisdiagnosticoViewModel(
        IUnitOfWork unitOfWork,
        ILogger<IrisdiagnosticoViewModel> logger)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        // ⚡ LOG MANUAL PARA FICHEIRO (ILogger não funciona!)
        LogManual("📝 IrisdiagnosticoViewModel CONSTRUTOR chamado!");
    }
    
    // ⚡ MÉTODO AUXILIAR PARA LOG MANUAL
    private void LogManual(string mensagem)
    {
        try
        {
            var logFile = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "BioDeskPro2", "LOGS_DEBUG.txt"
            );
            var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            var linha = $"[{timestamp}] {mensagem}\n";
            System.IO.File.AppendAllText(logFile, linha);
        }
        catch { /* Ignorar erros de log */ }
    }

    /// <summary>
    /// Carrega dados do paciente (chamado pelo FichaPacienteViewModel)
    /// </summary>
    public async Task CarregarDadosAsync(Paciente paciente)
    {
        LogManual("🔍 DEBUG: CarregarDadosAsync INICIADO");
        _logger.LogInformation("🔍 DEBUG: CarregarDadosAsync INICIADO");
        
        if (paciente == null)
        {
            LogManual("⚠️ CarregarDadosAsync: Paciente é NULL");
            _logger.LogWarning("⚠️ Tentativa de carregar dados com paciente nulo");
            return;
        }

        LogManual($"🔍 DEBUG: Paciente recebido: ID={paciente.Id}, Nome={paciente.NomeCompleto}");
        _logger.LogInformation("🔍 DEBUG: Paciente recebido: ID={Id}, Nome={Nome}", paciente.Id, paciente.NomeCompleto);

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
            LogManual($"🔍 CarregarImagensAsync: Paciente ID={PacienteAtual.Id}, Nome={PacienteAtual.NomeCompleto}");
            _logger.LogInformation("🔍 CarregarImagensAsync: Paciente ID={Id}, Nome={Nome}", PacienteAtual.Id, PacienteAtual.NomeCompleto);

            var todasImagens = await _unitOfWork.IrisImagens.GetAllAsync();
            LogManual($"🔍 Total de imagens na BD: {todasImagens.Count()}");
            _logger.LogInformation("🔍 Total de imagens na BD: {Count}", todasImagens.Count());

            var imagensDoPaciente = todasImagens
                .Where(i => i.PacienteId == PacienteAtual.Id)
                .OrderByDescending(i => i.DataCaptura)
                .ToList();

            LogManual($"🔍 Imagens filtradas para Paciente {PacienteAtual.Id}: {imagensDoPaciente.Count}");
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
                LogManual("❌ Remoção cancelada pelo utilizador");
                _logger.LogInformation("❌ Remoção de imagem cancelada pelo utilizador");
                return;
            }

            LogManual("✅ Utilizador confirmou remoção. Iniciando processo...");
            _logger.LogInformation("✅ Utilizador confirmou remoção. Iniciando processo...");

            IsLoading = true;
            ErrorMessage = null;

            var imagemId = IrisImagemSelecionada.Id;
            var caminhoImagem = IrisImagemSelecionada.CaminhoImagem;

            LogManual($"🔍 ID da imagem: {imagemId}, Caminho: {caminhoImagem}");
            _logger.LogInformation($"🔍 ID da imagem: {imagemId}, Caminho: {caminhoImagem}");

            // 🔓 Limpar seleção para liberar binding (converter já carregou em memória)
            LogManual("🔓 Limpando seleção para liberar referência...");
            IrisImagemSelecionada = null;
            LogManual("✅ Seleção limpa");

            // 2️⃣ Remover arquivo físico (se existir)
            if (System.IO.File.Exists(caminhoImagem))
            {
                LogManual($"🗑️ Arquivo existe, deletando: {caminhoImagem}");
                System.IO.File.Delete(caminhoImagem);
                LogManual("✅ Arquivo físico DELETADO com sucesso");
                _logger.LogInformation("🗑️ Arquivo físico removido: {Caminho}", caminhoImagem);
            }
            else
            {
                LogManual($"⚠️ Arquivo físico NÃO EXISTE: {caminhoImagem}");
                _logger.LogWarning("⚠️ Arquivo físico não encontrado: {Caminho}", caminhoImagem);
            }

            // 3️⃣ Remover do banco de dados (cascade delete remove IrisMarcas automaticamente)
            LogManual($"🔍 Buscando entidade na BD pelo ID {imagemId}...");
            var imagemParaRemover = await _unitOfWork.IrisImagens.GetByIdAsync(imagemId);
            
            if (imagemParaRemover == null)
            {
                LogManual($"❌ ERRO: Imagem ID {imagemId} não encontrada na BD!");
                ErrorMessage = "Imagem não encontrada na base de dados.";
                return;
            }

            LogManual($"✅ Entidade encontrada: Olho={imagemParaRemover.Olho}, PacienteId={imagemParaRemover.PacienteId}");
            LogManual($"🔍 Chamando _unitOfWork.IrisImagens.Remove para ID {imagemId}");
            _unitOfWork.IrisImagens.Remove(imagemParaRemover);
            LogManual("✅ Remove() executado, entidade marcada para remoção");

            LogManual("🔍 Salvando mudanças na BD...");
            _logger.LogInformation("🔍 Salvando mudanças na BD...");
            await _unitOfWork.SaveChangesAsync();

            LogManual($"✅ Imagem removida da BD: ID {imagemId}");
            _logger.LogInformation("✅ Imagem de íris removida da BD: ID {Id}", imagemId);

            // 4️⃣ Recarregar lista (seleção já foi limpa antes de deletar ficheiro)
            LogManual("🔍 Recarregando lista de imagens...");
            _logger.LogInformation("🔍 Recarregando lista de imagens...");
            await CarregarImagensAsync();
            LogManual("✅ Lista recarregada! RemoverImagemAsync COMPLETO");
        }
        catch (Exception ex)
        {
            LogManual($"❌❌❌ EXCEÇÃO CAPTURADA: {ex.GetType().Name}");
            LogManual($"Mensagem: {ex.Message}");
            LogManual($"StackTrace: {ex.StackTrace}");
            _logger.LogError(ex, "❌ Erro ao remover imagem de íris");
            ErrorMessage = $"Erro ao remover imagem: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
            LogManual("🏁 RemoverImagemAsync FINALIZADO (finally block)");
        }
    }

    private bool CanRemoverImagem()
    {
        var pode = IrisImagemSelecionada != null;
        _logger.LogInformation($"🔍 DEBUG: CanRemoverImagem chamado! IrisImagemSelecionada={(IrisImagemSelecionada?.Olho ?? "NULL")}, Pode={pode}");
        return pode;
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
            // TODO: Mostrar dialog para editar observações
            // Por agora, apenas log
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
}
