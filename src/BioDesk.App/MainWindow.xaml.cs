using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using BioDesk.Services.Navigation;
using BioDesk.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace BioDesk.App
{
    /// <summary>
    /// MainWindow simplificada com navegação funcional
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly INavigationService _navigationService;
        private readonly ILogger<MainWindow> _logger;
        private readonly DispatcherTimer _timer;
        private DateTime _dataAtual;

        public DateTime DataAtual
        {
            get => _dataAtual;
            set
            {
                _dataAtual = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public MainWindow(IServiceProvider serviceProvider, INavigationService navigationService, ILogger<MainWindow> logger)
        {
            InitializeComponent();

            _serviceProvider = serviceProvider;
            _navigationService = navigationService;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Configurar DataContext para binding do relógio
            DataContext = this;

            // Inicializar timer para atualizar relógio
            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _timer.Tick += (s, e) => DataAtual = DateTime.Now;
            _timer.Start();
            DataAtual = DateTime.Now;

            _logger.LogInformation("🚀 MainWindow iniciando...");

            // Registar views
            RegistarViews();

            // Configurar navegação
            _navigationService.NavigationRequested += OnNavigationRequested;

            // Navegar para Dashboard inicial
            _logger.LogInformation("📍 Navegando para Dashboard inicial...");
            _navigationService.NavigateTo("Dashboard");
        }

        private void RegistarViews()
        {
            _logger.LogInformation("🔧 Registrando views no sistema de navegação...");

            // Sistema limpo - views existentes + FichaPaciente + ListaPacientes
            _navigationService.Register("Dashboard", typeof(Views.DashboardView));
            _navigationService.Register("Consultas", typeof(Views.ConsultasView));
            _navigationService.Register("FichaPaciente", typeof(Views.FichaPacienteView));
            _navigationService.Register("NovoPaciente", typeof(Views.FichaPacienteView)); // Alias para criar novo
            _navigationService.Register("ListaPacientes", typeof(Views.ListaPacientesView)); // ✅ NOVO

            _logger.LogInformation("✅ Views registradas: Dashboard, Consultas, FichaPaciente, ListaPacientes");
        }

        private void OnNavigationRequested(object? sender, string viewName)
        {
            _logger.LogInformation("📡 OnNavigationRequested chamado para '{ViewName}'", viewName);

            if (!Dispatcher.CheckAccess())
            {
                _logger.LogInformation("⚡ Invocando no Dispatcher thread...");
                Dispatcher.Invoke(() => NavegarPara(viewName));
                return;
            }

            NavegarPara(viewName);
        }

        private void MainWindow_Closing(object? sender, CancelEventArgs e)
        {
            try
            {
                _logger.LogInformation("🛑 MainWindow_Closing: Verificando alterações não guardadas...");

                // Encontrar ContentControl na árvore visual
                var contentControl = this.FindName("ContentArea") as ContentControl;
                if (contentControl == null)
                {
                    _logger.LogWarning("⚠️ ContentArea não encontrado");
                    return;
                }

                // Verificar se FichaPacienteViewModel está ativo e tem alterações
                if (contentControl.Content is FrameworkElement fe &&
                    fe.DataContext is FichaPacienteViewModel vm &&
                    vm.IsDirty)
                {
                    _logger.LogWarning("⚠️ IsDirty detectado! Mostrando diálogo de confirmação...");

                    var result = MessageBox.Show(
                        "Tem alterações não guardadas no paciente atual.\n\n" +
                        "Deseja guardar antes de sair?",
                        "⚠️ Alterações Pendentes",
                        MessageBoxButton.YesNoCancel,
                        MessageBoxImage.Warning);

                    switch (result)
                    {
                        case MessageBoxResult.Yes:
                            _logger.LogInformation("✅ Utilizador escolheu guardar alterações");
                            // Guardar automaticamente
                            _ = vm.GuardarCompletoCommand.ExecuteAsync(null);
                            _logger.LogInformation("✅ Alterações guardadas com sucesso");
                            break;

                        case MessageBoxResult.No:
                            _logger.LogInformation("⚠️ Utilizador descartou alterações");
                            // Descartar alterações e sair
                            break;

                        case MessageBoxResult.Cancel:
                            _logger.LogInformation("❌ Utilizador cancelou o fecho");
                            e.Cancel = true; // Cancelar fecho da aplicação
                            break;
                    }
                }
                else
                {
                    _logger.LogInformation("✅ Nenhuma alteração pendente detectada");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "💥 Erro ao verificar alterações pendentes no fecho");
                // Permitir fecho mesmo com erro
            }
        }

        private void NavegarPara(string viewName)
        {
            try
            {
                _logger.LogInformation("🏗️ NavegarPara('{ViewName}') - criando view...", viewName);

                // Criar view e viewmodel correspondentes
                object? view = viewName switch
                {
                    "Dashboard" => _serviceProvider.GetRequiredService<Views.DashboardView>(),
                    "Consultas" => _serviceProvider.GetRequiredService<Views.ConsultasView>(),
                    "FichaPaciente" => _serviceProvider.GetRequiredService<Views.FichaPacienteView>(),
                    "NovoPaciente" => _serviceProvider.GetRequiredService<Views.FichaPacienteView>(),
                    "ListaPacientes" => _serviceProvider.GetRequiredService<Views.ListaPacientesView>(), // ✅ ADICIONADO
                    _ => null
                };

                if (view == null)
                {
                    _logger.LogError("❌ View '{ViewName}' não pôde ser criada", viewName);
                    MessageBox.Show($"View '{viewName}' não encontrada.", "Erro",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _logger.LogInformation("✅ View '{ViewName}' criada, tipo: {ViewType}", viewName, view.GetType().Name);

                // Definir DataContext apropriado
                if (view is FrameworkElement fe)
                {
                    _logger.LogInformation("🎯 Definindo DataContext para '{ViewName}'...", viewName);

                    // Sistema limpo - Dashboard + FichaPaciente + ListaPacientes
                    fe.DataContext = viewName switch
                    {
                        "Dashboard" => _serviceProvider.GetRequiredService<DashboardViewModel>(),
                        "FichaPaciente" => _serviceProvider.GetRequiredService<FichaPacienteViewModel>(),
                        "NovoPaciente" => _serviceProvider.GetRequiredService<FichaPacienteViewModel>(),
                        "ListaPacientes" => _serviceProvider.GetRequiredService<ListaPacientesViewModel>(), // ✅ ADICIONADO
                        "Consultas" => _serviceProvider.GetRequiredService<DashboardViewModel>(), // Fallback para Dashboard
                        _ => _serviceProvider.GetRequiredService<DashboardViewModel>() // Fallback para Dashboard
                    };

                    _logger.LogInformation("✅ DataContext definido para '{ViewName}', tipo: {DataContextType}",
                        viewName, fe.DataContext?.GetType().Name ?? "null");

                    // Atualizar conteúdo
                    _logger.LogInformation("🔄 Atualizando ContentArea.Content...");
                    var contentArea = this.FindName("ContentArea") as ContentControl;
                    if (contentArea != null)
                    {
                        contentArea.Content = fe;
                    }

                    _logger.LogInformation("✅ Navegação para '{ViewName}' concluída com sucesso", viewName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "💥 ERRO CRÍTICO ao navegar para '{ViewName}': {Message}", viewName, ex.Message);
                _logger.LogError("Stack trace completo: {StackTrace}", ex.StackTrace);

                MessageBox.Show($"Erro ao navegar: {ex.Message}", "Erro",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Atalhos de teclado globais
        /// Ctrl+N = Novo Paciente | Ctrl+S = Guardar | Ctrl+L = Lista Pacientes | Ctrl+D = Dashboard
        /// </summary>
        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            try
            {
                // Ctrl+N → Criar Novo Paciente
                if (e.Key == Key.N && Keyboard.Modifiers == ModifierKeys.Control)
                {
                    _logger.LogInformation("⌨️ Atalho Ctrl+N detectado - Navegando para Novo Paciente");
                    _navigationService.NavigateTo("NovoPaciente");
                    e.Handled = true;
                    return;
                }

                // Ctrl+L → Lista de Pacientes
                if (e.Key == Key.L && Keyboard.Modifiers == ModifierKeys.Control)
                {
                    _logger.LogInformation("⌨️ Atalho Ctrl+L detectado - Navegando para Lista de Pacientes");
                    _navigationService.NavigateTo("ListaPacientes");
                    e.Handled = true;
                    return;
                }

                // Ctrl+D → Dashboard
                if (e.Key == Key.D && Keyboard.Modifiers == ModifierKeys.Control)
                {
                    _logger.LogInformation("⌨️ Atalho Ctrl+D detectado - Navegando para Dashboard");
                    _navigationService.NavigateTo("Dashboard");
                    e.Handled = true;
                    return;
                }

                // Ctrl+S → Guardar (se estiver em FichaPaciente)
                if (e.Key == Key.S && Keyboard.Modifiers == ModifierKeys.Control)
                {
                    _logger.LogInformation("⌨️ Atalho Ctrl+S detectado - Tentando guardar");

                    var contentControl = this.FindName("ContentArea") as ContentControl;
                    if (contentControl?.Content is FrameworkElement fe &&
                        fe.DataContext is FichaPacienteViewModel vm)
                    {
                        _logger.LogInformation("✅ FichaPacienteViewModel detectado - Executando GuardarCompletoCommand");
                        _ = vm.GuardarCompletoCommand.ExecuteAsync(null);
                        e.Handled = true;
                    }
                    else
                    {
                        _logger.LogInformation("⚠️ Ctrl+S pressionado mas não está em FichaPaciente");
                    }
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "💥 Erro ao processar atalho de teclado");
            }
        }
    }
}
