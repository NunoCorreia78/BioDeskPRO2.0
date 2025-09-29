using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
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

            // Sistema limpo - views existentes + FichaPaciente
            _navigationService.Register("Dashboard", typeof(Views.DashboardView));
            _navigationService.Register("Consultas", typeof(Views.ConsultasView));
            _navigationService.Register("FichaPaciente", typeof(Views.FichaPacienteView));

            _logger.LogInformation("✅ Views registradas: Dashboard, Consultas, FichaPaciente");
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

                    // Sistema limpo - Dashboard + FichaPaciente
                    fe.DataContext = viewName switch
                    {
                        "Dashboard" => _serviceProvider.GetRequiredService<DashboardViewModel>(),
                        "FichaPaciente" => _serviceProvider.GetRequiredService<FichaPacienteViewModel>(),
                        "Consultas" => _serviceProvider.GetRequiredService<DashboardViewModel>(), // Fallback para Dashboard
                        _ => _serviceProvider.GetRequiredService<DashboardViewModel>() // Fallback para Dashboard
                    };

                    _logger.LogInformation("✅ DataContext definido para '{ViewName}', tipo: {DataContextType}",
                        viewName, fe.DataContext?.GetType().Name ?? "null");

                    // Atualizar conteúdo
                    _logger.LogInformation("🔄 Atualizando ContentArea.Content...");
                    ContentArea.Content = fe;

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
    }
}
