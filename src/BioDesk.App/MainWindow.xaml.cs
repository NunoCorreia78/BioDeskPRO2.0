using System;
using System.Windows;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App
{
    /// <summary>
    /// MainWindow simplificada com navegação funcional
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly INavigationService _navigationService;

        public MainWindow(IServiceProvider serviceProvider, INavigationService navigationService)
        {
            InitializeComponent();
            
            _serviceProvider = serviceProvider;
            _navigationService = navigationService;

            // Registar views
            RegistarViews();

            // Configurar navegação
            _navigationService.NavigationRequested += OnNavigationRequested;

            // Navegar para Dashboard inicial
            _navigationService.NavigateTo("Dashboard");
        }

        private void RegistarViews()
        {
            _navigationService.Register("Dashboard", typeof(Views.DashboardView));
            _navigationService.Register("NovoPaciente", typeof(Views.NovoPacienteView));
            _navigationService.Register("ListaPacientes", typeof(Views.ListaPacientesView));
            _navigationService.Register("FichaPaciente", typeof(Views.FichaPacienteView));
            _navigationService.Register("Consultas", typeof(Views.ConsultasView)); // 🩺 Gestão Consultas
        }

        private void OnNavigationRequested(object? sender, string viewName)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => NavegarPara(viewName));
                return;
            }

            NavegarPara(viewName);
        }

        private void NavegarPara(string viewName)
        {
            try
            {
                // Criar view e viewmodel correspondentes
                object? view = viewName switch
                {
                    "Dashboard" => _serviceProvider.GetRequiredService<Views.DashboardView>(),
                    "NovoPaciente" => _serviceProvider.GetRequiredService<Views.NovoPacienteView>(),
                    "ListaPacientes" => _serviceProvider.GetRequiredService<Views.ListaPacientesView>(),
                    "FichaPaciente" => _serviceProvider.GetRequiredService<Views.FichaPacienteView>(),
                    "Consultas" => _serviceProvider.GetRequiredService<Views.ConsultasView>(), // 🩺 Consultas View
                    _ => null
                };

                if (view == null)
                {
                    MessageBox.Show($"View '{viewName}' não encontrada.", "Erro", 
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Definir DataContext apropriado
                if (view is FrameworkElement fe)
                {
                    fe.DataContext = viewName switch
                    {
                        "Dashboard" => _serviceProvider.GetRequiredService<DashboardViewModel>(),
                        "NovoPaciente" => _serviceProvider.GetRequiredService<NovoPacienteViewModel>(),
                        "ListaPacientes" => _serviceProvider.GetRequiredService<ListaPacientesViewModel>(),
                        "FichaPaciente" => _serviceProvider.GetRequiredService<FichaPacienteViewModel>(),
                        "Consultas" => _serviceProvider.GetRequiredService<ConsultasViewModel>(), // 🩺 Consultas ViewModel
                        _ => null
                    };

                    // Atualizar conteúdo
                    ContentArea.Content = fe;

                    // Carregar dados async se necessário
                    if (fe.DataContext is DashboardViewModel dashVm)
                    {
                        _ = dashVm.CarregarDadosAsync();
                    }
                    else if (fe.DataContext is ListaPacientesViewModel listaVm)
                    {
                        _ = listaVm.CarregarDadosAsync();
                    }
                    else if (fe.DataContext is ConsultasViewModel consultasVm) // 🩺 Carregar Consultas
                    {
                        _ = consultasVm.CarregarDadosAsync();
                    }
                    else if (fe.DataContext is FichaPacienteViewModel fichaVm) // 🩺 Forçar reload do paciente ativo
                    {
                        // Forçar carregamento do paciente ativo (fix para problema de navegação)
                        var pacienteAtivo = _serviceProvider.GetRequiredService<IPacienteService>().GetPacienteAtivo();
                        if (pacienteAtivo != null)
                        {
                            fichaVm.CarregarPaciente(pacienteAtivo);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erro ao navegar: {ex.Message}", "Erro", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}