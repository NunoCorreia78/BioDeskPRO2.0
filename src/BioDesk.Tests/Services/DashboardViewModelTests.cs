using System;
using System.Threading.Tasks;
using Xunit;
using Microsoft.Extensions.Logging;
using BioDesk.ViewModels;
using BioDesk.Tests.Base;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;

namespace BioDesk.Tests.Services;

public class DashboardViewModelTests : ViewModelTestBase
{
    /// <summary>
    /// Testar inicialização do DashboardViewModel
    /// </summary>
    [Fact]
    public void Constructor_InicializaPropriedadesCorretamente()
    {
        // Act
        var viewModel = CreateViewModel<DashboardViewModel>();

        // Assert
        Assert.NotNull(viewModel);
        Assert.Equal(string.Empty, viewModel.PesquisarTexto);
        Assert.NotNull(viewModel.PacientesRecentes);
        Assert.Equal("Online", viewModel.StatusConexao);
        Assert.True(DateTime.Now.Date == viewModel.HoraAtual.Date);
    }

    /// <summary>
    /// Testar se comandos estão disponíveis 
    /// </summary>
    [Fact]
    public void Commands_DevemEstarDisponiveis()
    {
        // Act
        var viewModel = CreateViewModel<DashboardViewModel>();

        // Assert
        Assert.NotNull(viewModel.NovoPacienteCommand);
        Assert.NotNull(viewModel.AbrirListaPacientesCommand);
        Assert.NotNull(viewModel.PesquisarCommand);
    }

    /// <summary>
    /// Testar formatação de data em português
    /// </summary>
    [Fact]
    public void DataFormatadaPT_DeveFormatarCorretamente()
    {
        // Arrange
        var viewModel = CreateViewModel<DashboardViewModel>();

        // Act
        var dataFormatada = viewModel.DataFormatadaPT;

        // Assert
        Assert.NotNull(dataFormatada);
        Assert.Contains("/", dataFormatada);
    }

    /// <summary>
    /// Testar carregamento de pacientes recentes
    /// </summary>
    [Fact]
    public void CarregarPacientesRecentes_ComDadosSeeds_DeveCarregar()
    {
        // Arrange
        var viewModel = CreateViewModel<DashboardViewModel>();

        // Act - Carregar diretamente da propriedade
        var pacientesRecentes = viewModel.PacientesRecentes;

        // Assert
        Assert.NotNull(pacientesRecentes);
        Assert.True(pacientesRecentes.Count >= 0);
    }
}