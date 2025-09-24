using Xunit;
using BioDesk.ViewModels;
using BioDesk.Tests.Base;

namespace BioDesk.Tests.Services;

public class NovoPacienteViewModelTests : ViewModelTestBase
{
    /// <summary>
    /// Testar inicialização do NovoPacienteViewModel (stub)
    /// </summary>
    [Fact]
    public void Constructor_InicializaCorretamente()
    {
        // Act
        var viewModel = new NovoPacienteViewModel();

        // Assert
        Assert.NotNull(viewModel);
    }
}