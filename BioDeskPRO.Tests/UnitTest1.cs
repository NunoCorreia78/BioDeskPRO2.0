using Microsoft.EntityFrameworkCore;
using BioDeskPRO.Data;
using BioDeskPRO.Models;
using BioDeskPRO.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace BioDeskPRO.Tests;

public class PatientServiceIntegrationTests : IDisposable
{
    private readonly BioDeskContext _context;
    private readonly PatientService _patientService;
    private readonly Mock<ILogger<PatientService>> _mockLogger;

    public PatientServiceIntegrationTests()
    {
        var options = new DbContextOptionsBuilder<BioDeskContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new BioDeskContext(options);
        _mockLogger = new Mock<ILogger<PatientService>>();
        _patientService = new PatientService(_context, _mockLogger.Object);

        // Initialize database without seeded data to avoid conflicts
        _context.Database.EnsureCreated();
    }

    [Fact]
    public async Task ValidatePatientDataAsync_ValidPatient_ReturnsSuccess()
    {
        // Arrange
        var patient = new Patient
        {
            FullName = "João Silva",
            DateOfBirth = new DateTime(1980, 5, 15),
            CivilStatus = "Solteiro",
            Phone = "123456789",
            Email = "joao@email.com",
            HowFoundClinic = "Google"
        };

        // Act
        var result = await _patientService.ValidatePatientDataAsync(patient);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task ValidatePatientDataAsync_InvalidEmail_ReturnsFailure()
    {
        // Arrange
        var patient = new Patient
        {
            FullName = "Maria Silva",
            DateOfBirth = new DateTime(1985, 3, 20),
            Email = "invalid-email"
        };

        // Act
        var result = await _patientService.ValidatePatientDataAsync(patient);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("Invalid email format", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidatePatientDataAsync_EmptyName_ReturnsFailure()
    {
        // Arrange
        var patient = new Patient
        {
            FullName = "",
            DateOfBirth = new DateTime(1990, 1, 1)
        };

        // Act
        var result = await _patientService.ValidatePatientDataAsync(patient);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("Full name is required", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidatePatientDataAsync_FutureDateOfBirth_ReturnsFailure()
    {
        // Arrange
        var patient = new Patient
        {
            FullName = "Test Patient",
            DateOfBirth = DateTime.Today.AddDays(1)
        };

        // Act
        var result = await _patientService.ValidatePatientDataAsync(patient);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("Date of birth cannot be in the future", result.ErrorMessage);
    }

    [Fact]
    public async Task GetAllPatientsAsync_EmptyDatabase_ReturnsEmptyList()
    {
        // Act
        var result = await _patientService.GetAllPatientsAsync();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Data);
        Assert.Empty(result.Data);
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}