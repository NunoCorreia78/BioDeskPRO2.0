using BioDeskPRO.Models;

namespace BioDeskPRO.Tests;

public class PatientModelTests
{
    [Fact]
    public void Patient_AgeCalculation_ReturnsCorrectAge()
    {
        // Arrange
        var birthDate = new DateTime(1980, 5, 15);
        var patient = new Patient { DateOfBirth = birthDate };

        // Act
        var age = patient.Age;

        // Assert
        var expectedAge = DateTime.Today.Year - birthDate.Year;
        if (birthDate.Date > DateTime.Today.AddYears(-expectedAge))
            expectedAge--;

        Assert.Equal(expectedAge, age);
    }

    [Fact]
    public void Patient_Properties_SetCorrectly()
    {
        // Arrange & Act
        var patient = new Patient
        {
            FullName = "Test Patient",
            DateOfBirth = new DateTime(1990, 1, 1),
            CivilStatus = "Single",
            Phone = "123456789",
            Mobile = "987654321",
            Email = "test@email.com",
            HowFoundClinic = "Google",
            GeneralObservations = "Test observations"
        };

        // Assert
        Assert.Equal("Test Patient", patient.FullName);
        Assert.Equal(new DateTime(1990, 1, 1), patient.DateOfBirth);
        Assert.Equal("Single", patient.CivilStatus);
        Assert.Equal("123456789", patient.Phone);
        Assert.Equal("987654321", patient.Mobile);
        Assert.Equal("test@email.com", patient.Email);
        Assert.Equal("Google", patient.HowFoundClinic);
        Assert.Equal("Test observations", patient.GeneralObservations);
    }

    [Fact]
    public void Patient_NavigationProperties_InitializedCorrectly()
    {
        // Arrange & Act
        var patient = new Patient();

        // Assert
        Assert.NotNull(patient.Consultations);
        Assert.NotNull(patient.ConsentSignatures);
        Assert.Empty(patient.Consultations);
        Assert.Empty(patient.ConsentSignatures);
    }

    [Theory]
    [InlineData(1980, 5, 15)]
    [InlineData(1990, 12, 31)]
    [InlineData(2000, 1, 1)]
    public void Patient_AgeCalculation_VariousBirthDates_ReturnsCorrectAge(int year, int month, int day)
    {
        // Arrange
        var birthDate = new DateTime(year, month, day);
        var patient = new Patient { DateOfBirth = birthDate };

        // Act
        var age = patient.Age;

        // Assert
        var expectedAge = DateTime.Today.Year - birthDate.Year;
        if (birthDate.Date > DateTime.Today.AddYears(-expectedAge))
            expectedAge--;

        Assert.Equal(expectedAge, age);
        Assert.True(age >= 0);
    }
}