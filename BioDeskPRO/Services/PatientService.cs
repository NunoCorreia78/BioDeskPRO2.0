using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using BioDeskPRO.Data;
using BioDeskPRO.Models;

namespace BioDeskPRO.Services;

/// <summary>
/// Patient service implementation with validation and error handling
/// </summary>
public class PatientService : IPatientService
{
    private readonly BioDeskContext _context;
    private readonly ILogger<PatientService> _logger;

    public PatientService(BioDeskContext context, ILogger<PatientService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<ServiceResult<Patient>> CreatePatientAsync(Patient patient)
    {
        try
        {
            // Validate patient data
            var validationResult = await ValidatePatientDataAsync(patient);
            if (!validationResult.IsSuccess)
            {
                return ServiceResult<Patient>.Failure(validationResult.ErrorMessage);
            }

            // Check for duplicate email if provided
            if (!string.IsNullOrEmpty(patient.Email))
            {
                var existingPatient = await _context.Patients
                    .FirstOrDefaultAsync(p => p.Email.ToLower() == patient.Email.ToLower());
                
                if (existingPatient != null)
                {
                    return ServiceResult<Patient>.Failure("A patient with this email already exists.");
                }
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                _context.Patients.Add(patient);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("Patient created successfully with ID: {PatientId}", patient.Id);
                return ServiceResult<Patient>.Success(patient);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating patient: {PatientName}", patient.FullName);
            return ServiceResult<Patient>.Failure("Failed to create patient. Please try again.", ex);
        }
    }

    public async Task<ServiceResult<Patient>> UpdatePatientAsync(Patient patient)
    {
        try
        {
            // Validate patient data
            var validationResult = await ValidatePatientDataAsync(patient);
            if (!validationResult.IsSuccess)
            {
                return ServiceResult<Patient>.Failure(validationResult.ErrorMessage);
            }

            // Check if patient exists
            var existingPatient = await _context.Patients.FindAsync(patient.Id);
            if (existingPatient == null)
            {
                return ServiceResult<Patient>.Failure("Patient not found.");
            }

            // Check for duplicate email if provided and different from current
            if (!string.IsNullOrEmpty(patient.Email) && 
                patient.Email.ToLower() != existingPatient.Email.ToLower())
            {
                var duplicateEmail = await _context.Patients
                    .AnyAsync(p => p.Email.ToLower() == patient.Email.ToLower() && p.Id != patient.Id);
                
                if (duplicateEmail)
                {
                    return ServiceResult<Patient>.Failure("Another patient with this email already exists.");
                }
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                // Update fields
                existingPatient.FullName = patient.FullName;
                existingPatient.DateOfBirth = patient.DateOfBirth;
                existingPatient.CivilStatus = patient.CivilStatus;
                existingPatient.Phone = patient.Phone;
                existingPatient.Mobile = patient.Mobile;
                existingPatient.Email = patient.Email;
                existingPatient.HowFoundClinic = patient.HowFoundClinic;
                existingPatient.GeneralObservations = patient.GeneralObservations;

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("Patient updated successfully with ID: {PatientId}", patient.Id);
                return ServiceResult<Patient>.Success(existingPatient);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating patient with ID: {PatientId}", patient.Id);
            return ServiceResult<Patient>.Failure("Failed to update patient. Please try again.", ex);
        }
    }

    public async Task<ServiceResult<Patient?>> GetPatientByIdAsync(int id)
    {
        try
        {
            var patient = await _context.Patients
                .Include(p => p.Consultations)
                .Include(p => p.ConsentSignatures)
                    .ThenInclude(cs => cs.ConsentType)
                .FirstOrDefaultAsync(p => p.Id == id);

            return ServiceResult<Patient?>.Success(patient);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting patient with ID: {PatientId}", id);
            return ServiceResult<Patient?>.Failure("Failed to retrieve patient. Please try again.", ex);
        }
    }

    public async Task<ServiceResult<IEnumerable<Patient>>> GetAllPatientsAsync()
    {
        try
        {
            var patients = await _context.Patients
                .OrderBy(p => p.FullName)
                .ToListAsync();

            return ServiceResult<IEnumerable<Patient>>.Success(patients);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting all patients");
            return ServiceResult<IEnumerable<Patient>>.Failure("Failed to retrieve patients. Please try again.", ex);
        }
    }

    public async Task<ServiceResult<IEnumerable<Patient>>> SearchPatientsAsync(string searchTerm)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                return await GetAllPatientsAsync();
            }

            var searchLower = searchTerm.ToLower();
            var patients = await _context.Patients
                .Where(p => p.FullName.ToLower().Contains(searchLower) ||
                           p.Email.ToLower().Contains(searchLower) ||
                           p.Phone.Contains(searchTerm) ||
                           p.Mobile.Contains(searchTerm))
                .OrderBy(p => p.FullName)
                .ToListAsync();

            return ServiceResult<IEnumerable<Patient>>.Success(patients);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching patients with term: {SearchTerm}", searchTerm);
            return ServiceResult<IEnumerable<Patient>>.Failure("Failed to search patients. Please try again.", ex);
        }
    }

    public async Task<ServiceResult<bool>> DeletePatientAsync(int id)
    {
        try
        {
            var patient = await _context.Patients.FindAsync(id);
            if (patient == null)
            {
                return ServiceResult<bool>.Failure("Patient not found.");
            }

            using var transaction = await _context.Database.BeginTransactionAsync();
            try
            {
                _context.Patients.Remove(patient);
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation("Patient deleted successfully with ID: {PatientId}", id);
                return ServiceResult<bool>.Success(true);
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting patient with ID: {PatientId}", id);
            return ServiceResult<bool>.Failure("Failed to delete patient. Please try again.", ex);
        }
    }

    public async Task<ServiceResult<bool>> ValidatePatientDataAsync(Patient patient)
    {
        return await Task.FromResult(ValidatePatientData(patient));
    }

    private ServiceResult<bool> ValidatePatientData(Patient patient)
    {
        var errors = new List<string>();

        // Validate required fields
        if (string.IsNullOrWhiteSpace(patient.FullName))
            errors.Add("Full name is required.");

        if (patient.DateOfBirth == default)
            errors.Add("Date of birth is required.");

        // Validate date of birth is not in the future
        if (patient.DateOfBirth > DateTime.Today)
            errors.Add("Date of birth cannot be in the future.");

        // Validate age is reasonable (0-150 years)
        var age = patient.Age;
        if (age < 0 || age > 150)
            errors.Add("Invalid date of birth. Age must be between 0 and 150 years.");

        // Validate email format if provided
        if (!string.IsNullOrWhiteSpace(patient.Email))
        {
            var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
            if (!emailRegex.IsMatch(patient.Email))
                errors.Add("Invalid email format.");
        }

        // Validate phone format if provided
        if (!string.IsNullOrWhiteSpace(patient.Phone))
        {
            var phoneRegex = new Regex(@"^[\d\s\-\+\(\)]+$");
            if (!phoneRegex.IsMatch(patient.Phone))
                errors.Add("Invalid phone format.");
        }

        // Validate mobile format if provided
        if (!string.IsNullOrWhiteSpace(patient.Mobile))
        {
            var mobileRegex = new Regex(@"^[\d\s\-\+\(\)]+$");
            if (!mobileRegex.IsMatch(patient.Mobile))
                errors.Add("Invalid mobile format.");
        }

        if (errors.Any())
        {
            return ServiceResult<bool>.Failure(string.Join(" ", errors));
        }

        return ServiceResult<bool>.Success(true);
    }
}