using BioDeskPRO.Models;

namespace BioDeskPRO.Services;

/// <summary>
/// Patient-specific service interface
/// </summary>
public interface IPatientService
{
    Task<ServiceResult<Patient>> CreatePatientAsync(Patient patient);
    Task<ServiceResult<Patient>> UpdatePatientAsync(Patient patient);
    Task<ServiceResult<Patient?>> GetPatientByIdAsync(int id);
    Task<ServiceResult<IEnumerable<Patient>>> GetAllPatientsAsync();
    Task<ServiceResult<IEnumerable<Patient>>> SearchPatientsAsync(string searchTerm);
    Task<ServiceResult<bool>> DeletePatientAsync(int id);
    Task<ServiceResult<bool>> ValidatePatientDataAsync(Patient patient);
}