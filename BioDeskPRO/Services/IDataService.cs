namespace BioDeskPRO.Services;

/// <summary>
/// Generic data service interface for common operations
/// </summary>
public interface IDataService
{
    Task<T?> GetByIdAsync<T>(int id) where T : class;
    Task<IEnumerable<T>> GetAllAsync<T>() where T : class;
    Task<T> CreateAsync<T>(T entity) where T : class;
    Task<T> UpdateAsync<T>(T entity) where T : class;
    Task<bool> DeleteAsync<T>(int id) where T : class;
    Task<bool> SaveChangesAsync();
}

/// <summary>
/// Result wrapper for service operations
/// </summary>
public class ServiceResult<T>
{
    public bool IsSuccess { get; set; }
    public T? Data { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
    public Exception? Exception { get; set; }

    public static ServiceResult<T> Success(T data)
    {
        return new ServiceResult<T> { IsSuccess = true, Data = data };
    }

    public static ServiceResult<T> Failure(string errorMessage, Exception? exception = null)
    {
        return new ServiceResult<T> 
        { 
            IsSuccess = false, 
            ErrorMessage = errorMessage, 
            Exception = exception 
        };
    }
}