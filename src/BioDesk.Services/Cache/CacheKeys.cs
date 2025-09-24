namespace BioDesk.Services.Cache;

/// <summary>
/// Constantes para chaves de cache do sistema
/// Organização hierárquica para fácil invalidação por padrão
/// </summary>
public static class CacheKeys
{
    /// <summary>
    /// Prefixo para todos os dados de pacientes
    /// </summary>
    public const string PACIENTES_PREFIX = "pacientes:";
    
    /// <summary>
    /// Lista completa de todos os pacientes
    /// </summary>
    public const string PACIENTES_ALL = "pacientes:all";
    
    /// <summary>
    /// Lista de pacientes recentes
    /// Formato: pacientes:recent:{quantidade}
    /// </summary>
    public const string PACIENTES_RECENT = "pacientes:recent";
    
    /// <summary>
    /// Prefixo para resultados de pesquisa
    /// Formato: search:pacientes:{termo_normalizado}
    /// </summary>
    public const string SEARCH_PREFIX = "search:pacientes:";
    
    /// <summary>
    /// Paciente individual por ID
    /// Formato: pacientes:id:{id}
    /// </summary>
    public const string PACIENTE_BY_ID = "pacientes:id:";

    /// <summary>
    /// Gera chave para pacientes recentes
    /// </summary>
    public static string GetRecentKey(int quantidade) => $"{PACIENTES_RECENT}:{quantidade}";
    
    /// <summary>
    /// Gera chave para pesquisa normalizada
    /// </summary>
    public static string GetSearchKey(string termo) => 
        $"{SEARCH_PREFIX}{NormalizeTermo(termo)}";
    
    /// <summary>
    /// Gera chave para paciente por ID
    /// </summary>
    public static string GetPacienteKey(int id) => $"{PACIENTE_BY_ID}{id}";
    
    /// <summary>
    /// Normaliza termo de pesquisa para chave consistente
    /// </summary>
    private static string NormalizeTermo(string termo)
    {
        if (string.IsNullOrWhiteSpace(termo))
            return "empty";
        
        return termo.Trim()
                   .ToLowerInvariant()
                   .Replace(" ", "_")
                   .Replace(".", "_")
                   .Replace("@", "_at_");
    }
}