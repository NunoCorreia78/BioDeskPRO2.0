using BioDeskPro.Core.Entities;
using BioDeskPro.Data.Contexts;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
using System.Text;

namespace BioDeskPro.Data.Services;

public interface IPacienteService
{
    Task<IEnumerable<Paciente>> GetAllAsync();
    Task<IEnumerable<Paciente>> SearchAsync(string searchTerm);
    Task<Paciente?> GetByIdAsync(int id);
    Task<Paciente> CreateAsync(Paciente paciente);
    Task<Paciente> UpdateAsync(Paciente paciente);
    Task DeleteAsync(int id);
    Task<(bool isDuplicate, Paciente? existingPaciente)> CheckDuplicateAsync(Paciente paciente);
    Task<Paciente> MergePatientsAsync(int sourceId, int targetId);
    string NormalizeName(string name);
    int CalculateAge(DateTime dateOfBirth);
}

public class PacienteService : IPacienteService
{
    private readonly BioDeskContext _context;

    public PacienteService(BioDeskContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<Paciente>> GetAllAsync()
    {
        return await _context.Pacientes
            .Where(p => p.Ativo)
            .OrderBy(p => p.Nome)
            .ToListAsync();
    }

    public async Task<IEnumerable<Paciente>> SearchAsync(string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm))
            return await GetAllAsync();

        var normalizedTerm = NormalizeName(searchTerm);
        
        return await _context.Pacientes
            .Where(p => p.Ativo && 
                   (p.NomeNormalizado!.Contains(normalizedTerm) ||
                    (p.NumeroUtente != null && p.NumeroUtente.Contains(searchTerm)) ||
                    (p.Email != null && p.Email.Contains(searchTerm)) ||
                    (p.Telemovel != null && p.Telemovel.Contains(searchTerm))))
            .OrderBy(p => p.Nome)
            .ToListAsync();
    }

    public async Task<Paciente?> GetByIdAsync(int id)
    {
        return await _context.Pacientes
            .FirstOrDefaultAsync(p => p.Id == id && p.Ativo);
    }

    public async Task<Paciente> CreateAsync(Paciente paciente)
    {
        // Normalizar nome antes de criar
        paciente.NomeNormalizado = NormalizeName(paciente.Nome);
        
        // Verificar duplicados antes de criar
        var (isDuplicate, existingPaciente) = await CheckDuplicateAsync(paciente);
        if (isDuplicate && existingPaciente != null)
        {
            throw new InvalidOperationException($"Já existe um paciente similar: {existingPaciente.Nome}");
        }
        
        paciente.CreatedAt = DateTime.UtcNow;
        paciente.UpdatedAt = DateTime.UtcNow;
        paciente.Ativo = true;
        
        _context.Pacientes.Add(paciente);
        await _context.SaveChangesAsync();
        
        return paciente;
    }

    public async Task<Paciente> UpdateAsync(Paciente paciente)
    {
        var existing = await _context.Pacientes.FindAsync(paciente.Id);
        if (existing == null)
            throw new ArgumentException("Paciente não encontrado");
        
        // Atualizar campos existentes
        existing.Nome = paciente.Nome;
        existing.NomeNormalizado = NormalizeName(paciente.Nome);
        existing.NumeroUtente = paciente.NumeroUtente;
        existing.DocumentoIdentidade = paciente.DocumentoIdentidade;
        existing.DataNascimento = paciente.DataNascimento;
        existing.Sexo = paciente.Sexo;
        existing.Morada = paciente.Morada;
        existing.Telemovel = paciente.Telemovel;
        existing.Email = paciente.Email;
        existing.ComoConheceu = paciente.ComoConheceu;
        existing.Observacoes = paciente.Observacoes;
        existing.UpdatedAt = DateTime.UtcNow;
        
        await _context.SaveChangesAsync();
        return existing;
    }

    public async Task DeleteAsync(int id)
    {
        var paciente = await _context.Pacientes.FindAsync(id);
        if (paciente != null)
        {
            // Soft delete
            paciente.Ativo = false;
            paciente.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }
    }

    public async Task<(bool isDuplicate, Paciente? existingPaciente)> CheckDuplicateAsync(Paciente paciente)
    {
        var normalizedNome = NormalizeName(paciente.Nome);
        
        // 1. Verificar correspondência exata por UNIQUE constraints
        var exactMatch = await _context.Pacientes
            .Where(p => p.Ativo && 
                       (p.NomeNormalizado == normalizedNome && p.DataNascimento == paciente.DataNascimento) ||
                       (!string.IsNullOrEmpty(paciente.Email) && p.Email == paciente.Email))
            .FirstOrDefaultAsync();
        
        if (exactMatch != null)
            return (true, exactMatch);
        
        // 2. Verificar similaridade por Levenshtein nos apelidos
        if (paciente.DataNascimento.HasValue)
        {
            var pacientesComMesmaData = await _context.Pacientes
                .Where(p => p.Ativo && p.DataNascimento == paciente.DataNascimento)
                .ToListAsync();
            
            var nomePartes = normalizedNome.Split(' ');
            var ultimoNome = nomePartes.Length > 1 ? nomePartes.Last() : "";
            
            foreach (var p in pacientesComMesmaData)
            {
                if (string.IsNullOrEmpty(p.NomeNormalizado)) continue;
                
                var existingPartes = p.NomeNormalizado.Split(' ');
                var existingUltimoNome = existingPartes.Length > 1 ? existingPartes.Last() : "";
                
                if (!string.IsNullOrEmpty(ultimoNome) && !string.IsNullOrEmpty(existingUltimoNome))
                {
                    var distance = CalculateLevenshteinDistance(ultimoNome, existingUltimoNome);
                    if (distance <= 1) // Tolerância de 1 caractere
                    {
                        return (true, p);
                    }
                }
            }
        }
        
        return (false, null);
    }

    public async Task<Paciente> MergePatientsAsync(int sourceId, int targetId)
    {
        using var transaction = await _context.Database.BeginTransactionAsync();
        
        try
        {
            var sourcePaciente = await _context.Pacientes.FindAsync(sourceId);
            var targetPaciente = await _context.Pacientes.FindAsync(targetId);
            
            if (sourcePaciente == null || targetPaciente == null)
                throw new ArgumentException("Pacientes não encontrados");
            
            // Transferir relacionamentos (FKs) do source para o target
            // Encontros
            await _context.Database.ExecuteSqlRawAsync(
                "UPDATE Encontros SET PacienteId = {0} WHERE PacienteId = {1}", 
                targetId, sourceId);
            
            // Documentos
            await _context.Database.ExecuteSqlRawAsync(
                "UPDATE Documentos SET PacienteId = {0} WHERE PacienteId = {1}", 
                targetId, sourceId);
            
            // DeclaracoesSaude
            await _context.Database.ExecuteSqlRawAsync(
                "UPDATE DeclaracoesSaude SET PacienteId = {0} WHERE PacienteId = {1}", 
                targetId, sourceId);
            
            // ConsentimentosPaciente
            await _context.Database.ExecuteSqlRawAsync(
                "UPDATE ConsentimentosPaciente SET PacienteId = {0} WHERE PacienteId = {1}", 
                targetId, sourceId);
            
            // Remover o paciente source (soft delete)
            sourcePaciente.Ativo = false;
            sourcePaciente.UpdatedAt = DateTime.UtcNow;
            
            // Atualizar target
            targetPaciente.UpdatedAt = DateTime.UtcNow;
            
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();
            
            return targetPaciente;
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }

    public string NormalizeName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;
        
        // Converter para lowercase e remover acentos
        var normalized = name.ToLowerInvariant();
        
        // Remover acentos
        normalized = RemoveAccents(normalized);
        
        // Remover caracteres especiais e múltiplos espaços
        normalized = System.Text.RegularExpressions.Regex.Replace(normalized, @"[^\w\s]", "");
        normalized = System.Text.RegularExpressions.Regex.Replace(normalized, @"\s+", " ");
        
        return normalized.Trim();
    }

    public int CalculateAge(DateTime dateOfBirth)
    {
        var today = DateTime.Today;
        var age = today.Year - dateOfBirth.Year;
        
        if (dateOfBirth.Date > today.AddYears(-age))
            age--;
        
        return Math.Max(0, age);
    }

    private string RemoveAccents(string text)
    {
        var normalizedString = text.Normalize(NormalizationForm.FormD);
        var stringBuilder = new StringBuilder(capacity: normalizedString.Length);

        for (int i = 0; i < normalizedString.Length; i++)
        {
            char c = normalizedString[i];
            var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(c);
            if (unicodeCategory != UnicodeCategory.NonSpacingMark)
            {
                stringBuilder.Append(c);
            }
        }

        return stringBuilder
            .ToString()
            .Normalize(NormalizationForm.FormC);
    }

    private int CalculateLevenshteinDistance(string s1, string s2)
    {
        if (string.IsNullOrEmpty(s1)) return s2?.Length ?? 0;
        if (string.IsNullOrEmpty(s2)) return s1.Length;

        var d = new int[s1.Length + 1, s2.Length + 1];

        for (int i = 0; i <= s1.Length; i++)
            d[i, 0] = i;

        for (int j = 0; j <= s2.Length; j++)
            d[0, j] = j;

        for (int i = 1; i <= s1.Length; i++)
        {
            for (int j = 1; j <= s2.Length; j++)
            {
                int cost = s1[i - 1] == s2[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
            }
        }

        return d[s1.Length, s2.Length];
    }
}