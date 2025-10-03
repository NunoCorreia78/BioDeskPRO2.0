using Microsoft.EntityFrameworkCore;
using BioDesk.Data;
using BioDesk.Domain.Entities;

var options = new DbContextOptionsBuilder<BioDeskDbContext>()
    .UseSqlite("Data Source=../biodesk.db")
    .Options;

using var context = new BioDeskDbContext(options);

Console.WriteLine("=== TESTE: Método GetAllOrderedByNomeAsync() ===\n");

// Simular o que o Repository faz
var pacientesViaRepository = await context.Pacientes
    .OrderBy(p => p.NomeCompleto)
    .ToListAsync();

Console.WriteLine($"📊 Pacientes retornados pelo método GetAllOrderedByNomeAsync(): {pacientesViaRepository.Count}\n");
Console.WriteLine(new string('-', 100));

foreach (var p in pacientesViaRepository)
{
    Console.WriteLine($"ID: {p.Id,-4} | Processo: {p.NumeroProcesso,-15} | {p.NomeCompleto}");

    if (p.NomeCompleto.Contains("Nuno", StringComparison.OrdinalIgnoreCase))
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("     ^^^ NUNO FILIPE CORREIA ESTÁ NA QUERY! ^^^");
        Console.ResetColor();
    }
}

Console.WriteLine(new string('-', 100));

// Testar SearchByNomeAsync com termo vazio
Console.WriteLine("\n=== TESTE: SearchByNomeAsync('') ===\n");
var searchResultEmpty = await context.Pacientes
    .Where(p => p.NomeCompleto.ToLower().Contains(""))
    .OrderBy(p => p.NomeCompleto)
    .Take(50)
    .ToListAsync();

Console.WriteLine($"Resultados: {searchResultEmpty.Count}");

// Testar SearchByNomeAsync com "Nuno"
Console.WriteLine("\n=== TESTE: SearchByNomeAsync('Nuno') ===\n");
var searchResultNuno = await context.Pacientes
    .Where(p => p.NomeCompleto.ToLower().Contains("nuno"))
    .OrderBy(p => p.NomeCompleto)
    .Take(50)
    .ToListAsync();

Console.WriteLine($"Resultados: {searchResultNuno.Count}");
foreach (var p in searchResultNuno)
{
    Console.WriteLine($"  - {p.NomeCompleto}");
}

Console.WriteLine("\n=== FIM DOS TESTES ===");
