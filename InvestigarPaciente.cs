using Microsoft.EntityFrameworkCore;
using BioDesk.Data;
using BioDesk.Domain.Entities;

var options = new DbContextOptionsBuilder<BioDeskDbContext>()
    .UseSqlite("Data Source=biodesk.db")
    .Options;

using var context = new BioDeskDbContext(options);

Console.WriteLine("=== INVESTIGAÇÃO: Paciente 'Nuno Filipe Correia' ===\n");
Console.WriteLine("📋 TODOS OS PACIENTES NA BASE DE DADOS:");
Console.WriteLine(new string('-', 100));

var pacientes = await context.Pacientes
    .OrderBy(p => p.NomeCompleto)
    .ToListAsync();

if (!pacientes.Any())
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("⚠️  ATENÇÃO: Base de dados VAZIA - nenhum paciente encontrado!");
    Console.ResetColor();
}
else
{
    int contador = 1;
    foreach (var p in pacientes)
    {
        var dataNasc = p.DataNascimento?.ToString("dd/MM/yyyy") ?? "(sem data)";
        var processo = p.NumeroProcesso ?? "(sem processo)";

        Console.WriteLine($"{contador,3}. ID: {p.Id,-4} | Processo: {processo,-10} | {p.NomeCompleto,-40} | Nasc: {dataNasc}");

        // Destacar se encontrar "Nuno" ou "Correia"
        if (p.NomeCompleto.Contains("Nuno", StringComparison.OrdinalIgnoreCase) ||
            p.NomeCompleto.Contains("Correia", StringComparison.OrdinalIgnoreCase))
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"       ^^^ MATCH ENCONTRADO: '{p.NomeCompleto}' ^^^");
            Console.ResetColor();
        }

        contador++;
    }

    Console.WriteLine(new string('-', 100));
    Console.WriteLine($"\n✅ Total de pacientes: {pacientes.Count}\n");

    // Procurar especificamente por "Nuno Filipe Correia"
    var nunoFilipe = pacientes.FirstOrDefault(p =>
        p.NomeCompleto.Contains("Nuno", StringComparison.OrdinalIgnoreCase) &&
        p.NomeCompleto.Contains("Filipe", StringComparison.OrdinalIgnoreCase) &&
        p.NomeCompleto.Contains("Correia", StringComparison.OrdinalIgnoreCase));

    Console.WriteLine("\n" + new string('=', 100));
    if (nunoFilipe != null)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("✅ PACIENTE 'Nuno Filipe Correia' ENCONTRADO:");
        Console.WriteLine($"   ID: {nunoFilipe.Id}");
        Console.WriteLine($"   Processo: {nunoFilipe.NumeroProcesso ?? "(não definido)"}");
        Console.WriteLine($"   Nome Completo: {nunoFilipe.NomeCompleto}");
        Console.WriteLine($"   Data Nascimento: {nunoFilipe.DataNascimento?.ToString("dd/MM/yyyy") ?? "(não definida)"}");
        Console.WriteLine($"   Género: {nunoFilipe.Genero ?? "(não definido)"}");
        Console.ResetColor();
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("❌ PACIENTE 'Nuno Filipe Correia' NÃO ENCONTRADO!");
        Console.ResetColor();

        // Verificar se existe algum "Nuno"
        var qualquerNuno = pacientes.Where(p => p.NomeCompleto.Contains("Nuno", StringComparison.OrdinalIgnoreCase)).ToList();
        if (qualquerNuno.Any())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n⚠️  Encontrados {qualquerNuno.Count} paciente(s) com 'Nuno' no nome:");
            foreach (var p in qualquerNuno)
            {
                Console.WriteLine($"   - {p.NomeCompleto} (ID: {p.Id}, Processo: {p.NumeroProcesso ?? "N/A"})");
            }
            Console.ResetColor();
        }

        // Verificar se existe algum "Correia"
        var qualquerCorreia = pacientes.Where(p => p.NomeCompleto.Contains("Correia", StringComparison.OrdinalIgnoreCase)).ToList();
        if (qualquerCorreia.Any())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n⚠️  Encontrados {qualquerCorreia.Count} paciente(s) com 'Correia' no nome:");
            foreach (var p in qualquerCorreia)
            {
                Console.WriteLine($"   - {p.NomeCompleto} (ID: {p.Id}, Processo: {p.NumeroProcesso ?? "N/A"})");
            }
            Console.ResetColor();
        }
    }
    Console.WriteLine(new string('=', 100));
}

Console.WriteLine("\n=== FIM DA INVESTIGAÇÃO ===");
