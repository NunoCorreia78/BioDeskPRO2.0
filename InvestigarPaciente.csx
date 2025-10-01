#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.EntityFrameworkCore.Sqlite, 8.0.0"
#r "nuget: Microsoft.Extensions.Logging.Console, 8.0.0"

using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

// Entidade Paciente
public class Paciente
{
    [Key]
    public int Id { get; set; }

    public string Nome { get; set; } = string.Empty;
    public string? Email { get; set; }
    public DateTime? DataNascimento { get; set; }
}

// DbContext
public class BioContext : DbContext
{
    public DbSet<Paciente> Pacientes { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlite("Data Source=biodesk.db");
    }
}

// Script principal
Console.WriteLine("=== INVESTIGAÇÃO: Paciente 'Nuno Filipe Correia' ===\n");

using var db = new BioContext();

Console.WriteLine("📋 TODOS OS PACIENTES NA BASE DE DADOS:");
Console.WriteLine(new string('-', 80));

var pacientes = await db.Pacientes
    .OrderBy(p => p.Nome)
    .ToListAsync();

if (!pacientes.Any())
{
    Console.WriteLine("⚠️  ATENÇÃO: Base de dados VAZIA - nenhum paciente encontrado!");
}
else
{
    int contador = 1;
    foreach (var p in pacientes)
    {
        var dataNasc = p.DataNascimento?.ToString("dd/MM/yyyy") ?? "(sem data)";
        var email = string.IsNullOrEmpty(p.Email) ? "(sem email)" : p.Email;

        Console.WriteLine($"{contador}. ID: {p.Id,-3} | {p.Nome,-40} | {email,-30} | Nasc: {dataNasc}");

        // Destacar se encontrar "Nuno" ou "Correia"
        if (p.Nome.Contains("Nuno", StringComparison.OrdinalIgnoreCase) ||
            p.Nome.Contains("Correia", StringComparison.OrdinalIgnoreCase))
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"   ^^^ MATCH ENCONTRADO: '{p.Nome}' ^^^");
            Console.ResetColor();
        }

        contador++;
    }

    Console.WriteLine(new string('-', 80));
    Console.WriteLine($"\n✅ Total de pacientes: {pacientes.Count}\n");

    // Procurar especificamente por "Nuno Filipe Correia"
    var nunoFilipe = pacientes.FirstOrDefault(p =>
        p.Nome.Contains("Nuno", StringComparison.OrdinalIgnoreCase) &&
        p.Nome.Contains("Filipe", StringComparison.OrdinalIgnoreCase) &&
        p.Nome.Contains("Correia", StringComparison.OrdinalIgnoreCase));

    if (nunoFilipe != null)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("✅ PACIENTE 'Nuno Filipe Correia' ENCONTRADO:");
        Console.WriteLine($"   ID: {nunoFilipe.Id}");
        Console.WriteLine($"   Nome Completo: {nunoFilipe.Nome}");
        Console.WriteLine($"   Email: {nunoFilipe.Email ?? "(não definido)"}");
        Console.WriteLine($"   Data Nascimento: {nunoFilipe.DataNascimento?.ToString("dd/MM/yyyy") ?? "(não definida)"}");
        Console.ResetColor();
    }
    else
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("❌ PACIENTE 'Nuno Filipe Correia' NÃO ENCONTRADO!");
        Console.ResetColor();

        // Verificar se existe algum "Nuno"
        var qualquerNuno = pacientes.Where(p => p.Nome.Contains("Nuno", StringComparison.OrdinalIgnoreCase)).ToList();
        if (qualquerNuno.Any())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n⚠️  Encontrados {qualquerNuno.Count} paciente(s) com 'Nuno' no nome:");
            foreach (var p in qualquerNuno)
            {
                Console.WriteLine($"   - {p.Nome} (ID: {p.Id})");
            }
            Console.ResetColor();
        }
    }
}

Console.WriteLine("\n=== FIM DA INVESTIGAÇÃO ===");
