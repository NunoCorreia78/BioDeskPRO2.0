<#
.SYNOPSIS
Verifica estado da BD sem perder dados - análise segura
#>

$dbPath = Join-Path $PWD "biodesk.db"

if (!(Test-Path $dbPath)) {
    Write-Host "❌ BD não encontrada: $dbPath"
    exit
}

$dbSize = (Get-Item $dbPath).Length / 1KB
Write-Host "📂 BD encontrada: $dbPath"
Write-Host "📊 Tamanho: $([math]::Round($dbSize, 2)) KB"
Write-Host ""

# Usar dotnet-script inline com C#
$csharpCode = @"
using System;
using System.IO;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;

var dbPath = @"$dbPath";
var options = new DbContextOptionsBuilder<BioDeskDbContext>()
    .UseSqlite(`$"Data Source={dbPath}")
    .Options;

using (var db = new BioDeskDbContext(options))
{
    var totalPacientes = db.Pacientes.Count();
    Console.WriteLine(`$"👥 Total de Pacientes: {totalPacientes}");

    var seedIds = db.Pacientes.Where(p => p.Id <= 3).Select(p => new { p.Id, p.NumeroProcesso, p.NomeCompleto }).ToList();

    if (seedIds.Any())
    {
        Console.WriteLine("\n⚠️ Pacientes com IDs de SEED (1,2,3):");
        foreach (var p in seedIds)
        {
            Console.WriteLine(`$"  • ID {p.Id}: {p.NumeroProcesso} - {p.NomeCompleto}");
        }
    }
    else
    {
        Console.WriteLine("\n✅ IDs 1,2,3 estão LIVRES");
    }

    var primeiros5 = db.Pacientes.OrderBy(p => p.Id).Take(5).Select(p => new { p.Id, p.NumeroProcesso, p.NomeCompleto }).ToList();

    if (primeiros5.Any())
    {
        Console.WriteLine("\n📋 Primeiros 5 Pacientes:");
        foreach (var p in primeiros5)
        {
            Console.WriteLine(`$"  • ID {p.Id}: {p.NumeroProcesso} - {p.NomeCompleto}");
        }
    }

    var totalSessoes = db.Sessoes.Count();
    Console.WriteLine(`$"\n📅 Total de Sessões: {totalSessoes}");
}
"@

# Executar com dotnet run inline
dotnet run --project src/BioDesk.App -- --check-db
