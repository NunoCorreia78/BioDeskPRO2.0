#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.EntityFrameworkCore.Sqlite, 8.0.0"

using Microsoft.EntityFrameworkCore;
using System.Linq;

var dbPath = @"C:\ProgramData\BioDeskPro2\biodesk.db";

Console.WriteLine($"🔍 Analisando categorias em ItemBancoCore...");
Console.WriteLine($"📂 BD: {dbPath}\n");

if (!File.Exists(dbPath))
{
    Console.WriteLine($"❌ BD não encontrada em: {dbPath}");
    return;
}

var optionsBuilder = new DbContextOptionsBuilder<AppDbContext>();
optionsBuilder.UseSqlite($"Data Source={dbPath}");

using var db = new AppDbContext(optionsBuilder.Options);

// Query 1: Todas as categorias ÚNICAS
var categorias = await db.Database
    .SqlQueryRaw<string>("SELECT DISTINCT Categoria FROM ItemBancoCore WHERE Categoria IS NOT NULL ORDER BY Categoria")
    .ToListAsync();

Console.WriteLine($"📊 Total de categorias únicas: {categorias.Count}\n");
Console.WriteLine("═══════════════════════════════════════");

foreach (var cat in categorias)
{
    // Contar quantos itens por categoria
    var count = await db.Database
        .SqlQueryRaw<int>($"SELECT COUNT(*) as Value FROM ItemBancoCore WHERE Categoria = '{cat.Replace("'", "''")}'")
        .FirstOrDefaultAsync();
    
    Console.WriteLine($"• {cat,-30} ({count,5} itens)");
}

Console.WriteLine("═══════════════════════════════════════\n");

// Query 2: Total de itens
var total = await db.Database
    .SqlQueryRaw<int>("SELECT COUNT(*) as Value FROM ItemBancoCore")
    .FirstOrDefaultAsync();

Console.WriteLine($"✅ Total de itens na tabela: {total}");

// DbContext mínimo
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}
