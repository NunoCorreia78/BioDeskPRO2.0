using System;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;
using BioDesk.Data.SeedData;

namespace BioDesk.Data.SeedData;

/// <summary>
/// Programa console para seed dos ItemBancoCore na BD
/// Executa ValidateAll() e insere os 156 itens (Bach, Chakras, Meridianos, Órgãos)
/// </summary>
public class SeedItemBancoCoreProgram
{
    public static void Main(string[] args)
    {
        Console.WriteLine("════════════════════════════════════════════════════════════");
        Console.WriteLine("  🌟 SEED ItemBancoCore - Sistema Core Informacional");
        Console.WriteLine("════════════════════════════════════════════════════════════\n");

        // Caminho da BD (SEMPRE usar o mesmo PathService)
        var dbPath = args.Length > 0 ? args[0] :
            @"C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db";

        Console.WriteLine($"📂 BD: {dbPath}");

        if (!File.Exists(dbPath))
        {
            Console.WriteLine($"❌ ERRO: BD não encontrada em {dbPath}");
            Console.WriteLine("   Execute 'dotnet ef database update' primeiro!");
            Environment.Exit(1);
        }

        // Criar DbContext
        var optionsBuilder = new DbContextOptionsBuilder<BioDeskDbContext>();
        optionsBuilder.UseSqlite($"Data Source={dbPath}");

        using var context = new BioDeskDbContext(optionsBuilder.Options);

        try
        {
            // 1. Validar dados ANTES de inserir
            Console.WriteLine("\n🔍 FASE 1: Validação dos dados...");
            Console.WriteLine("─────────────────────────────────────────────────────────────");

            ItemBancoCoreSeeder.ValidateAll();

            Console.WriteLine("\n✅ Validação completa - dados íntegros!\n");

            // 2. Verificar se já existe seed
            var count = context.ItensBancoCore.Count();
            if (count > 0)
            {
                Console.WriteLine($"⚠️  AVISO: Já existem {count} itens na tabela ItensBancoCore");
                Console.Write("   Deseja LIMPAR e re-seed? (S/N): ");
                var resposta = Console.ReadLine()?.Trim().ToUpperInvariant();

                if (resposta == "S" || resposta == "SIM" || resposta == "Y" || resposta == "YES")
                {
                    Console.WriteLine("\n🗑️  Limpando tabela ItensBancoCore...");
                    context.Database.ExecuteSqlRaw("DELETE FROM ItensBancoCore");
                    Console.WriteLine("✅ Tabela limpa!");
                }
                else
                {
                    Console.WriteLine("\n❌ Operação cancelada pelo utilizador");
                    Environment.Exit(0);
                }
            }

            // 3. Obter itens do seeder
            Console.WriteLine("\n💾 FASE 2: Inserção dos dados...");
            Console.WriteLine("─────────────────────────────────────────────────────────────");

            var itens = ItemBancoCoreSeeder.GetAll();

            Console.WriteLine($"📦 Total de itens a inserir: {itens.Count}");
            Console.WriteLine();

            // 4. Inserir em lote (performance)
            context.ItensBancoCore.AddRange(itens);
            var inserted = context.SaveChanges();

            Console.WriteLine($"✅ {inserted} itens inseridos com sucesso!");

            // 5. Verificar contagem por categoria
            Console.WriteLine("\n📊 FASE 3: Verificação final...");
            Console.WriteLine("─────────────────────────────────────────────────────────────");

            var categorias = context.ItensBancoCore
                .GroupBy(x => x.Categoria)
                .Select(g => new { Categoria = g.Key, Total = g.Count() })
                .OrderBy(x => x.Categoria)
                .ToList();

            foreach (var cat in categorias)
            {
                Console.WriteLine($"   {cat.Categoria,-30} {cat.Total,4} itens");
            }

            var totalFinal = context.ItensBancoCore.Count();
            Console.WriteLine($"\n   {"TOTAL",-30} {totalFinal,4} itens");

            // 6. Verificar GUIDs únicos
            var duplicados = context.ItensBancoCore
                .GroupBy(x => x.ExternalId)
                .Where(g => g.Count() > 1)
                .Count();

            if (duplicados > 0)
            {
                Console.WriteLine($"\n❌ ERRO: {duplicados} GUIDs duplicados encontrados!");
                Environment.Exit(1);
            }
            else
            {
                Console.WriteLine("\n✅ Zero GUIDs duplicados - integridade garantida!");
            }

            // 7. Sucesso total
            Console.WriteLine("\n════════════════════════════════════════════════════════════");
            Console.WriteLine("  ✅ SEED COMPLETO - Sistema Core 100% Operacional");
            Console.WriteLine("════════════════════════════════════════════════════════════");
            Console.WriteLine("\n🚀 Próximos passos:");
            Console.WriteLine("   1. Registar serviços em App.xaml.cs (DI)");
            Console.WriteLine("   2. Testar CoreAnaliseService.ScanAsync()");
            Console.WriteLine("   3. Integrar Dashboard navigation");
            Console.WriteLine();

        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ ERRO FATAL: {ex.Message}");
            Console.WriteLine($"\nStack Trace:\n{ex.StackTrace}");
            Environment.Exit(1);
        }
    }
}
