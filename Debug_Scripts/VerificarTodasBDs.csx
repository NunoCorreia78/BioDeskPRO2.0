using System;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

Console.WriteLine("🔍 VERIFICAÇÃO COMPLETA DA BASE DE DADOS BIODESK\n");
Console.WriteLine("=" .PadRight(60, '=') + "\n");

// Verificar ambas as localizações possíveis da BD
var dbPaths = new[]
{
    Path.Combine(Directory.GetCurrentDirectory(), "biodesk.db"),
    Path.Combine(Directory.GetCurrentDirectory(), "src", "BioDesk.App", "biodesk.db")
};

foreach (var dbPath in dbPaths)
{
    Console.WriteLine($"📂 A verificar: {dbPath}");
    
    if (!File.Exists(dbPath))
    {
        Console.WriteLine("   ❌ Ficheiro não encontrado\n");
        continue;
    }
    
    Console.WriteLine($"   ✅ Ficheiro existe ({new FileInfo(dbPath).Length / 1024} KB)\n");
    
    try
    {
        using var connection = new SqliteConnection($"Data Source={dbPath}");
        connection.Open();
        
        // Contar pacientes
        using var cmdCount = connection.CreateCommand();
        cmdCount.CommandText = "SELECT COUNT(*) FROM Pacientes";
        var total = Convert.ToInt32(cmdCount.ExecuteScalar());
        
        Console.WriteLine($"   📊 Total de pacientes: {total}\n");
        
        // Listar TODOS os pacientes
        using var cmdList = connection.CreateCommand();
        cmdList.CommandText = @"
            SELECT Id, NumeroProcesso, NomeCompleto, DataNascimento, 
                   DataCriacao, DataUltimaAtualizacao
            FROM Pacientes 
            ORDER BY NomeCompleto";
        
        using var reader = cmdList.ExecuteReader();
        
        Console.WriteLine("   📋 LISTA COMPLETA DE PACIENTES (A-Z):");
        Console.WriteLine("   " + "-".PadRight(58, '-'));
        
        var count = 0;
        while (reader.Read())
        {
            count++;
            var id = reader.GetInt32(0);
            var numProcesso = reader.GetString(1);
            var nome = reader.GetString(2);
            var dataNasc = reader.GetDateTime(3);
            var dataCriacao = reader.GetDateTime(4);
            var dataAtualizacao = reader.IsDBNull(5) ? (DateTime?)null : reader.GetDateTime(5);
            
            Console.WriteLine($"\n   {count}. ID: {id} | Nº Processo: {numProcesso}");
            Console.WriteLine($"      Nome: {nome}");
            Console.WriteLine($"      Nascimento: {dataNasc:dd/MM/yyyy}");
            Console.WriteLine($"      Criado: {dataCriacao:dd/MM/yyyy HH:mm}");
            Console.WriteLine($"      Atualizado: {(dataAtualizacao.HasValue ? dataAtualizacao.Value.ToString("dd/MM/yyyy HH:mm") : "Nunca")}");
        }
        
        Console.WriteLine("\n   " + "-".PadRight(58, '-'));
        Console.WriteLine($"   ✅ Total listado: {count} pacientes\n");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"   💥 ERRO: {ex.Message}\n");
    }
}

Console.WriteLine("=" .PadRight(60, '='));
Console.WriteLine("\n🎯 CONCLUSÃO:");
Console.WriteLine("   Se o paciente 'Nuno Filipe' não aparece em nenhuma BD,");
Console.WriteLine("   significa que não foi gravado corretamente.\n");
