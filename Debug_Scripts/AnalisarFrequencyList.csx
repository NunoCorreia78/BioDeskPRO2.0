#!/usr/bin/env dotnet-script
#r "nuget: ExcelDataReader, 3.7.0"
#r "nuget: ExcelDataReader.DataSet, 3.7.0"

using System;
using System.IO;
using System.Text;
using ExcelDataReader;

Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

var excelPath = @"c:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Templates\Terapias\FrequencyList.xls";

Console.WriteLine("📊 ANÁLISE DO FrequencyList.xls");
Console.WriteLine("================================\n");

using var stream = File.Open(excelPath, FileMode.Open, FileAccess.Read);
using var reader = ExcelDataReader.ExcelReaderFactory.CreateReader(stream);
var dataset = reader.AsDataSet();

Console.WriteLine($"Número de folhas: {dataset.Tables.Count}");

for (int s = 0; s < dataset.Tables.Count; s++)
{
    var table = dataset.Tables[s];
    Console.WriteLine($"\n📄 FOLHA {s + 1}: '{table.TableName}'");
    Console.WriteLine($"   Total de linhas: {table.Rows.Count}");
    Console.WriteLine($"   Total de colunas: {table.Columns.Count}");

    if (table.Rows.Count > 0)
    {
        Console.WriteLine($"\n   Cabeçalho (primeira linha):");
        for (int col = 0; col < Math.Min(table.Columns.Count, 20); col++)
        {
            var value = table.Rows[0][col]?.ToString()?.Trim() ?? "(vazio)";
            Console.WriteLine($"      Col {col + 1}: {value}");
        }

        // Mostrar primeiras 5 linhas de dados
        Console.WriteLine($"\n   Primeiras 5 linhas de dados:");
        for (int row = 1; row <= Math.Min(5, table.Rows.Count - 1); row++)
        {
            Console.WriteLine($"\n   Linha {row}:");
            for (int col = 0; col < Math.Min(table.Columns.Count, 10); col++)
            {
                var value = table.Rows[row][col]?.ToString()?.Trim() ?? "(vazio)";
                if (value.Length > 50) value = value.Substring(0, 47) + "...";
                Console.WriteLine($"      Col {col + 1}: {value}");
            }
        }
    }
}

// Contagem de frequências únicas
var table0 = dataset.Tables[0];
var uniqueProtocols = new HashSet<string>();
int totalFrequencies = 0;

for (int row = 1; row < table0.Rows.Count; row++)
{
    var diseaseName = table0.Rows[row][1]?.ToString()?.Trim();
    if (!string.IsNullOrWhiteSpace(diseaseName))
    {
        uniqueProtocols.Add(diseaseName);

        // Contar frequências (colunas 2+)
        for (int col = 2; col < table0.Columns.Count; col++)
        {
            var freq = table0.Rows[row][col]?.ToString()?.Trim();
            if (!string.IsNullOrWhiteSpace(freq) && double.TryParse(freq, out _))
            {
                totalFrequencies++;
            }
        }
    }
}

Console.WriteLine($"\n\n📈 ESTATÍSTICAS GLOBAIS:");
Console.WriteLine($"   Protocolos únicos (doenças): {uniqueProtocols.Count}");
Console.WriteLine($"   Total de frequências: {totalFrequencies}");
Console.WriteLine($"   Média de frequências por protocolo: {(totalFrequencies / (double)uniqueProtocols.Count):F1}");

Console.WriteLine("\n✅ Análise concluída!");
