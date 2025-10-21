using System;
using System.IO;
using System.Text;

var srcPath = Path.Combine(Directory.GetParent(Directory.GetCurrentDirectory())?.FullName ?? "", "src");

var files = Directory.GetFiles(srcPath, "*.xaml", SearchOption.AllDirectories)
    .Concat(Directory.GetFiles(srcPath, "*.cs", SearchOption.AllDirectories))
    .Where(f => !f.Contains("\\obj\\") && !f.Contains("\\bin\\"))
    .ToArray();

Console.WriteLine($"Processing {files.Length} files...");
int fixedCount = 0;

foreach (var file in files)
{
    try
    {
        // Ler como Latin-1 (ISO-8859-1) e reinterpretar como UTF-8
        var bytes = File.ReadAllBytes(file);
        var latin1 = Encoding.GetEncoding("ISO-8859-1");
        var latin1String = latin1.GetString(bytes);

        // Se não tem caracteres problemáticos, pular
        if (!latin1String.Any(c => c > 127 && c < 256))
            continue;

        // Reinterpretar: converter string Latin-1 para bytes UTF-8
        var utf8Bytes = Encoding.UTF8.GetBytes(latin1String);
        var correctedString = Encoding.UTF8.GetString(utf8Bytes);

        // Escrever com UTF-8 sem BOM
        File.WriteAllText(file, correctedString, new UTF8Encoding(false));
        Console.WriteLine($"FIXED: {Path.GetFileName(file)}");
        fixedCount++;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"ERROR in {Path.GetFileName(file)}: {ex.Message}");
    }
}

Console.WriteLine($"\nDONE! Fixed {fixedCount} files.");
