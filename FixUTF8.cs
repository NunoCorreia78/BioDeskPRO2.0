using System;
using System.IO;
using System.Text;
using System.Linq;

class FixUTF8
{
    static void Main(string[] args)
    {
        var replacements = new (string wrong, string correct)[]
        {
            ("Ã¡", "á"), ("Ã§", "ç"), ("Ã£", "ã"), ("Ã©", "é"),
            ("Ã­", "í"), ("Ãº", "ú"), ("Ã´", "ô"), ("Ã ", "à"),
            ("Ã³", "ó"), ("Ãª", "ê"), ("📧", "📧"), ("📞", "📞"),
            ("🌿", "🌿"), ("Ã‡", "Ç"), ("á¡", "á"), ("á§áµes", "ções"),
            ("á§áµ", "çõ"), ("á£o", "ão"), ("á©", "é"), ("áº", "ú"),
            ("á´", "ô"), ("á³", "ó"), ("áª", "ê"), ("á ", "à"),
            ("Ã§Ã£o", "ção"), ("Ã§Ãµes", "ções"), ("Ã§Ã£", "çã")
        };

        var srcPath = Path.Combine(Directory.GetCurrentDirectory(), "src");

        // Fix CS files
        var csFiles = Directory.GetFiles(srcPath, "*.cs", SearchOption.AllDirectories);
        Console.WriteLine($"Fixing {csFiles.Length} C# files...");

        foreach (var file in csFiles)
        {
            FixFile(file, replacements);
        }

        // Fix XAML files
        var xamlFiles = Directory.GetFiles(srcPath, "*.xaml", SearchOption.AllDirectories);
        Console.WriteLine($"Fixing {xamlFiles.Length} XAML files...");

        foreach (var file in xamlFiles)
        {
            FixFile(file, replacements);
        }

        Console.WriteLine("DONE! All files fixed with UTF-8 encoding.");
    }

    static void FixFile(string filePath, (string wrong, string correct)[] replacements)
    {
        try
        {
            // Read with UTF-8 encoding
            var content = File.ReadAllText(filePath, Encoding.UTF8);
            var original = content;

            // Apply all replacements
            foreach (var (wrong, correct) in replacements)
            {
                content = content.Replace(wrong, correct);
            }

            // Only write if changed
            if (content != original)
            {
                // Write with UTF-8 BOM
                File.WriteAllText(filePath, content, new UTF8Encoding(true));
                Console.WriteLine($"FIXED: {Path.GetFileName(filePath)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR in {filePath}: {ex.Message}");
        }
    }
}
