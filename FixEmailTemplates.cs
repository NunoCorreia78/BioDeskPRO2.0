using System;
using System.IO;
using System.Text;

class FixEmailTemplates
{
    static void Main()
    {
        var filePath = @"c:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\src\BioDesk.ViewModels\Abas\ComunicacaoViewModel.cs";

        // Ler com UTF-8
        var content = File.ReadAllText(filePath, Encoding.UTF8);

        // Aplicar correções
        content = content.Replace("Olá", "Olá");
        content = content.Replace("ddocumentação necessária", "documentação necessária");
        content = content.Replace("dúvida", "dúvida");
        content = content.Replace("Ã  disposiÃ§Ã£o", "à disposição");
        content = content.Replace("Bioenergética", "Bioenergética");
        content = content.Replace("prescrição", "prescrição");
        content = content.Replace("prescrição", "Prescrição");
        content = content.Replace("Confirmação", "Confirmação");
        content = content.Replace("está", "está");
        content = content.Replace("disponível", "disponível");

        // Emojis
        content = content.Replace("📧", "📧");
        content = content.Replace("📞", "📞");
        content = content.Replace("🌿", "🌿");

        // Gravar com UTF-8 sem BOM
        File.WriteAllText(filePath, content, new UTF8Encoding(false));

        Console.WriteLine("✅ Correções aplicadas com sucesso!");
    }
}
