// Teste rápido para verificar se o comando existe

#r "src/BioDesk.ViewModels/bin/Debug/net8.0-windows/BioDesk.ViewModels.dll"
#r "src/BioDesk.Services/bin/Debug/net8.0/BioDesk.Services.dll"
#r "src/BioDesk.Data/bin/Debug/net8.0/BioDesk.Data.dll"
#r "src/BioDesk.Domain/bin/Debug/net8.0/BioDesk.Domain.dll"

using BioDesk.ViewModels.Abas;
using System.Reflection;

Console.WriteLine("🔍 Verificando comandos em RegistoConsultasViewModel...\n");

var type = typeof(RegistoConsultasViewModel);
var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);

Console.WriteLine("📋 PROPRIEDADES (comandos potenciais):");
foreach (var prop in properties.Where(p => p.Name.EndsWith("Command")))
{
    Console.WriteLine($"  ✅ {prop.Name} ({prop.PropertyType.Name})");
}

Console.WriteLine($"\n🔢 Total de comandos encontrados: {properties.Count(p => p.Name.EndsWith("Command"))}");

// Verificar especificamente o comando que precisamos
var comandoPdf = properties.FirstOrDefault(p => p.Name == "GerarPdfPrescricaoAsyncCommand");
if (comandoPdf != null)
{
    Console.WriteLine($"\n🎯 COMANDO ENCONTRADO: {comandoPdf.Name}");
    Console.WriteLine($"   Tipo: {comandoPdf.PropertyType.FullName}");
}
else
{
    Console.WriteLine("\n❌ COMANDO 'GerarPdfPrescricaoAsyncCommand' NÃO ENCONTRADO!");

    // Listar comandos similares
    var similarCommands = properties.Where(p => p.Name.Contains("Pdf") || p.Name.Contains("Prescricao"));
    if (similarCommands.Any())
    {
        Console.WriteLine("\n⚠️ Comandos similares encontrados:");
        foreach (var cmd in similarCommands)
        {
            Console.WriteLine($"   - {cmd.Name}");
        }
    }
}
