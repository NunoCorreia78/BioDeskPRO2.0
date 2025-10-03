using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;

var dbPath = Path.Combine(Environment.CurrentDirectory, "biodesk.db");
var options = new DbContextOptionsBuilder<BioDeskDbContext>()
    .UseSqlite($"Data Source={dbPath}")
    .Options;

using var context = new BioDeskDbContext(options);

Console.WriteLine("=== EMAILS NA BASE DE DADOS ===\n");

var emails = await context.Comunicacoes
    .OrderByDescending(c => c.DataCriacao)
    .Take(15)
    .Select(c => new
    {
        c.Id,
        c.DataCriacao,
        c.Assunto,
        c.Status,
        c.IsEnviado,
        c.TentativasEnvio,
        c.ProximaTentativa,
        c.UltimoErro
    })
    .ToListAsync();

foreach (var email in emails)
{
    Console.WriteLine($"ID: {email.Id}");
    Console.WriteLine($"Data: {email.DataCriacao:dd/MM/yyyy HH:mm:ss}");
    Console.WriteLine($"Assunto: {email.Assunto}");
    Console.WriteLine($"Status: {email.Status} | Enviado: {email.IsEnviado}");
    Console.WriteLine($"Tentativas: {email.TentativasEnvio}");
    Console.WriteLine($"Próxima Tentativa: {email.ProximaTentativa?.ToString("dd/MM/yyyy HH:mm:ss") ?? "N/A"}");
    Console.WriteLine($"Último Erro: {email.UltimoErro ?? "N/A"}");
    Console.WriteLine(new string('-', 80));
}

var agendados = emails.Count(e => e.Status == BioDesk.Domain.Entities.StatusComunicacao.Agendado);
var enviados = emails.Count(e => e.Status == BioDesk.Domain.Entities.StatusComunicacao.Enviado);
var falhados = emails.Count(e => e.Status == BioDesk.Domain.Entities.StatusComunicacao.Falhado);

Console.WriteLine($"\n=== RESUMO ===");
Console.WriteLine($"Agendados: {agendados}");
Console.WriteLine($"Enviados: {enviados}");
Console.WriteLine($"Falhados: {falhados}");
