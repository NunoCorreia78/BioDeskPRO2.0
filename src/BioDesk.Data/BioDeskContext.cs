using System;
using Microsoft.EntityFrameworkCore;
using BioDesk.Domain.Entities;

namespace BioDesk.Data;

/// <summary>
/// Contexto da base de dados para o BioDeskPro2
/// Configuração: SQLite com índices únicos para evitar duplicações
/// Seed: 3 pacientes de exemplo no arranque
/// </summary>
public class BioDeskContext : DbContext
{
    public DbSet<Paciente> Pacientes { get; set; }

    public BioDeskContext(DbContextOptions<BioDeskContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configuração da entidade Paciente (sem seed)
        modelBuilder.Entity<Paciente>(entity =>
        {
            entity.HasKey(p => p.Id);
            
            // Índice único para evitar duplicações
            entity.HasIndex(p => new { p.Nome, p.DataNascimento })
                  .IsUnique()
                  .HasDatabaseName("IX_Paciente_Unique");

            // Configurações de propriedades
            entity.Property(p => p.Nome)
                  .IsRequired()
                  .HasMaxLength(200);

            entity.Property(p => p.Email)
                  .IsRequired()
                  .HasMaxLength(255);

            entity.Property(p => p.Telefone)
                  .HasMaxLength(20);

            entity.Property(p => p.CriadoEm)
                  .IsRequired();

            entity.Property(p => p.AtualizadoEm)
                  .IsRequired();
        });

        // Seed de dados de exemplo
        SeedData(modelBuilder);
    }

    private static void SeedData(ModelBuilder modelBuilder)
    {
        var agora = DateTime.Now;

        var pacientes = new[]
        {
            new Paciente
            {
                Id = 1,
                Nome = "Ana Silva",
                DataNascimento = new DateTime(1985, 3, 15),
                Email = "ana.silva@email.com",
                Telefone = "912345678",
                CriadoEm = agora.AddDays(-30),
                AtualizadoEm = agora.AddDays(-2)
            },
            new Paciente
            {
                Id = 2,
                Nome = "João Ferreira",
                DataNascimento = new DateTime(1978, 7, 22),
                Email = "joao.ferreira@email.com",
                Telefone = "925678912",
                CriadoEm = agora.AddDays(-25),
                AtualizadoEm = agora.AddDays(-5)
            },
            new Paciente
            {
                Id = 3,
                Nome = "Maria Costa",
                DataNascimento = new DateTime(1992, 11, 8),
                Email = "maria.costa@email.com",
                Telefone = "934567823",
                CriadoEm = agora.AddDays(-20),
                AtualizadoEm = agora.AddDays(-1)
            }
        };

        modelBuilder.Entity<Paciente>().HasData(pacientes);
    }
}