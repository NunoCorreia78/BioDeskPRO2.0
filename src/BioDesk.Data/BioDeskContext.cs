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
    public DbSet<Consulta> Consultas { get; set; }

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
            
            // Índice único para evitar duplicações (simplificado após remoção DataNascimento)
            entity.HasIndex(p => p.Nome)
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
                DataNascimento = new DateTime(1990, 7, 22),
                Email = "joao.ferreira@email.com",
                Telefone = "925678912",
                CriadoEm = agora.AddDays(-25),
                AtualizadoEm = agora.AddDays(-5)
            },
            new Paciente
            {
                Id = 3,
                Nome = "Maria Costa",
                DataNascimento = new DateTime(1988, 11, 10),
                Email = "maria.costa@email.com",
                Telefone = "934567823",
                CriadoEm = agora.AddDays(-20),
                AtualizadoEm = agora.AddDays(-1)
            }
        };

        // Configuração da entidade Consulta
        modelBuilder.Entity<Consulta>(entity =>
        {
            entity.HasKey(c => c.Id);

            // Relacionamento com Paciente
            entity.HasOne(c => c.Paciente)
                  .WithMany(p => p.Consultas)
                  .HasForeignKey(c => c.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Índice para performance de consultas por paciente
            entity.HasIndex(c => c.PacienteId)
                  .HasDatabaseName("IX_Consulta_PacienteId");

            // Índice para performance de consultas por data
            entity.HasIndex(c => c.DataConsulta)
                  .HasDatabaseName("IX_Consulta_DataConsulta");

            // Configurações de propriedades
            entity.Property(c => c.TipoConsulta)
                  .IsRequired()
                  .HasMaxLength(50);

            entity.Property(c => c.Status)
                  .IsRequired()
                  .HasMaxLength(20);

            entity.Property(c => c.Notas)
                  .HasMaxLength(2000);

            entity.Property(c => c.Valor)
                  .HasColumnType("decimal(10,2)");

            entity.Property(c => c.DataCriacao)
                  .IsRequired();
        });

        // Seed de consultas de exemplo
        var consultasExemplo = new[]
        {
            new Consulta
            {
                Id = 1,
                PacienteId = 1,
                DataConsulta = agora.AddDays(-14),
                TipoConsulta = "Primeira",
                Notas = "Primeira consulta de naturopatia. Paciente apresenta sintomas de stress.",
                Valor = 60.00m,
                Status = "Realizada",
                DataCriacao = agora.AddDays(-14)
            },
            new Consulta
            {
                Id = 2,
                PacienteId = 1,
                DataConsulta = agora.AddDays(-7),
                TipoConsulta = "Seguimento",
                Notas = "Seguimento - melhoria dos sintomas de stress.",
                Valor = 45.00m,
                Status = "Realizada",
                DataCriacao = agora.AddDays(-7)
            },
            new Consulta
            {
                Id = 3,
                PacienteId = 2,
                DataConsulta = agora.AddDays(-10),
                TipoConsulta = "Primeira",
                Notas = "Primeira consulta de osteopatia. Dores lombares.",
                Valor = 65.00m,
                Status = "Realizada",
                DataCriacao = agora.AddDays(-10)
            },
            new Consulta
            {
                Id = 4,
                PacienteId = 3,
                DataConsulta = agora.AddDays(2),
                TipoConsulta = "Primeira",
                Notas = "Consulta agendada para medicina quântica.",
                Valor = 70.00m,
                Status = "Agendada",
                DataCriacao = agora.AddDays(-3)
            }
        };

        modelBuilder.Entity<Paciente>().HasData(pacientes);
        modelBuilder.Entity<Consulta>().HasData(consultasExemplo);
    }
}