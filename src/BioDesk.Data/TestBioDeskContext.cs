using System;
using Microsoft.EntityFrameworkCore;
using BioDesk.Domain.Entities;

namespace BioDesk.Data;

/// <summary>
/// Contexto de teste sem dados de seed
/// Usado apenas para testes unitários
/// </summary>
public class TestBioDeskContext : DbContext
{
    public DbSet<Paciente> Pacientes { get; set; }

    public TestBioDeskContext(DbContextOptions<TestBioDeskContext> options) : base(options)
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

        // SEM SEED DATA para testes limpos
    }
}