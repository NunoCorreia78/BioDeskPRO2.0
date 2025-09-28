using System;
using Microsoft.EntityFrameworkCore;
using BioDesk.Domain.Entities;

namespace BioDesk.Data;

/// <summary>
/// DbContext principal do BioDeskPro2
/// Implementa todas as entidades para sistema de fichas de paciente completo
/// </summary>
public class BioDeskDbContext : DbContext
{
    public BioDeskDbContext(DbContextOptions<BioDeskDbContext> options) : base(options)
    {
    }

    // === ENTIDADES PRINCIPAIS ===
    public DbSet<Paciente> Pacientes { get; set; } = null!;
    public DbSet<Contacto> Contactos { get; set; } = null!;
    public DbSet<HistoricoMedico> HistoricosMedicos { get; set; } = null!;
    public DbSet<Consulta> Consultas { get; set; } = null!;
    public DbSet<Consentimento> Consentimentos { get; set; } = null!;
    public DbSet<IrisAnalise> IrisAnalises { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // === CONFIGURAÇÃO PACIENTE ===
        modelBuilder.Entity<Paciente>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.NumeroProcesso)
                  .IsUnique()
                  .HasDatabaseName("IX_Pacientes_NumeroProcesso");

            entity.HasIndex(e => e.NomeCompleto)
                  .HasDatabaseName("IX_Pacientes_NomeCompleto");

            entity.HasIndex(e => e.DataNascimento)
                  .HasDatabaseName("IX_Pacientes_DataNascimento");

            // Relacionamento 1:1 com Contacto
            entity.HasOne(p => p.Contacto)
                  .WithOne(c => c.Paciente)
                  .HasForeignKey<Contacto>(c => c.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Relacionamentos 1:N
            entity.HasMany(p => p.HistoricoMedico)
                  .WithOne(h => h.Paciente)
                  .HasForeignKey(h => h.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasMany(p => p.Consultas)
                  .WithOne(c => c.Paciente)
                  .HasForeignKey(c => c.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasMany(p => p.Consentimentos)
                  .WithOne(c => c.Paciente)
                  .HasForeignKey(c => c.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasMany(p => p.IrisAnalises)
                  .WithOne(i => i.Paciente)
                  .HasForeignKey(i => i.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // === CONFIGURAÇÃO CONTACTO ===
        modelBuilder.Entity<Contacto>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PacienteId)
                  .IsUnique()
                  .HasDatabaseName("IX_Contactos_PacienteId");

            entity.HasIndex(e => e.EmailPrincipal)
                  .HasDatabaseName("IX_Contactos_EmailPrincipal");
        });

        // === CONFIGURAÇÃO HISTÓRICO MÉDICO ===
        modelBuilder.Entity<HistoricoMedico>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PacienteId)
                  .HasDatabaseName("IX_HistoricosMedicos_PacienteId");
        });

        // === CONFIGURAÇÃO CONSULTA ===
        modelBuilder.Entity<Consulta>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PacienteId)
                  .HasDatabaseName("IX_Consultas_PacienteId");

            entity.HasIndex(e => e.DataHoraConsulta)
                  .HasDatabaseName("IX_Consultas_DataHoraConsulta");

            entity.HasIndex(e => e.TipoConsulta)
                  .HasDatabaseName("IX_Consultas_TipoConsulta");

            entity.HasIndex(e => e.Estado)
                  .HasDatabaseName("IX_Consultas_Estado");
        });

        // === CONFIGURAÇÃO CONSENTIMENTO ===
        modelBuilder.Entity<Consentimento>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PacienteId)
                  .HasDatabaseName("IX_Consentimentos_PacienteId");

            entity.HasIndex(e => e.TipoTratamento)
                  .HasDatabaseName("IX_Consentimentos_TipoTratamento");

            entity.HasIndex(e => e.Estado)
                  .HasDatabaseName("IX_Consentimentos_Estado");

            entity.HasIndex(e => e.DataExpiracao)
                  .HasDatabaseName("IX_Consentimentos_DataExpiracao");
        });

        // === CONFIGURAÇÃO ÍRIS ANÁLISE ===
        modelBuilder.Entity<IrisAnalise>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PacienteId)
                  .HasDatabaseName("IX_IrisAnalises_PacienteId");

            entity.HasIndex(e => e.DataHoraAnalise)
                  .HasDatabaseName("IX_IrisAnalises_DataHoraAnalise");
        });

        // === DADOS DE SEED ===
        SeedData(modelBuilder);
    }

    /// <summary>
    /// Dados de seed para desenvolvimento e testes
    /// </summary>
    private static void SeedData(ModelBuilder modelBuilder)
    {
        // SEED: 3 Pacientes base para desenvolvimento
        var pacientes = new[]
        {
            new Paciente
            {
                Id = 1,
                NumeroProcesso = "PAC-2025-001",
                NomeCompleto = "João Silva Santos",
                DataNascimento = new DateTime(1980, 5, 15),
                Genero = "Masculino",
                NomePreferido = "João",
                Nacionalidade = "Portuguesa",
                EstadoCivil = "Casado",
                Profissao = "Engenheiro Informático",
                EstadoRegisto = "Incompleto",
                DataCriacao = DateTime.UtcNow.AddDays(-30)
            },
            new Paciente
            {
                Id = 2,
                NumeroProcesso = "PAC-2025-002",
                NomeCompleto = "Maria Fernanda Costa",
                DataNascimento = new DateTime(1975, 11, 22),
                Genero = "Feminino",
                NomePreferido = "Maria",
                Nacionalidade = "Portuguesa",
                EstadoCivil = "Solteira",
                Profissao = "Professora",
                EstadoRegisto = "Em Progresso",
                ProgressoAbas = "{\"Aba1\":true,\"Aba2\":true,\"Aba3\":false}",
                DataCriacao = DateTime.UtcNow.AddDays(-15)
            },
            new Paciente
            {
                Id = 3,
                NumeroProcesso = "PAC-2025-003",
                NomeCompleto = "Carlos António Pereira",
                DataNascimento = new DateTime(1990, 3, 8),
                Genero = "Masculino",
                NIF = "123456789",
                Nacionalidade = "Portuguesa",
                EstadoCivil = "União de Facto",
                Profissao = "Designer Gráfico",
                EstadoRegisto = "Completo",
                ProgressoAbas = "{\"Aba1\":true,\"Aba2\":true,\"Aba3\":true,\"Aba4\":true,\"Aba5\":true,\"Aba6\":false}",
                DataCriacao = DateTime.UtcNow.AddDays(-7)
            }
        };

        modelBuilder.Entity<Paciente>().HasData(pacientes);

        // SEED: Contactos para os pacientes
        var contactos = new[]
        {
            new Contacto
            {
                Id = 1,
                PacienteId = 1,
                RuaAvenida = "Rua das Flores",
                Numero = "123",
                AndarFraccao = "2º Esq",
                CodigoPostal = "1000-001",
                Localidade = "Lisboa",
                Distrito = "Lisboa",
                TelefonePrincipal = "912345678",
                EmailPrincipal = "joao.santos@email.com"
            },
            new Contacto
            {
                Id = 2,
                PacienteId = 2,
                RuaAvenida = "Avenida da República",
                Numero = "456",
                CodigoPostal = "4000-100",
                Localidade = "Porto",
                Distrito = "Porto",
                TelefonePrincipal = "923456789",
                TelefoneAlternativo = "225551234",
                EmailPrincipal = "maria.costa@email.com"
            },
            new Contacto
            {
                Id = 3,
                PacienteId = 3,
                RuaAvenida = "Praça do Comércio",
                Numero = "789",
                CodigoPostal = "3000-050",
                Localidade = "Coimbra",
                Distrito = "Coimbra",
                TelefonePrincipal = "934567890",
                EmailPrincipal = "carlos.pereira@email.com",
                EmailAlternativo = "c.pereira.design@email.com"
            }
        };

        modelBuilder.Entity<Contacto>().HasData(contactos);
    }
}
