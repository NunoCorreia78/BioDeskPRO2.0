using System;
using System.Collections.Generic;
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
    
    // DbSets para Avaliação Clínica (legado - manter compatibilidade)
    public DbSet<AvaliacaoClinica> AvaliacoesClinicas { get; set; }
    public DbSet<MotivoConsulta> MotivosConsulta { get; set; }
    public DbSet<HistoriaClinica> HistoriaClinicas { get; set; }
    public DbSet<RevisaoSistemas> RevisoesSistemas { get; set; }
    public DbSet<EstiloVida> EstilosVida { get; set; }
    public DbSet<HistoriaFamiliar> HistoriasFamiliares { get; set; }

    // DbSets para Nova Arquitetura Clínica (MVP)
    public DbSet<SessaoClinica> SessoesClinicas { get; set; }
    public DbSet<SintomaSessao> SintomasSessao { get; set; }
    public DbSet<SintomaAtivo> SintomasAtivos { get; set; }
    public DbSet<AlteracaoMedicacao> AlteracoesMedicacao { get; set; }
    public DbSet<MedicacaoAtual> MedicacaoAtual { get; set; }
    public DbSet<RedFlag> RedFlags { get; set; }
    public DbSet<DeclaracaoLegal> DeclaracoesLegais { get; set; }

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

        // Configuração das entidades de Avaliação Clínica
        ConfigurarAvaliacaoClinica(modelBuilder);

        // Seed de dados de exemplo
        SeedData(modelBuilder);
    }

    private static void ConfigurarAvaliacaoClinica(ModelBuilder modelBuilder)
    {
        // Configuração da AvaliacaoClinica
        modelBuilder.Entity<AvaliacaoClinica>(entity =>
        {
            entity.HasKey(a => a.Id);
            
            // Relacionamento com Paciente (1:N)
            entity.HasOne(a => a.Paciente)
                  .WithMany()
                  .HasForeignKey(a => a.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Relacionamentos One-to-One opcionais
            entity.HasOne(a => a.MotivoConsulta)
                  .WithOne(m => m.AvaliacaoClinica)
                  .HasForeignKey<MotivoConsulta>(m => m.AvaliacaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(a => a.HistoriaClinica)
                  .WithOne(h => h.AvaliacaoClinica)
                  .HasForeignKey<HistoriaClinica>(h => h.AvaliacaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(a => a.RevisaoSistemas)
                  .WithOne(r => r.AvaliacaoClinica)
                  .HasForeignKey<RevisaoSistemas>(r => r.AvaliacaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(a => a.EstiloVida)
                  .WithOne(e => e.AvaliacaoClinica)
                  .HasForeignKey<EstiloVida>(e => e.AvaliacaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(a => a.HistoriaFamiliar)
                  .WithOne(h => h.AvaliacaoClinica)
                  .HasForeignKey<HistoriaFamiliar>(h => h.AvaliacaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Índices para performance
            entity.HasIndex(a => a.PacienteId)
                  .HasDatabaseName("IX_AvaliacaoClinica_PacienteId");
            
            entity.HasIndex(a => a.DataCriacao)
                  .HasDatabaseName("IX_AvaliacaoClinica_DataCriacao");
        });

        // Configuração do MotivoConsulta
        modelBuilder.Entity<MotivoConsulta>(entity =>
        {
            entity.HasKey(m => m.Id);
            entity.Property(m => m.MotivosJson).HasMaxLength(1000);
            entity.Property(m => m.OutroMotivo).HasMaxLength(200);
            entity.Property(m => m.Localizacao).HasMaxLength(100);
            entity.Property(m => m.Lado).HasMaxLength(20);
            entity.Property(m => m.Duracao).HasMaxLength(50);
            entity.Property(m => m.Evolucao).HasMaxLength(20);
            entity.Property(m => m.CaraterJson).HasMaxLength(500);
            entity.Property(m => m.FatoresAgravantesJson).HasMaxLength(500);
            entity.Property(m => m.FatoresAlivioJson).HasMaxLength(500);
            entity.Property(m => m.Observacoes).HasMaxLength(1000);
        });

        // Configuração da HistoriaClinica
        modelBuilder.Entity<HistoriaClinica>(entity =>
        {
            entity.HasKey(h => h.Id);
            entity.Property(h => h.DoencasCronicasJson).HasMaxLength(1000);
            entity.Property(h => h.CirurgiasJson).HasMaxLength(2000);
            entity.Property(h => h.TiposAlergiasJson).HasMaxLength(500);
            entity.Property(h => h.EspecificarAlergias).HasMaxLength(1000);
            entity.Property(h => h.MedicacaoAtualJson).HasMaxLength(2000);
            entity.Property(h => h.SuplementacaoJson).HasMaxLength(2000);
            entity.Property(h => h.VacinacaoJson).HasMaxLength(500);
            entity.Property(h => h.Observacoes).HasMaxLength(1000);
        });

        // Configuração da RevisaoSistemas
        modelBuilder.Entity<RevisaoSistemas>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.Property(r => r.CardiovascularJson).HasMaxLength(500);
            entity.Property(r => r.CardiovascularObs).HasMaxLength(500);
            entity.Property(r => r.RespiratorioJson).HasMaxLength(500);
            entity.Property(r => r.RespiratorioObs).HasMaxLength(500);
            entity.Property(r => r.DigestivoJson).HasMaxLength(500);
            entity.Property(r => r.DigestivoObs).HasMaxLength(500);
            entity.Property(r => r.RenalUrinarioJson).HasMaxLength(500);
            entity.Property(r => r.RenalUrinarioObs).HasMaxLength(500);
            entity.Property(r => r.EndocrinoMetabolicoJson).HasMaxLength(500);
            entity.Property(r => r.EndocrinoMetabolicoObs).HasMaxLength(500);
            entity.Property(r => r.MusculoEsqueleticoJson).HasMaxLength(500);
            entity.Property(r => r.MusculoEsqueleticoObs).HasMaxLength(500);
            entity.Property(r => r.NeurologicoJson).HasMaxLength(500);
            entity.Property(r => r.NeurologicoObs).HasMaxLength(500);
            entity.Property(r => r.PeleJson).HasMaxLength(500);
            entity.Property(r => r.PeleObs).HasMaxLength(500);
            entity.Property(r => r.HumorSonoEnergiaJson).HasMaxLength(500);
            entity.Property(r => r.HumorSonoEnergiaObs).HasMaxLength(500);
        });

        // Configuração do EstiloVida
        modelBuilder.Entity<EstiloVida>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.AlimentacaoJson).HasMaxLength(500);
            entity.Property(e => e.Hidratacao).HasMaxLength(20);
            entity.Property(e => e.ExercicioJson).HasMaxLength(500);
            entity.Property(e => e.ExercicioFrequencia).HasMaxLength(50);
            entity.Property(e => e.Tabaco).HasMaxLength(20);
            entity.Property(e => e.Alcool).HasMaxLength(20);
            entity.Property(e => e.Cafeina).HasMaxLength(20);
            entity.Property(e => e.SonoJson).HasMaxLength(500);
            entity.Property(e => e.Observacoes).HasMaxLength(1000);
        });

        // Configuração da HistoriaFamiliar
        modelBuilder.Entity<HistoriaFamiliar>(entity =>
        {
            entity.HasKey(h => h.Id);
            entity.Property(h => h.AntecedentesJson).HasMaxLength(1000);
            entity.Property(h => h.ParentescoJson).HasMaxLength(500);
            entity.Property(h => h.Observacoes).HasMaxLength(1000);
        });
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

        // Configurações para Nova Arquitetura Clínica
        ConfigurarArquiteturaClinica(modelBuilder);
    }

    /// <summary>
    /// Configurações EF Core para a nova arquitetura clínica
    /// </summary>
    private static void ConfigurarArquiteturaClinica(ModelBuilder modelBuilder)
    {
        // SessaoClinica
        modelBuilder.Entity<SessaoClinica>(entity =>
        {
            entity.HasKey(s => s.Id);
            entity.HasIndex(s => new { s.PacienteId, s.DataSessao });
            
            entity.HasOne(s => s.Paciente)
                  .WithMany()
                  .HasForeignKey(s => s.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // SintomaSessao
        modelBuilder.Entity<SintomaSessao>(entity =>
        {
            entity.HasKey(s => s.Id);
            entity.HasIndex(s => s.SessaoClinicaId);
            
            entity.HasOne(s => s.SessaoClinica)
                  .WithMany(sc => sc.SintomasTrabalhados)
                  .HasForeignKey(s => s.SessaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // SintomaAtivo
        modelBuilder.Entity<SintomaAtivo>(entity =>
        {
            entity.HasKey(s => s.Id);
            entity.HasIndex(s => new { s.PacienteId, s.Nome }).IsUnique(); // Evitar duplicação
            entity.HasIndex(s => new { s.PacienteId, s.Prioridade });
            
            entity.HasOne(s => s.Paciente)
                  .WithMany()
                  .HasForeignKey(s => s.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // AlteracaoMedicacao
        modelBuilder.Entity<AlteracaoMedicacao>(entity =>
        {
            entity.HasKey(a => a.Id);
            entity.HasIndex(a => a.SessaoClinicaId);
            
            entity.HasOne(a => a.SessaoClinica)
                  .WithMany(sc => sc.AlteracoesMedicacao)
                  .HasForeignKey(a => a.SessaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // MedicacaoAtual
        modelBuilder.Entity<MedicacaoAtual>(entity =>
        {
            entity.HasKey(m => m.Id);
            entity.HasIndex(m => new { m.PacienteId, m.Nome, m.Dose }).IsUnique(); // Evitar duplicação
            entity.HasIndex(m => new { m.PacienteId, m.Estado });
            
            entity.HasOne(m => m.Paciente)
                  .WithMany()
                  .HasForeignKey(m => m.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // RedFlag
        modelBuilder.Entity<RedFlag>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.HasIndex(r => r.SessaoClinicaId);
            entity.HasIndex(r => new { r.Estado, r.NivelRisco });
            
            entity.HasOne(r => r.SessaoClinica)
                  .WithMany(sc => sc.RedFlags)
                  .HasForeignKey(r => r.SessaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // DeclaracaoLegal (relação 1:1 com SessaoClinica)
        modelBuilder.Entity<DeclaracaoLegal>(entity =>
        {
            entity.HasKey(d => d.Id);
            entity.HasIndex(d => d.SessaoClinicaId).IsUnique();
            
            entity.HasOne(d => d.SessaoClinica)
                  .WithOne(sc => sc.Declaracao)
                  .HasForeignKey<DeclaracaoLegal>(d => d.SessaoClinicaId)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }
}