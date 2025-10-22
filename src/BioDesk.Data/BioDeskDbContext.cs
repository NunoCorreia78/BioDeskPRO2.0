using System;
using System.Collections.Generic;
using System.Linq;
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
    public DbSet<Consulta> Consultas { get; set; } = null!;
    public DbSet<Consentimento> Consentimentos { get; set; } = null!;
    public DbSet<IrisAnalise> IrisAnalises { get; set; } = null!;
    public DbSet<SessionHistorico> SessionHistoricos { get; set; } = null!;

    // === CONFIGURAÇÃO GLOBAL ===
    public DbSet<ConfiguracaoClinica> ConfiguracaoClinica { get; set; } = null!;

    // === DECLARAÇÃO DE SAÚDE (ABA 2) ===
    public DbSet<DeclaracaoSaude> DeclaracoesSaude { get; set; } = null!;

    // === SESSÕES CLÍNICAS (ABA 4) ===
    public DbSet<Sessao> Sessoes { get; set; } = null!;
    public DbSet<AbordagemSessao> AbordagensSessoes { get; set; } = null!;

    // === COMUNICAÇÃO E SEGUIMENTO (ABA 5) ===
    public DbSet<Comunicacao> Comunicacoes { get; set; } = null!;
    public DbSet<AnexoComunicacao> AnexosComunicacoes { get; set; } = null!;

    // === IRISDIAGNÓSTICO (ABA 6) ===
    public DbSet<IrisImagem> IrisImagens { get; set; } = null!;
    public DbSet<IrisMarca> IrisMarcas { get; set; } = null!;

    // === TERAPIAS BIOENERGÉTICAS (ABA 8) ===
    public DbSet<ProtocoloTerapeutico> ProtocolosTerapeuticos { get; set; } = null!;
    public DbSet<PlanoTerapia> PlanosTerapia { get; set; } = null!;
    public DbSet<Terapia> Terapias { get; set; } = null!;
    public DbSet<SessaoTerapia> SessoesTerapia { get; set; } = null!;
    public DbSet<LeituraBioenergetica> LeiturasBioenergeticas { get; set; } = null!;
    public DbSet<EventoHardware> EventosHardware { get; set; } = null!;
    public DbSet<ImportacaoExcelLog> ImportacoesExcelLog { get; set; } = null!;

    // === TEMPLATES GLOBAIS E DOCUMENTOS EXTERNOS ===
    public DbSet<TemplateGlobal> TemplatesGlobais { get; set; } = null!;
    public DbSet<DocumentoExternoPaciente> DocumentosExternosPacientes { get; set; } = null!;

    // === SISTEMA CORE INFORMACIONAL (INERGETIX-INSPIRED) ===
    public DbSet<ItemBancoCore> ItensBancoCore { get; set; } = null!;

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

            // Relacionamento 1:1 com DeclaracaoSaude
            entity.HasOne(p => p.DeclaracaoSaude)
                  .WithOne(d => d.Paciente)
                  .HasForeignKey<DeclaracaoSaude>(d => d.PacienteId)
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

        // === CONFIGURAÇÃO DECLARAÇÃO DE SAÚDE (ABA 2) ===
        modelBuilder.Entity<DeclaracaoSaude>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PacienteId)
                  .IsUnique()
                  .HasDatabaseName("IX_DeclaracoesSaude_PacienteId");

            entity.Property(e => e.EspecificacaoOutrasDoencas)
                  .HasMaxLength(1000);

            entity.Property(e => e.SuplementosAlimentares)
                  .HasMaxLength(1000);

            entity.Property(e => e.MedicamentosNaturais)
                  .HasMaxLength(1000);
        });

        // === CONFIGURAÇÃO SESSÃO (ABA 4 - REGISTO DE CONSULTAS) ===
        modelBuilder.Entity<Sessao>(entity =>
        {
            entity.HasKey(e => e.Id);

            // Índices para performance
            entity.HasIndex(e => e.PacienteId)
                  .HasDatabaseName("IX_Sessoes_PacienteId");

            entity.HasIndex(e => e.DataHora)
                  .HasDatabaseName("IX_Sessoes_DataHora");

            entity.HasIndex(e => e.IsDeleted)
                  .HasDatabaseName("IX_Sessoes_IsDeleted");

            // Relacionamento com Paciente
            entity.HasOne(s => s.Paciente)
                  .WithMany()
                  .HasForeignKey(s => s.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Relacionamento com Abordagens (Many-to-Many)
            entity.HasMany(s => s.Abordagens)
                  .WithOne(a => a.Sessao)
                  .HasForeignKey(a => a.SessaoId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Configurações de campos
            entity.Property(s => s.Motivo)
                  .IsRequired()
                  .HasMaxLength(500);

            entity.Property(s => s.Contexto)
                  .HasMaxLength(1000);

            entity.Property(s => s.Achados)
                  .HasMaxLength(2000);

            entity.Property(s => s.PressaoArterial)
                  .HasMaxLength(20);

            entity.Property(s => s.Peso)
                  .HasPrecision(5, 2); // Ex: 150.50 kg

            entity.Property(s => s.Temperatura)
                  .HasPrecision(4, 2); // Ex: 36.50 °C

            entity.Property(s => s.OutrasMedicoes)
                  .HasMaxLength(1000);

            entity.Property(s => s.Avaliacao)
                  .HasMaxLength(2000);

            entity.Property(s => s.Plano)
                  .HasMaxLength(3000);
        });

        // === CONFIGURAÇÃO ABORDAGEM SESSÃO (Many-to-Many) ===
        modelBuilder.Entity<AbordagemSessao>(entity =>
        {
            entity.HasKey(e => e.Id);

            // Índice composto para garantir unicidade (Sessão + TipoAbordagem)
            entity.HasIndex(e => new { e.SessaoId, e.TipoAbordagem })
                  .IsUnique()
                  .HasDatabaseName("IX_AbordagensSessoes_SessaoId_TipoAbordagem");

            entity.Property(e => e.Observacoes)
                  .HasMaxLength(1000);
        });

        // === CONFIGURAÇÃO GLOBAL DA CLÍNICA ===
        modelBuilder.Entity<ConfiguracaoClinica>(entity =>
        {
            entity.HasKey(e => e.Id);

            // Garantir que existe apenas UMA configuração (Id = 1)
            entity.Property(e => e.Id)
                    .ValueGeneratedNever(); // Id não é auto-incremento

            entity.Property(e => e.NomeClinica)
                    .IsRequired()
                    .HasMaxLength(200);

            entity.Property(e => e.Morada)
                    .HasMaxLength(500);

            entity.Property(e => e.Telefone)
                    .HasMaxLength(50);

            entity.Property(e => e.Email)
                    .HasMaxLength(100);

            entity.Property(e => e.NIPC)
                    .HasMaxLength(20);

            entity.Property(e => e.LogoPath)
                    .HasMaxLength(500);

            entity.Property(e => e.DataAtualizacao)
                    .IsRequired();
        });

        // === CONFIGURAÇÃO TEMPLATES GLOBAIS ===
        modelBuilder.Entity<TemplateGlobal>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.Nome)
                  .HasDatabaseName("IX_TemplatesGlobais_Nome");

            entity.HasIndex(e => e.Tipo)
                  .HasDatabaseName("IX_TemplatesGlobais_Tipo");

            entity.HasIndex(e => e.Categoria)
                  .HasDatabaseName("IX_TemplatesGlobais_Categoria");

            entity.HasIndex(e => e.DisponivelEmail)
                  .HasDatabaseName("IX_TemplatesGlobais_DisponivelEmail");

            entity.HasIndex(e => e.IsDeleted)
                  .HasDatabaseName("IX_TemplatesGlobais_IsDeleted");
        });

        // === CONFIGURAÇÃO DOCUMENTOS EXTERNOS PACIENTE ===
        modelBuilder.Entity<DocumentoExternoPaciente>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PacienteId)
                  .HasDatabaseName("IX_DocumentosExternos_PacienteId");

            entity.HasIndex(e => e.DataDocumento)
                  .HasDatabaseName("IX_DocumentosExternos_DataDocumento");

            entity.HasIndex(e => e.Categoria)
                  .HasDatabaseName("IX_DocumentosExternos_Categoria");

            entity.HasIndex(e => e.IsDeleted)
                  .HasDatabaseName("IX_DocumentosExternos_IsDeleted");

            // Relacionamento com Paciente
            entity.HasOne(d => d.Paciente)
                  .WithMany()
                  .HasForeignKey(d => d.PacienteId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // === CONFIGURAÇÃO TERAPIAS BIOENERGÉTICAS ===

        // PlanoTerapia
        modelBuilder.Entity<PlanoTerapia>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.SessaoId)
                  .HasDatabaseName("IX_PlanosTerapia_SessaoId");

            entity.HasIndex(e => e.Estado)
                  .HasDatabaseName("IX_PlanosTerapia_Estado");

            entity.HasIndex(e => e.CriadoEm)
                  .HasDatabaseName("IX_PlanosTerapia_CriadoEm");

            // Relacionamento com Sessao
            entity.HasOne(p => p.Sessao)
                  .WithMany()
                  .HasForeignKey(p => p.SessaoId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Terapia
        modelBuilder.Entity<Terapia>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.PlanoTerapiaId)
                  .HasDatabaseName("IX_Terapias_PlanoTerapiaId");

            entity.HasIndex(e => e.Ordem)
                  .HasDatabaseName("IX_Terapias_Ordem");

            entity.HasIndex(e => e.ProtocoloTerapeuticoId)
                  .HasDatabaseName("IX_Terapias_ProtocoloTerapeuticoId");

            // Relacionamento com PlanoTerapia
            entity.HasOne(t => t.PlanoTerapia)
                  .WithMany(p => p.Terapias)
                  .HasForeignKey(t => t.PlanoTerapiaId)
                  .OnDelete(DeleteBehavior.Cascade);

            // Relacionamento com ProtocoloTerapeutico
            entity.HasOne(t => t.ProtocoloTerapeutico)
                  .WithMany(p => p.Terapias)
                  .HasForeignKey(t => t.ProtocoloTerapeuticoId)
                  .OnDelete(DeleteBehavior.Restrict); // Não deletar protocolo se usado em plano
        });

        // SessaoTerapia
        modelBuilder.Entity<SessaoTerapia>(entity =>
        {
            entity.HasKey(e => e.Id);

            // Índice composto para ordenação
            entity.HasIndex(e => new { e.PlanoTerapiaId, e.InicioEm })
                  .HasDatabaseName("IX_SessoesTerapia_PlanoId_Inicio");

            entity.HasIndex(e => e.TipoRng)
                  .HasDatabaseName("IX_SessoesTerapia_TipoRng");

            // Relacionamento com PlanoTerapia
            entity.HasOne(s => s.PlanoTerapia)
                  .WithMany(p => p.SessoesTerapia)
                  .HasForeignKey(s => s.PlanoTerapiaId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // LeituraBioenergetica
        modelBuilder.Entity<LeituraBioenergetica>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.SessaoTerapiaId)
                  .HasDatabaseName("IX_LeiturasBioenergeticas_SessaoTerapiaId");

            entity.HasIndex(e => e.Timestamp)
                  .HasDatabaseName("IX_LeiturasBioenergeticas_Timestamp");

            // Relacionamento com SessaoTerapia
            entity.HasOne(l => l.SessaoTerapia)
                  .WithMany(s => s.Leituras)
                  .HasForeignKey(l => l.SessaoTerapiaId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // EventoHardware
        modelBuilder.Entity<EventoHardware>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.SessaoTerapiaId)
                  .HasDatabaseName("IX_EventosHardware_SessaoTerapiaId");

            entity.HasIndex(e => e.Timestamp)
                  .HasDatabaseName("IX_EventosHardware_Timestamp");

            entity.HasIndex(e => e.TipoEvento)
                  .HasDatabaseName("IX_EventosHardware_TipoEvento");

            entity.HasIndex(e => e.Severidade)
                  .HasDatabaseName("IX_EventosHardware_Severidade");

            // Relacionamento com SessaoTerapia
            entity.HasOne(e => e.SessaoTerapia)
                  .WithMany(s => s.EventosHardware)
                  .HasForeignKey(e => e.SessaoTerapiaId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ProtocoloTerapeutico (já existe, adicionar índices)
        modelBuilder.Entity<ProtocoloTerapeutico>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.Nome)
                  .HasDatabaseName("IX_ProtocolosTerapeuticos_Nome");

            entity.HasIndex(e => e.Categoria)
                  .HasDatabaseName("IX_ProtocolosTerapeuticos_Categoria");

            entity.HasIndex(e => e.ExternalId)
                  .IsUnique()
                  .HasDatabaseName("IX_ProtocolosTerapeuticos_ExternalId");
        });

        // ImportacaoExcelLog
        modelBuilder.Entity<ImportacaoExcelLog>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.HasIndex(e => e.ImportadoEm)
                  .HasDatabaseName("IX_ImportacoesExcelLog_ImportadoEm");

            entity.HasIndex(e => e.Sucesso)
                  .HasDatabaseName("IX_ImportacoesExcelLog_Sucesso");
        });

        // === CONFIGURAÇÃO ITEM BANCO CORE (Sistema Informacional) ===
        modelBuilder.Entity<ItemBancoCore>(entity =>
        {
            entity.HasKey(e => e.Id);

            // Índice único para ExternalId (GUID)
            entity.HasIndex(e => e.ExternalId)
                  .IsUnique()
                  .HasDatabaseName("IX_ItensBancoCore_ExternalId");

            // Índices para queries de ressonância
            entity.HasIndex(e => e.Categoria)
                  .HasDatabaseName("IX_ItensBancoCore_Categoria");

            entity.HasIndex(e => e.Nome)
                  .HasDatabaseName("IX_ItensBancoCore_Nome");

            entity.HasIndex(e => e.Subcategoria)
                  .HasDatabaseName("IX_ItensBancoCore_Subcategoria");

            entity.HasIndex(e => e.GeneroAplicavel)
                  .HasDatabaseName("IX_ItensBancoCore_GeneroAplicavel");

            entity.HasIndex(e => e.IsActive)
                  .HasDatabaseName("IX_ItensBancoCore_IsActive");

            // Índice composto para filtros comuns
            entity.HasIndex(e => new { e.Categoria, e.IsActive, e.GeneroAplicavel })
                  .HasDatabaseName("IX_ItensBancoCore_Categoria_Active_Genero");
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

        // SEED: Sessões de exemplo (Aba 4: Registo de Consultas)
        // ⚠️ COMENTADO: Seed data causa FK constraint se pacientes ID=1,2,3 não existirem
        // Se precisares de dados de teste, cria pacientes manualmente primeiro
        /*
        var sessoes = new[]
        {
        // Sessões para João Santos (ID=1)
        new Sessao
        {
            Id = 1,
            PacienteId = 1,
            DataHora = DateTime.Now.AddDays(-30),
            DuracaoMinutos = 60,
            Motivo = "Dor lombar aguda",
            Contexto = "Após esforço físico no ginásio",
            Achados = "Tensão muscular paravertebral L4-L5, trigger points bilateral",
            PressaoArterial = "120/80",
            Peso = 78.5m,
            Temperatura = 36.5m,
            Avaliacao = "Lombalgia mecânica aguda",
            Plano = "HVLA L4-L5 + Protocolo anti-inflamatório + Repouso relativo 3 dias + Reavaliação 1 semana",
            CriadoEm = DateTime.Now.AddDays(-30),
            IsDeleted = false
        },
        new Sessao
        {
            Id = 2,
            PacienteId = 1,
            DataHora = DateTime.Now.AddDays(-23),
            DuracaoMinutos = 45,
            Motivo = "Reavaliação lombalgia",
            Achados = "Melhoria 70%, tensão residual L5",
            PressaoArterial = "118/78",
            Peso = 78.0m,
            Avaliacao = "Evolução favorável",
            Plano = "Alongamentos paravertebrais 10' 2x/dia + Manter atividade física moderada",
            CriadoEm = DateTime.Now.AddDays(-23),
            IsDeleted = false
        },
        new Sessao
        {
            Id = 3,
            PacienteId = 1,
            DataHora = DateTime.Now.AddDays(-10),
            DuracaoMinutos = 60,
            Motivo = "Consulta de rotina + stress elevado",
            Contexto = "Período de trabalho intenso com deadlines apertados",
            Achados = "FC: 85 bpm, tensão cervical bilateral",
            PressaoArterial = "135/88",
            OutrasMedicoes = "FC: 85 bpm, padrão respiratório superficial",
            Avaliacao = "Stress ocupacional com somatização",
            Plano = "Protocolo anti-stress + Meditação 10' diária + Dieta anti-inflamatória + Ómega-3",
            CriadoEm = DateTime.Now.AddDays(-10),
            IsDeleted = false
        },

        // Sessões para Maria Costa (ID=2)
        new Sessao
        {
            Id = 4,
            PacienteId = 2,
            DataHora = DateTime.Now.AddDays(-15),
            DuracaoMinutos = 90,
            Motivo = "Avaliação inicial - cefaleias recorrentes",
            Contexto = "Cefaleias tensionais há 6 meses, agravamento recente",
            Achados = "Trigger points trapézio superior bilateral, C5-C6 com restrição de mobilidade",
            PressaoArterial = "125/82",
            Peso = 62.0m,
            Temperatura = 36.3m,
            OutrasMedicoes = "FC: 72 bpm",
            Avaliacao = "Cefaleia tensional de origem cervical",
            Plano = "Manipulação C5-C6 + Exercícios posturais + Hidratação 2L/dia + Redução stress + Reavaliação 2 semanas",
            CriadoEm = DateTime.Now.AddDays(-15),
            IsDeleted = false
        },
        new Sessao
        {
            Id = 5,
            PacienteId = 2,
            DataHora = DateTime.Now.AddDays(-1),
            DuracaoMinutos = 60,
            Motivo = "Reavaliação cefaleias + análise iridológica",
            Achados = "Redução 60% frequência cefaleias, mobilidade cervical normalizada",
            PressaoArterial = "120/78",
            Peso = 61.5m,
            Avaliacao = "Excelente evolução",
            Plano = "Manter exercícios + Consulta follow-up 1 mês",
            CriadoEm = DateTime.Now.AddDays(-1),
            IsDeleted = false
        },

        // Sessão para Carlos Pereira (ID=3) - Multi-abordagem
        new Sessao
        {
            Id = 6,
            PacienteId = 3,
            DataHora = DateTime.Now.AddDays(-5),
            DuracaoMinutos = 120,
            Motivo = "Consulta integrada - dor articular + fadiga crónica",
            Contexto = "Dores articulares múltiplas (joelhos, ombros) + fadiga persistente há 3 meses",
            Achados = "Edema leve joelho direito, mobilidade ombro esquerdo reduzida 20%, padrão de fadiga adrenal",
            PressaoArterial = "128/84",
            Peso = 85.0m,
            Temperatura = 36.4m,
            OutrasMedicoes = "FC: 78 bpm, qualidade sono: 5/10",
            Avaliacao = "Síndrome inflamatório multifatorial + possível sobrecarga adrenal",
            Plano = "Osteopatia articular + Mesoterapia anti-inflamatória joelhos + Protocolo naturopático (Curcuma + Ómega-3 + Magnésio) + Dieta anti-inflamatória + Eliminar açúcar refinado + Sono 8h/noite + Reavaliação 3 semanas",
            CriadoEm = DateTime.Now.AddDays(-5),
            IsDeleted = false
        }
    };

        modelBuilder.Entity<Sessao>().HasData(sessoes);
        */

        // SEED: Abordagens terapêuticas aplicadas nas sessões
        // ⚠️ COMENTADO: Dependem das Sessões seed acima
        /*
        var abordagensSessoes = new[]
        {
        // Sessão 1 (João) - Osteopatia
        new AbordagemSessao { Id = 1, SessaoId = 1, TipoAbordagem = TipoAbordagem.Osteopatia },

        // Sessão 2 (João) - Osteopatia
        new AbordagemSessao { Id = 2, SessaoId = 2, TipoAbordagem = TipoAbordagem.Osteopatia },

        // Sessão 3 (João) - Naturopatia + Medicina Bioenergética
        new AbordagemSessao { Id = 3, SessaoId = 3, TipoAbordagem = TipoAbordagem.Naturopatia, Observacoes = "Suplementação adaptogénica" },
        new AbordagemSessao { Id = 4, SessaoId = 3, TipoAbordagem = TipoAbordagem.MedicinaBioenergetica, Observacoes = "Equilíbrio energético" },

        // Sessão 4 (Maria) - Osteopatia
        new AbordagemSessao { Id = 5, SessaoId = 4, TipoAbordagem = TipoAbordagem.Osteopatia },

        // Sessão 5 (Maria) - Osteopatia + Iridologia
        new AbordagemSessao { Id = 6, SessaoId = 5, TipoAbordagem = TipoAbordagem.Osteopatia },
        new AbordagemSessao { Id = 7, SessaoId = 5, TipoAbordagem = TipoAbordagem.Iridologia, Observacoes = "Análise constitucional" },

        // Sessão 6 (Carlos) - Multi-abordagem (Osteopatia + Mesoterapia + Naturopatia)
        new AbordagemSessao { Id = 8, SessaoId = 6, TipoAbordagem = TipoAbordagem.Osteopatia, Observacoes = "Técnicas articulares joelhos e ombro" },
        new AbordagemSessao { Id = 9, SessaoId = 6, TipoAbordagem = TipoAbordagem.Mesoterapia, Observacoes = "Infiltrações anti-inflamatórias" },
        new AbordagemSessao { Id = 10, SessaoId = 6, TipoAbordagem = TipoAbordagem.Naturopatia, Observacoes = "Protocolo anti-inflamatório oral" }
    };

        modelBuilder.Entity<AbordagemSessao>().HasData(abordagensSessoes);
        */

        // SEED: Configuração Global da Clínica (Id fixo = 1)
        var configuracaoClinica = new ConfiguracaoClinica
        {
            Id = 1,
            NomeClinica = "Minha Clínica",
            Morada = null,
            Telefone = null,
            Email = null,
            NIPC = null,
            LogoPath = null,
            DataAtualizacao = DateTime.UtcNow
        };

        modelBuilder.Entity<ConfiguracaoClinica>().HasData(configuracaoClinica);
    }

    /// <summary>
    /// Seed inicial dos 156 itens do Banco Core (Inergetix-inspired)
    /// Este método deve ser chamado APÓS Database.Migrate() no App.xaml.cs
    /// </summary>
    public void EnsureItensBancoCoreSeeded()
    {
        // Verificar se já existem itens
        if (ItensBancoCore.Any())
        {
            Console.WriteLine("ℹ️ ItensBancoCore já contém dados. Seed ignorado.");
            return;
        }

        Console.WriteLine("🌱 A semear 156 itens do Banco Core...");

        var itens = BioDesk.Data.SeedData.ItemBancoCoreSeeder.GetAll();
        ItensBancoCore.AddRange(itens);
        SaveChanges();

        Console.WriteLine($"✅ {itens.Count} itens inseridos com sucesso!");
    }
}
