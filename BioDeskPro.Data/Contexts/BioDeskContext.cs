using BioDeskPro.Core.Entities;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
using System.Text;

namespace BioDeskPro.Data.Contexts;

public class BioDeskContext : DbContext
{
    public BioDeskContext(DbContextOptions<BioDeskContext> options) : base(options)
    {
    }
    
    // DbSets para todas as entidades
    public DbSet<Paciente> Pacientes { get; set; }
    public DbSet<Encontro> Encontros { get; set; }
    public DbSet<Consulta> Consultas { get; set; }
    public DbSet<IrisImage> IrisImages { get; set; }
    public DbSet<IrisFinding> IrisFindings { get; set; }
    public DbSet<IrisReport> IrisReports { get; set; }
    public DbSet<QuantumProtocol> QuantumProtocols { get; set; }
    public DbSet<QuantumSession> QuantumSessions { get; set; }
    public DbSet<ConsentimentoTipo> ConsentimentoTipos { get; set; }
    public DbSet<ConsentimentoPaciente> ConsentimentoPacientes { get; set; }
    public DbSet<DeclaracaoSaude> DeclaracoesSaude { get; set; }
    public DbSet<Documento> Documentos { get; set; }
    public DbSet<OutboxEmail> OutboxEmails { get; set; }
    public DbSet<KnowledgeEntry> KnowledgeEntries { get; set; }
    public DbSet<KnowledgeLink> KnowledgeLinks { get; set; }
    
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var bioDeskPath = Path.Combine(appDataPath, "BioDesk", "data");
            Directory.CreateDirectory(bioDeskPath);
            
            var dbPath = Path.Combine(bioDeskPath, "biodesk.db");
            
            optionsBuilder.UseSqlite($"Data Source={dbPath}");
        }
    }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Configurar índices para busca e performance
        ConfigureIndexes(modelBuilder);
        
        // Configurar relacionamentos
        ConfigureRelationships(modelBuilder);
        
        // Configurar campos únicos para anti-duplicação
        ConfigureUniqueConstraints(modelBuilder);
        
        // Configurar normalização de strings
        ConfigureStringNormalization(modelBuilder);
        
        // Configurar valores padrão
        ConfigureDefaults(modelBuilder);
    }
    
    private static void ConfigureIndexes(ModelBuilder modelBuilder)
    {
        // Paciente - índices para busca
        modelBuilder.Entity<Paciente>()
            .HasIndex(p => p.NomeNormalizado)
            .HasDatabaseName("IX_Paciente_NomeNormalizado");
        
        modelBuilder.Entity<Paciente>()
            .HasIndex(p => p.NumeroUtente)
            .HasDatabaseName("IX_Paciente_NumeroUtente");
        
        modelBuilder.Entity<Paciente>()
            .HasIndex(p => p.DocumentoIdentidade)
            .HasDatabaseName("IX_Paciente_DocumentoIdentidade");
        
        // Encontro - índices para performance
        modelBuilder.Entity<Encontro>()
            .HasIndex(e => e.DataEncontro)
            .HasDatabaseName("IX_Encontro_DataEncontro");
        
        modelBuilder.Entity<Encontro>()
            .HasIndex(e => new { e.PacienteId, e.DataEncontro })
            .HasDatabaseName("IX_Encontro_Paciente_Data");
        
        // QuantumProtocol - índice para busca
        modelBuilder.Entity<QuantumProtocol>()
            .HasIndex(qp => qp.NomeNormalizado)
            .HasDatabaseName("IX_QuantumProtocol_NomeNormalizado");
        
        // ConsentimentoTipo - índice para busca
        modelBuilder.Entity<ConsentimentoTipo>()
            .HasIndex(ct => ct.NomeNormalizado)
            .HasDatabaseName("IX_ConsentimentoTipo_NomeNormalizado");
        
        // KnowledgeEntry - índices para busca
        modelBuilder.Entity<KnowledgeEntry>()
            .HasIndex(ke => ke.TituloNormalizado)
            .HasDatabaseName("IX_KnowledgeEntry_TituloNormalizado");
        
        modelBuilder.Entity<KnowledgeEntry>()
            .HasIndex(ke => ke.Categoria)
            .HasDatabaseName("IX_KnowledgeEntry_Categoria");
        
        // OutboxEmail - índice para performance
        modelBuilder.Entity<OutboxEmail>()
            .HasIndex(oe => new { oe.Status, oe.DataCriacao })
            .HasDatabaseName("IX_OutboxEmail_Status_DataCriacao");
    }
    
    private static void ConfigureRelationships(ModelBuilder modelBuilder)
    {
        // Relacionamentos com CASCADE apropriado
        
        // Paciente -> Encontros
        modelBuilder.Entity<Encontro>()
            .HasOne(e => e.Paciente)
            .WithMany(p => p.Encontros)
            .HasForeignKey(e => e.PacienteId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // Encontro -> Consultas
        modelBuilder.Entity<Consulta>()
            .HasOne(c => c.Encontro)
            .WithMany(e => e.Consultas)
            .HasForeignKey(c => c.EncontroId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // Encontro -> IrisImages
        modelBuilder.Entity<IrisImage>()
            .HasOne(ii => ii.Encontro)
            .WithMany(e => e.IrisImages)
            .HasForeignKey(ii => ii.EncontroId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // IrisImage -> IrisFindings
        modelBuilder.Entity<IrisFinding>()
            .HasOne(iif => iif.IrisImage)
            .WithMany(ii => ii.Findings)
            .HasForeignKey(iif => iif.IrisImageId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // IrisImage -> IrisReports
        modelBuilder.Entity<IrisReport>()
            .HasOne(ir => ir.IrisImage)
            .WithMany(ii => ii.Reports)
            .HasForeignKey(ir => ir.IrisImageId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // QuantumProtocol -> QuantumSessions
        modelBuilder.Entity<QuantumSession>()
            .HasOne(qs => qs.QuantumProtocol)
            .WithMany(qp => qp.Sessions)
            .HasForeignKey(qs => qs.QuantumProtocolId)
            .OnDelete(DeleteBehavior.Restrict); // Não deletar protocolo se há sessões
        
        // Encontro -> QuantumSessions
        modelBuilder.Entity<QuantumSession>()
            .HasOne(qs => qs.Encontro)
            .WithMany(e => e.QuantumSessions)
            .HasForeignKey(qs => qs.EncontroId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // ConsentimentoTipo -> ConsentimentoPaciente
        modelBuilder.Entity<ConsentimentoPaciente>()
            .HasOne(cp => cp.ConsentimentoTipo)
            .WithMany(ct => ct.ConsentimentosPaciente)
            .HasForeignKey(cp => cp.ConsentimentoTipoId)
            .OnDelete(DeleteBehavior.Restrict); // Não deletar tipo se há consentimentos
        
        // Paciente -> ConsentimentoPaciente
        modelBuilder.Entity<ConsentimentoPaciente>()
            .HasOne(cp => cp.Paciente)
            .WithMany(p => p.Consentimentos)
            .HasForeignKey(cp => cp.PacienteId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // Paciente -> DeclaracaoSaude
        modelBuilder.Entity<DeclaracaoSaude>()
            .HasOne(ds => ds.Paciente)
            .WithMany(p => p.DeclaracoesSaude)
            .HasForeignKey(ds => ds.PacienteId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // Paciente -> Documentos
        modelBuilder.Entity<Documento>()
            .HasOne(d => d.Paciente)
            .WithMany(p => p.Documentos)
            .HasForeignKey(d => d.PacienteId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // KnowledgeEntry -> KnowledgeLinks
        modelBuilder.Entity<KnowledgeLink>()
            .HasOne(kl => kl.KnowledgeEntry)
            .WithMany(ke => ke.Links)
            .HasForeignKey(kl => kl.KnowledgeEntryId)
            .OnDelete(DeleteBehavior.Cascade);
    }
    
    private static void ConfigureUniqueConstraints(ModelBuilder modelBuilder)
    {
        // Paciente - evitar duplicados por documento
        modelBuilder.Entity<Paciente>()
            .HasIndex(p => p.DocumentoIdentidade)
            .IsUnique()
            .HasFilter("DocumentoIdentidade IS NOT NULL AND DocumentoIdentidade != ''")
            .HasDatabaseName("UQ_Paciente_DocumentoIdentidade");
        
        // Paciente - evitar duplicados por número de utente
        modelBuilder.Entity<Paciente>()
            .HasIndex(p => p.NumeroUtente)
            .IsUnique()
            .HasFilter("NumeroUtente IS NOT NULL AND NumeroUtente != ''")
            .HasDatabaseName("UQ_Paciente_NumeroUtente");
        
        // ConsentimentoPaciente - um consentimento de cada tipo por paciente
        modelBuilder.Entity<ConsentimentoPaciente>()
            .HasIndex(cp => new { cp.PacienteId, cp.ConsentimentoTipoId })
            .IsUnique()
            .HasDatabaseName("UQ_ConsentimentoPaciente_Paciente_Tipo");
    }
    
    private static void ConfigureStringNormalization(ModelBuilder modelBuilder)
    {
        // Configurar normalização automática para campos específicos
        // Isso será implementado via interceptors ou triggers
    }
    
    private static void ConfigureDefaults(ModelBuilder modelBuilder)
    {
        // Configurar valores padrão para campos de auditoria
        modelBuilder.Entity<BaseEntity>()
            .Property(e => e.CreatedAt)
            .HasDefaultValueSql("datetime('now')");
    }
    
    public override int SaveChanges()
    {
        ProcessChanges();
        return base.SaveChanges();
    }
    
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        ProcessChanges();
        return await base.SaveChangesAsync(cancellationToken);
    }
    
    private void ProcessChanges()
    {
        var entries = ChangeTracker.Entries<BaseEntity>();
        
        foreach (var entry in entries)
        {
            switch (entry.State)
            {
                case EntityState.Added:
                    entry.Entity.CreatedAt = DateTime.UtcNow;
                    break;
                
                case EntityState.Modified:
                    entry.Entity.UpdatedAt = DateTime.UtcNow;
                    break;
            }
            
            // Normalizar strings para campos específicos
            NormalizeStrings(entry.Entity);
        }
    }
    
    private static void NormalizeStrings(BaseEntity entity)
    {
        // Normalização de strings conforme especificado no contrato
        switch (entity)
        {
            case Paciente paciente:
                paciente.NomeNormalizado = NormalizeString(paciente.Nome);
                break;
            
            case QuantumProtocol protocol:
                protocol.NomeNormalizado = NormalizeString(protocol.Nome);
                break;
            
            case ConsentimentoTipo consentimento:
                consentimento.NomeNormalizado = NormalizeString(consentimento.Nome);
                break;
            
            case KnowledgeEntry knowledge:
                knowledge.TituloNormalizado = NormalizeString(knowledge.Titulo);
                break;
        }
    }
    
    private static string? NormalizeString(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return null;
        
        // Trim, minúsculas, remover acentos
        var normalized = input.Trim().ToLowerInvariant();
        
        // Remover acentos
        var normalizedString = normalized.Normalize(NormalizationForm.FormD);
        var stringBuilder = new StringBuilder();
        
        foreach (var c in normalizedString)
        {
            var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(c);
            if (unicodeCategory != UnicodeCategory.NonSpacingMark)
            {
                stringBuilder.Append(c);
            }
        }
        
        return stringBuilder.ToString().Normalize(NormalizationForm.FormC);
    }
}