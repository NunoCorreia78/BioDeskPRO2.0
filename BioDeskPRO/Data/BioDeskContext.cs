using Microsoft.EntityFrameworkCore;
using BioDeskPRO.Models;

namespace BioDeskPRO.Data;

/// <summary>
/// Database context for BioDeskPRO application
/// </summary>
public class BioDeskContext : DbContext
{
    public BioDeskContext(DbContextOptions<BioDeskContext> options) : base(options)
    {
    }

    public DbSet<Patient> Patients { get; set; }
    public DbSet<Consultation> Consultations { get; set; }
    public DbSet<ConsentType> ConsentTypes { get; set; }
    public DbSet<ConsentSignature> ConsentSignatures { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure Patient entity
        modelBuilder.Entity<Patient>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.FullName).IsRequired().HasMaxLength(200);
            entity.Property(e => e.DateOfBirth).IsRequired();
            entity.Property(e => e.CivilStatus).HasMaxLength(50);
            entity.Property(e => e.Phone).HasMaxLength(20);
            entity.Property(e => e.Mobile).HasMaxLength(20);
            entity.Property(e => e.Email).HasMaxLength(200);
            entity.Property(e => e.HowFoundClinic).HasMaxLength(100);
            entity.Property(e => e.CreatedAt).IsRequired();
            entity.Property(e => e.UpdatedAt).IsRequired();

            // Index for search performance
            entity.HasIndex(e => e.FullName);
            entity.HasIndex(e => e.Email);
        });

        // Configure Consultation entity
        modelBuilder.Entity<Consultation>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.ConsultationDate).IsRequired();
            entity.Property(e => e.CreatedAt).IsRequired();

            // Foreign key relationship
            entity.HasOne(e => e.Patient)
                  .WithMany(p => p.Consultations)
                  .HasForeignKey(e => e.PatientId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure ConsentType entity
        modelBuilder.Entity<ConsentType>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.Description).IsRequired();
            entity.Property(e => e.IsRequired).IsRequired();
            entity.Property(e => e.IsActive).IsRequired();
        });

        // Configure ConsentSignature entity
        modelBuilder.Entity<ConsentSignature>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.SignedAt).IsRequired();
            entity.Property(e => e.IsActive).IsRequired();

            // Foreign key relationships
            entity.HasOne(e => e.Patient)
                  .WithMany(p => p.ConsentSignatures)
                  .HasForeignKey(e => e.PatientId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.ConsentType)
                  .WithMany(ct => ct.ConsentSignatures)
                  .HasForeignKey(e => e.ConsentTypeId)
                  .OnDelete(DeleteBehavior.Restrict);

            // Unique constraint to prevent duplicate signatures
            entity.HasIndex(e => new { e.PatientId, e.ConsentTypeId })
                  .IsUnique();
        });

        // Seed data for ConsentTypes
        modelBuilder.Entity<ConsentType>().HasData(
            new ConsentType
            {
                Id = 1,
                Name = "LGPD/GDPR Data Processing",
                Description = "Consent for processing personal data according to LGPD and GDPR regulations",
                IsRequired = true,
                IsActive = true
            },
            new ConsentType
            {
                Id = 2,
                Name = "Medical Treatment",
                Description = "Consent for naturopathic and holistic medical treatment",
                IsRequired = true,
                IsActive = true
            },
            new ConsentType
            {
                Id = 3,
                Name = "Marketing Communications",
                Description = "Consent to receive marketing communications and health tips",
                IsRequired = false,
                IsActive = true
            }
        );
    }

    /// <summary>
    /// Override SaveChanges to automatically update timestamps
    /// </summary>
    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }

    /// <summary>
    /// Override SaveChangesAsync to automatically update timestamps
    /// </summary>
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return await base.SaveChangesAsync(cancellationToken);
    }

    private void UpdateTimestamps()
    {
        var entries = ChangeTracker
            .Entries()
            .Where(e => e.Entity is Patient && (e.State == EntityState.Added || e.State == EntityState.Modified));

        foreach (var entityEntry in entries)
        {
            if (entityEntry.Entity is Patient patient)
            {
                if (entityEntry.State == EntityState.Added)
                {
                    patient.CreatedAt = DateTime.UtcNow;
                }
                patient.UpdatedAt = DateTime.UtcNow;
            }
        }
    }
}