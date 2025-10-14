using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace BioDesk.Data;

/// <summary>
/// Factory para criar DbContext em design-time (migrations)
/// </summary>
public class BioDeskDbContextFactory : IDesignTimeDbContextFactory<BioDeskDbContext>
{
    public BioDeskDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<BioDeskDbContext>();

        // Caminho temporário para migrations (será sobrescrito em runtime)
        optionsBuilder.UseSqlite("Data Source=biodesk_migrations.db");

        return new BioDeskDbContext(optionsBuilder.Options);
    }
}
