using System;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore.Storage;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação do Unit of Work
/// Gerencia ciclo de vida dos repositórios e transações
/// </summary>
public class UnitOfWork : IUnitOfWork
{
    private readonly BioDeskDbContext _context;
    private IDbContextTransaction? _transaction;
    private bool _disposed = false;

    // Lazy initialization dos repositórios
    private IPacienteRepository? _pacientes;
    private ISessaoRepository? _sessoes;
    private IRepository<Contacto>? _contactos;
    private IRepository<Consentimento>? _consentimentos;
    private IRepository<Comunicacao>? _comunicacoes;
    private IRepository<IrisImagem>? _irisImagens;
    private IRepository<IrisMarca>? _irisMarcas;
    private IRepository<ConfiguracaoClinica>? _configuracaoClinica;
    private ITemplateGlobalRepository? _templatesGlobais;
    private IDocumentoExternoPacienteRepository? _documentosExternos;

    public UnitOfWork(BioDeskDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public IPacienteRepository Pacientes
    {
        get
        {
            _pacientes ??= new PacienteRepository(_context);
            return _pacientes;
        }
    }

    public ISessaoRepository Sessoes
    {
        get
        {
            _sessoes ??= new SessaoRepository(_context);
            return _sessoes;
        }
    }

    public IRepository<Contacto> Contactos
    {
        get
        {
            _contactos ??= new Repository<Contacto>(_context);
            return _contactos;
        }
    }

    public IRepository<Consentimento> Consentimentos
    {
        get
        {
            _consentimentos ??= new Repository<Consentimento>(_context);
            return _consentimentos;
        }
    }

    public IRepository<Comunicacao> Comunicacoes
    {
        get
        {
            _comunicacoes ??= new Repository<Comunicacao>(_context);
            return _comunicacoes;
        }
    }

    public IRepository<IrisImagem> IrisImagens
    {
        get
        {
            _irisImagens ??= new Repository<IrisImagem>(_context);
            return _irisImagens;
        }
    }

    public IRepository<IrisMarca> IrisMarcas
    {
        get
        {
            _irisMarcas ??= new Repository<IrisMarca>(_context);
            return _irisMarcas;
        }
    }

    public IRepository<ConfiguracaoClinica> ConfiguracaoClinica
    {
        get
        {
            _configuracaoClinica ??= new Repository<ConfiguracaoClinica>(_context);
            return _configuracaoClinica;
        }
    }

    public ITemplateGlobalRepository TemplatesGlobais
    {
        get
        {
            _templatesGlobais ??= new TemplateGlobalRepository(_context);
            return _templatesGlobais;
        }
    }

    public IDocumentoExternoPacienteRepository DocumentosExternos
    {
        get
        {
            _documentosExternos ??= new DocumentoExternoPacienteRepository(_context);
            return _documentosExternos;
        }
    }

    /// <summary>
    /// Grava mudanças no contexto com retry logic para SQLite locked
    /// ✅ CORREÇÃO: 3 tentativas com exponential backoff para evitar "database is locked"
    /// </summary>
    public async Task<int> SaveChangesAsync()
    {
        const int maxRetries = 3;
        int delay = 50; // ms inicial

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                return await _context.SaveChangesAsync();
            }
            catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == 5 && attempt < maxRetries) // Error 5 = SQLITE_BUSY
            {
                // ✅ Database locked: aguardar antes de retry
                await Task.Delay(delay);
                delay *= 2; // Exponential backoff: 50ms → 100ms → 200ms
            }
        }

        // ✅ Última tentativa sem catch (propaga exceção se falhar)
        return await _context.SaveChangesAsync();
    }

    public async Task BeginTransactionAsync()
    {
        _transaction = await _context.Database.BeginTransactionAsync();
    }

    public async Task CommitTransactionAsync()
    {
        if (_transaction != null)
        {
            await _transaction.CommitAsync();
            await _transaction.DisposeAsync();
            _transaction = null;
        }
    }

    public async Task RollbackTransactionAsync()
    {
        if (_transaction != null)
        {
            await _transaction.RollbackAsync();
            await _transaction.DisposeAsync();
            _transaction = null;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _transaction?.Dispose();
            _context.Dispose();
        }
        _disposed = true;
    }
}
