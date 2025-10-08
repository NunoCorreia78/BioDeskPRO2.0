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
    private IRepository<HistoricoMedico>? _historicoMedico;
    private IRepository<IrisImagem>? _irisImagens;
    private IRepository<IrisMarca>? _irisMarcas;
    private IRepository<ConfiguracaoClinica>? _configuracaoClinica;

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

    public IRepository<HistoricoMedico> HistoricoMedico
    {
        get
        {
            _historicoMedico ??= new Repository<HistoricoMedico>(_context);
            return _historicoMedico;
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

    public async Task<int> SaveChangesAsync()
    {
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
