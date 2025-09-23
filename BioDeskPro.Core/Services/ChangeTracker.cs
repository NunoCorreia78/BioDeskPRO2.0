using BioDeskPro.Core.Interfaces;
using System.Collections.Concurrent;

namespace BioDeskPro.Core.Services;

public class ChangeTracker : IChangeTracker
{
    private readonly ConcurrentDictionary<object, string> _trackedEntities = new();
    private readonly object _lock = new();
    private bool _isDirty;
    private bool _inBatch;
    private bool _batchHasChanges;
    
    public bool IsDirty 
    { 
        get 
        {
            lock (_lock)
            {
                return _inBatch ? _batchHasChanges : _isDirty;
            }
        }
        private set
        {
            lock (_lock)
            {
                var oldValue = _inBatch ? _batchHasChanges : _isDirty;
                
                if (_inBatch)
                {
                    _batchHasChanges = value;
                }
                else
                {
                    _isDirty = value;
                }
                
                var newValue = _inBatch ? _batchHasChanges : _isDirty;
                
                if (oldValue != newValue)
                {
                    DirtyStateChanged?.Invoke(this, newValue);
                }
            }
        }
    }
    
    public event EventHandler<bool>? DirtyStateChanged;
    
    public void MarkDirty()
    {
        IsDirty = true;
    }
    
    public void MarkClean()
    {
        lock (_lock)
        {
            if (_inBatch)
            {
                _batchHasChanges = false;
            }
            else
            {
                _isDirty = false;
                _trackedEntities.Clear();
                DirtyStateChanged?.Invoke(this, false);
            }
        }
    }
    
    public void Reset()
    {
        lock (_lock)
        {
            _isDirty = false;
            _inBatch = false;
            _batchHasChanges = false;
            _trackedEntities.Clear();
            DirtyStateChanged?.Invoke(this, false);
        }
    }
    
    public void TrackEntity(object entity, string? propertyName = null)
    {
        ArgumentNullException.ThrowIfNull(entity);
        
        var entityKey = propertyName != null ? $"{entity.GetType().Name}.{propertyName}" : entity.GetType().Name;
        _trackedEntities.TryAdd(entity, entityKey);
        MarkDirty();
    }
    
    public void UntrackEntity(object entity)
    {
        ArgumentNullException.ThrowIfNull(entity);
        _trackedEntities.TryRemove(entity, out _);
        
        // Se não há mais entidades rastreadas, marca como limpo
        if (_trackedEntities.IsEmpty)
        {
            MarkClean();
        }
    }
    
    public void BeginBatch()
    {
        lock (_lock)
        {
            _inBatch = true;
            _batchHasChanges = false;
        }
    }
    
    public void EndBatch()
    {
        lock (_lock)
        {
            if (_inBatch)
            {
                _inBatch = false;
                if (_batchHasChanges)
                {
                    _isDirty = true;
                    DirtyStateChanged?.Invoke(this, true);
                }
                _batchHasChanges = false;
            }
        }
    }
    
    public void CancelBatch()
    {
        lock (_lock)
        {
            _inBatch = false;
            _batchHasChanges = false;
        }
    }
    
    public IReadOnlyList<string> GetChangedEntities()
    {
        return _trackedEntities.Values.Distinct().ToList().AsReadOnly();
    }
    
    public bool HasChanges(string entityType)
    {
        return _trackedEntities.Values.Any(v => v.StartsWith(entityType, StringComparison.OrdinalIgnoreCase));
    }
}