namespace BioDeskPro.Core.Interfaces;

public interface IChangeTracker
{
    bool IsDirty { get; }
    
    event EventHandler<bool>? DirtyStateChanged;
    
    void MarkDirty();
    void MarkClean();
    void Reset();
    
    // Para rastreamento específico de entidades
    void TrackEntity(object entity, string? propertyName = null);
    void UntrackEntity(object entity);
    
    // Para operações em lote
    void BeginBatch();
    void EndBatch();
    void CancelBatch();
    
    // Informações detalhadas sobre as mudanças
    IReadOnlyList<string> GetChangedEntities();
    bool HasChanges(string entityType);
}