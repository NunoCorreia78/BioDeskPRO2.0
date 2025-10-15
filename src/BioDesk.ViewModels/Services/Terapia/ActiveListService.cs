using System.Collections.ObjectModel;
using System.Linq;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.ViewModels.Services.Terapia;

public interface IActiveListService
{
    ObservableCollection<ScanResultItem> ActiveItems { get; }
    void AddOrUpdate(ScanResultItem item);
}

public sealed class ActiveListService : IActiveListService
{
    public ObservableCollection<ScanResultItem> ActiveItems { get; } = new();

    public void AddOrUpdate(ScanResultItem item)
    {
        var existing = ActiveItems.FirstOrDefault(x => x.ItemId == item.ItemId && x.Code == item.Code);
        if (existing is null)
        {
            ActiveItems.Add(item);
        }
        else
        {
            var index = ActiveItems.IndexOf(existing);
            ActiveItems[index] = item;
        }
    }
}
