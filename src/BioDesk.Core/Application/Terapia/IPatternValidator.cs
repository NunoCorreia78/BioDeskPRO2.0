using System;
using System.Collections.Generic;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia;

public interface IPatternValidator
{
    IReadOnlyList<ScanResultItem> Validate(
        int[] hits,
        int totalIterations,
        int itemCount,
        PatternValidationConfig cfg,
        Func<int, int, string> itemName,
        Func<int, int, string> itemCode,
        Func<int, int, string> itemCategory);
}
