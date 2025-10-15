using System;

namespace BioDesk.Core.Application.Terapia;

public interface IImprovementModel
{
    double Next(double current, double z, double scorePct, TimeSpan dt);
}
