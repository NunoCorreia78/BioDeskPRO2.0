using BioDeskPro.Core.Entities;

namespace BioDeskPro.Core.Interfaces;

public interface IPacienteContext
{
    Paciente? PacienteAtivo { get; }
    Encontro? EncontroAtivo { get; }
    
    event EventHandler<Paciente?>? PacienteChanged;
    event EventHandler<Encontro?>? EncontroChanged;
    
    void SetPacienteAtivo(Paciente? paciente);
    void SetEncontroAtivo(Encontro? encontro);
    void ClearContext();
    
    bool HasPacienteAtivo { get; }
    bool HasEncontroAtivo { get; }
    bool HasContextoClinico { get; }
}