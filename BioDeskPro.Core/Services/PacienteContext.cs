using BioDeskPro.Core.Entities;
using BioDeskPro.Core.Interfaces;

namespace BioDeskPro.Core.Services;

public class PacienteContext : IPacienteContext
{
    private Paciente? _pacienteAtivo;
    private Encontro? _encontroAtivo;
    
    public Paciente? PacienteAtivo 
    { 
        get => _pacienteAtivo;
        private set
        {
            if (_pacienteAtivo != value)
            {
                _pacienteAtivo = value;
                PacienteChanged?.Invoke(this, value);
            }
        }
    }
    
    public Encontro? EncontroAtivo 
    { 
        get => _encontroAtivo;
        private set
        {
            if (_encontroAtivo != value)
            {
                _encontroAtivo = value;
                EncontroChanged?.Invoke(this, value);
            }
        }
    }
    
    public bool HasPacienteAtivo => PacienteAtivo != null;
    public bool HasEncontroAtivo => EncontroAtivo != null;
    public bool HasContextoClinico => HasPacienteAtivo && HasEncontroAtivo;
    
    public event EventHandler<Paciente?>? PacienteChanged;
    public event EventHandler<Encontro?>? EncontroChanged;
    
    public void SetPacienteAtivo(Paciente? paciente)
    {
        PacienteAtivo = paciente;
        
        // Se trocar de paciente, limpar encontro ativo
        if (paciente == null || EncontroAtivo?.PacienteId != paciente.Id)
        {
            EncontroAtivo = null;
        }
    }
    
    public void SetEncontroAtivo(Encontro? encontro)
    {
        // Validar se o encontro pertence ao paciente ativo
        if (encontro != null && PacienteAtivo != null && encontro.PacienteId != PacienteAtivo.Id)
        {
            throw new InvalidOperationException("Encontro não pertence ao paciente ativo");
        }
        
        EncontroAtivo = encontro;
    }
    
    public void ClearContext()
    {
        EncontroAtivo = null;
        PacienteAtivo = null;
    }
}