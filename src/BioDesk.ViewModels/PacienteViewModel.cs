using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels
{
    /// <summary>
    /// Wrapper para a entidade Paciente que resolve problemas de binding do WPF
    /// </summary>
    public class PacienteViewModel : INotifyPropertyChanged
    {
        private Paciente _paciente;

        public PacienteViewModel(Paciente paciente)
        {
            _paciente = paciente ?? throw new ArgumentNullException(nameof(paciente));
        }

        public Paciente Paciente => _paciente;

        public int Id => _paciente.Id;

        public string Nome
        {
            get => _paciente.Nome;
            set
            {
                if (_paciente.Nome != value)
                {
                    _paciente.Nome = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(NomeCompleto));
                }
            }
        }

        public DateTime DataNascimento
        {
            get => _paciente.DataNascimento;
            set
            {
                if (_paciente.DataNascimento != value)
                {
                    _paciente.DataNascimento = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(Idade));
                }
            }
        }

        public string Email
        {
            get => _paciente.Email;
            set
            {
                if (_paciente.Email != value)
                {
                    _paciente.Email = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? Telefone
        {
            get => _paciente.Telefone;
            set
            {
                if (_paciente.Telefone != value)
                {
                    _paciente.Telefone = value;
                    OnPropertyChanged();
                }
            }
        }

        // Propriedades read-only para binding
        public string NomeCompleto => _paciente.Nome;
        
        public int Idade => DateTime.Now.Year - _paciente.DataNascimento.Year - 
                           (DateTime.Now.DayOfYear < _paciente.DataNascimento.DayOfYear ? 1 : 0);

        public DateTime CriadoEm => _paciente.CriadoEm;
        public DateTime AtualizadoEm => _paciente.AtualizadoEm;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}