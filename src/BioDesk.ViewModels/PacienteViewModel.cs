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
                }
            }
        }

        public DateTime? DataNascimento
        {
            get => _paciente.DataNascimento;
            set
            {
                if (_paciente.DataNascimento != value)
                {
                    _paciente.DataNascimento = value;
                    OnPropertyChanged();
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

        public string? Profissao
        {
            get => _paciente.Profissao;
            set
            {
                if (_paciente.Profissao != value)
                {
                    _paciente.Profissao = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? NIF
        {
            get => _paciente.NIF;
            set
            {
                if (_paciente.NIF != value)
                {
                    _paciente.NIF = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? Genero
        {
            get => _paciente.Genero;
            set
            {
                if (_paciente.Genero != value)
                {
                    _paciente.Genero = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? EstadoCivil
        {
            get => _paciente.EstadoCivil;
            set
            {
                if (_paciente.EstadoCivil != value)
                {
                    _paciente.EstadoCivil = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? Morada
        {
            get => _paciente.Morada;
            set
            {
                if (_paciente.Morada != value)
                {
                    _paciente.Morada = value;
                    OnPropertyChanged();
                }
            }
        }

        #region Propriedades de Anamnese Detalhada

        public string? QueixaPrincipal
        {
            get => _paciente.QueixaPrincipal;
            set
            {
                if (_paciente.QueixaPrincipal != value)
                {
                    _paciente.QueixaPrincipal = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? DuracaoSintomas
        {
            get => _paciente.DuracaoSintomas;
            set
            {
                if (_paciente.DuracaoSintomas != value)
                {
                    _paciente.DuracaoSintomas = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? IntensidadeSintomas
        {
            get => _paciente.IntensidadeSintomas;
            set
            {
                if (_paciente.IntensidadeSintomas != value)
                {
                    _paciente.IntensidadeSintomas = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? HistoriaDoencaAtual
        {
            get => _paciente.HistoriaDoencaAtual;
            set
            {
                if (_paciente.HistoriaDoencaAtual != value)
                {
                    _paciente.HistoriaDoencaAtual = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? FatoresDesencadeantes
        {
            get => _paciente.FatoresDesencadeantes;
            set
            {
                if (_paciente.FatoresDesencadeantes != value)
                {
                    _paciente.FatoresDesencadeantes = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? TratamentosRealizados
        {
            get => _paciente.TratamentosRealizados;
            set
            {
                if (_paciente.TratamentosRealizados != value)
                {
                    _paciente.TratamentosRealizados = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? DoencasAnteriores
        {
            get => _paciente.DoencasAnteriores;
            set
            {
                if (_paciente.DoencasAnteriores != value)
                {
                    _paciente.DoencasAnteriores = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? CirurgiasRealizadas
        {
            get => _paciente.CirurgiasRealizadas;
            set
            {
                if (_paciente.CirurgiasRealizadas != value)
                {
                    _paciente.CirurgiasRealizadas = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? MedicacaoAtual
        {
            get => _paciente.MedicacaoAtual;
            set
            {
                if (_paciente.MedicacaoAtual != value)
                {
                    _paciente.MedicacaoAtual = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? AlergiasConhecidas
        {
            get => _paciente.AlergiasConhecidas;
            set
            {
                if (_paciente.AlergiasConhecidas != value)
                {
                    _paciente.AlergiasConhecidas = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? SistemaCardiovascular
        {
            get => _paciente.SistemaCardiovascular;
            set
            {
                if (_paciente.SistemaCardiovascular != value)
                {
                    _paciente.SistemaCardiovascular = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? SistemaRespiratorio
        {
            get => _paciente.SistemaRespiratorio;
            set
            {
                if (_paciente.SistemaRespiratorio != value)
                {
                    _paciente.SistemaRespiratorio = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? SistemaDigestivo
        {
            get => _paciente.SistemaDigestivo;
            set
            {
                if (_paciente.SistemaDigestivo != value)
                {
                    _paciente.SistemaDigestivo = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? SistemaNeurologico
        {
            get => _paciente.SistemaNeurologico;
            set
            {
                if (_paciente.SistemaNeurologico != value)
                {
                    _paciente.SistemaNeurologico = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? HabitosAlimentares
        {
            get => _paciente.HabitosAlimentares;
            set
            {
                if (_paciente.HabitosAlimentares != value)
                {
                    _paciente.HabitosAlimentares = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? AtividadeFisica
        {
            get => _paciente.AtividadeFisica;
            set
            {
                if (_paciente.AtividadeFisica != value)
                {
                    _paciente.AtividadeFisica = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? QualidadeSono
        {
            get => _paciente.QualidadeDesonoEnum;
            set
            {
                if (_paciente.QualidadeDesonoEnum != value)
                {
                    _paciente.QualidadeDesonoEnum = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? GestaoStress
        {
            get => _paciente.GestaoStress;
            set
            {
                if (_paciente.GestaoStress != value)
                {
                    _paciente.GestaoStress = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? ConsumoAlcool
        {
            get => _paciente.ConsumoAlcoolEnum;
            set
            {
                if (_paciente.ConsumoAlcoolEnum != value)
                {
                    _paciente.ConsumoAlcoolEnum = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? Tabagismo
        {
            get => _paciente.Tabagismo;
            set
            {
                if (_paciente.Tabagismo != value)
                {
                    _paciente.Tabagismo = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? AntecedentesFamiliares
        {
            get => _paciente.AntecedentesFamiliares;
            set
            {
                if (_paciente.AntecedentesFamiliares != value)
                {
                    _paciente.AntecedentesFamiliares = value;
                    OnPropertyChanged();
                }
            }
        }

        public string? DoencasHereditarias
        {
            get => _paciente.DoencasHereditarias;
            set
            {
                if (_paciente.DoencasHereditarias != value)
                {
                    _paciente.DoencasHereditarias = value;
                    OnPropertyChanged();
                }
            }
        }

        #endregion

        // Propriedades de idade removidas conforme solicitado
        
        public DateTime CriadoEm => _paciente.CriadoEm;
        public DateTime AtualizadoEm => _paciente.AtualizadoEm;

        /// <summary>
        /// Propriedades formatadas para exibição no DataGrid
        /// </summary>
        // IdadeFormatada removida conforme solicitado
        
        public string UltimaConsultaFormatada
        {
            get
            {
                // Por agora, usar data de última atualização
                var ultimaAtualizacao = _paciente.AtualizadoEm;
                var diasAtras = (DateTime.Now - ultimaAtualizacao).Days;
                
                return diasAtras switch
                {
                    0 => "Hoje",
                    1 => "Ontem",
                    < 7 => $"{diasAtras} dias",
                    < 30 => $"{diasAtras / 7} semanas",
                    _ => ultimaAtualizacao.ToString("dd/MM/yyyy")
                };
            }
        }
        
        public string StatusFormatado
        {
            get
            {
                // Por agora, considerar ativo se foi atualizado nos últimos 6 meses
                var diasSemAtualizacao = (DateTime.Now - _paciente.AtualizadoEm).Days;
                return diasSemAtualizacao <= 180 ? "Ativo" : "Inativo";
            }
        }

        /// <summary>
        /// Acesso ao objeto Paciente original para operações que precisam da entidade
        /// </summary>
        public Paciente PacienteOriginal => _paciente;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}