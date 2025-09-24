using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Pacientes;

/// <summary>
/// Interface para gestão de pacientes no BioDeskPro2
/// Caminho de ouro: SearchAsync → SelecionarPaciente → SetPacienteAtivo → NavigateTo("FichaPaciente")
/// </summary>
public interface IPacienteService
{
    /// <summary>
    /// Define o paciente ativo no sistema
    /// OBRIGATÓRIO antes de navegar para FichaPaciente
    /// </summary>
    void SetPacienteAtivo(Paciente paciente);

    /// <summary>
    /// Obtém o paciente atualmente ativo
    /// </summary>
    Paciente? GetPacienteAtivo();

    /// <summary>
    /// Pesquisa pacientes por nome, email ou número de utente
    /// </summary>
    Task<List<Paciente>> SearchAsync(string termo);

    /// <summary>
    /// Obtém todos os pacientes
    /// </summary>
    Task<List<Paciente>> GetTodosAsync();

    /// <summary>
    /// Obtém pacientes recentes (por data de atualização)
    /// </summary>
    Task<List<Paciente>> GetRecentesAsync(int quantidade = 5);

    /// <summary>
    /// Grava um paciente (novo ou atualização)
    /// </summary>
    Task<Paciente> GravarAsync(Paciente paciente);

    /// <summary>
    /// Obtém um paciente por ID
    /// </summary>
    Task<Paciente?> GetByIdAsync(int id);

    /// <summary>
    /// Evento disparado quando o paciente ativo muda
    /// </summary>
    event EventHandler<Paciente?>? PacienteAtivoChanged;
}