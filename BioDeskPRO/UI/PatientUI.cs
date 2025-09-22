using BioDeskPRO.Models;
using BioDeskPRO.Services;

namespace BioDeskPRO.UI;

/// <summary>
/// Patient management user interface
/// </summary>
public class PatientUI
{
    private readonly IPatientService _patientService;

    public PatientUI(IPatientService patientService)
    {
        _patientService = patientService;
    }

    public async Task ShowPatientManagementAsync()
    {
        while (true)
        {
            ConsoleUI.DrawHeader("GESTÃO DE PACIENTES", "Cadastro e Consulta de Dados Biográficos");

            var options = new[]
            {
                "Novo Paciente",
                "Listar Todos os Pacientes",
                "Buscar Paciente",
                "Editar Paciente",
                "Voltar ao Menu Principal"
            };

            var choice = ConsoleUI.GetChoice("Selecione uma opção", options);

            try
            {
                switch (choice)
                {
                    case 0:
                        await CreateNewPatientAsync();
                        break;
                    case 1:
                        await ListAllPatientsAsync();
                        break;
                    case 2:
                        await SearchPatientsAsync();
                        break;
                    case 3:
                        await EditPatientAsync();
                        break;
                    case 4:
                        return;
                }
            }
            catch (Exception ex)
            {
                ConsoleUI.ShowError($"Erro inesperado: {ex.Message}");
                ConsoleUI.PauseForUser();
            }
        }
    }

    private async Task CreateNewPatientAsync()
    {
        ConsoleUI.DrawHeader("NOVO PACIENTE", "Cadastro de Dados Biográficos");

        var patient = new Patient();

        ConsoleUI.DrawCard("Informações Pessoais", () =>
        {
            patient.FullName = ConsoleUI.GetInput("Nome Completo", required: true);
            patient.DateOfBirth = ConsoleUI.GetDateInput("Data de Nascimento", required: true);
            
            var civilStatusOptions = new[] { "Solteiro(a)", "Casado(a)", "Divorciado(a)", "Viúvo(a)", "União Estável", "Não Informado" };
            var civilStatusChoice = ConsoleUI.GetChoice("Estado Civil", civilStatusOptions);
            patient.CivilStatus = civilStatusOptions[civilStatusChoice];
        });

        ConsoleUI.DrawCard("Informações de Contato", () =>
        {
            patient.Phone = ConsoleUI.GetInput("Telefone");
            patient.Mobile = ConsoleUI.GetInput("Telemóvel");
            patient.Email = ConsoleUI.GetInput("Email");
        });

        ConsoleUI.DrawCard("Informações Adicionais", () =>
        {
            var howFoundOptions = new[] 
            { 
                "Google", "Instagram", "Facebook", "Indicação de Paciente", 
                "Indicação Médica", "Evento/Palestra", "Folheto/Panfleto", "Outro" 
            };
            var howFoundChoice = ConsoleUI.GetChoice("Como conheceu a clínica", howFoundOptions);
            patient.HowFoundClinic = howFoundOptions[howFoundChoice];

            patient.GeneralObservations = ConsoleUI.GetInput("Observações Gerais");
        });

        // Show summary
        ConsoleUI.DrawCard("Resumo dos Dados", () =>
        {
            Console.WriteLine($"Nome: {patient.FullName}");
            Console.WriteLine($"Data de Nascimento: {patient.DateOfBirth:dd/MM/yyyy} (Idade: {patient.Age} anos)");
            Console.WriteLine($"Estado Civil: {patient.CivilStatus}");
            Console.WriteLine($"Telefone: {patient.Phone}");
            Console.WriteLine($"Telemóvel: {patient.Mobile}");
            Console.WriteLine($"Email: {patient.Email}");
            Console.WriteLine($"Como conheceu: {patient.HowFoundClinic}");
            if (!string.IsNullOrEmpty(patient.GeneralObservations))
                Console.WriteLine($"Observações: {patient.GeneralObservations}");
        });

        if (ConsoleUI.GetConfirmation("Confirma o cadastro deste paciente?"))
        {
            var result = await _patientService.CreatePatientAsync(patient);
            if (result.IsSuccess)
            {
                ConsoleUI.ShowSuccess($"Paciente '{patient.FullName}' cadastrado com sucesso! ID: {result.Data!.Id}");
            }
            else
            {
                ConsoleUI.ShowError($"Erro ao cadastrar paciente: {result.ErrorMessage}");
            }
        }
        else
        {
            ConsoleUI.ShowWarning("Cadastro cancelado.");
        }

        ConsoleUI.PauseForUser();
    }

    private async Task ListAllPatientsAsync()
    {
        ConsoleUI.DrawHeader("LISTA DE PACIENTES", "Todos os Pacientes Cadastrados");

        var result = await _patientService.GetAllPatientsAsync();
        if (result.IsSuccess)
        {
            ConsoleUI.DisplayPatientList(result.Data!);
        }
        else
        {
            ConsoleUI.ShowError($"Erro ao carregar pacientes: {result.ErrorMessage}");
        }

        ConsoleUI.PauseForUser();
    }

    private async Task SearchPatientsAsync()
    {
        ConsoleUI.DrawHeader("BUSCAR PACIENTES", "Pesquisa por Nome, Email ou Telefone");

        var searchTerm = ConsoleUI.GetInput("Digite o termo de busca", required: true);

        var result = await _patientService.SearchPatientsAsync(searchTerm);
        if (result.IsSuccess)
        {
            var patients = result.Data!.ToList();
            Console.WriteLine($"\nEncontrados {patients.Count} paciente(s):");
            Console.WriteLine();
            ConsoleUI.DisplayPatientList(patients);

            if (patients.Any())
            {
                Console.WriteLine();
                var patientId = ConsoleUI.GetInput("Digite o ID do paciente para ver detalhes (ou Enter para voltar)");
                if (int.TryParse(patientId, out var id))
                {
                    await ShowPatientDetailsAsync(id);
                }
            }
        }
        else
        {
            ConsoleUI.ShowError($"Erro na busca: {result.ErrorMessage}");
        }

        ConsoleUI.PauseForUser();
    }

    private async Task EditPatientAsync()
    {
        ConsoleUI.DrawHeader("EDITAR PACIENTE", "Modificação de Dados Biográficos");

        var patientId = ConsoleUI.GetInput("Digite o ID do paciente para editar", required: true);
        if (!int.TryParse(patientId, out var id))
        {
            ConsoleUI.ShowError("ID inválido.");
            ConsoleUI.PauseForUser();
            return;
        }

        var result = await _patientService.GetPatientByIdAsync(id);
        if (!result.IsSuccess)
        {
            ConsoleUI.ShowError($"Erro ao carregar paciente: {result.ErrorMessage}");
            ConsoleUI.PauseForUser();
            return;
        }

        var patient = result.Data;
        if (patient == null)
        {
            ConsoleUI.ShowError("Paciente não encontrado.");
            ConsoleUI.PauseForUser();
            return;
        }

        // Show current data and edit
        await ShowPatientDetailsAsync(patient);

        if (ConsoleUI.GetConfirmation("Deseja editar este paciente?"))
        {
            await EditPatientDataAsync(patient);
        }
    }

    private async Task ShowPatientDetailsAsync(int patientId)
    {
        var result = await _patientService.GetPatientByIdAsync(patientId);
        if (result.IsSuccess && result.Data != null)
        {
            await ShowPatientDetailsAsync(result.Data);
        }
        else
        {
            ConsoleUI.ShowError("Paciente não encontrado.");
        }
    }

    private async Task ShowPatientDetailsAsync(Patient patient)
    {
        await Task.CompletedTask; // Make method truly async
        ConsoleUI.DrawHeader($"DETALHES DO PACIENTE - ID: {patient.Id}", patient.FullName);

        ConsoleUI.DrawCard("Informações Pessoais", () =>
        {
            Console.WriteLine($"Nome Completo: {patient.FullName}");
            Console.WriteLine($"Data de Nascimento: {patient.DateOfBirth:dd/MM/yyyy}");
            Console.WriteLine($"Idade: {patient.Age} anos");
            Console.WriteLine($"Estado Civil: {patient.CivilStatus}");
        });

        ConsoleUI.DrawCard("Informações de Contato", () =>
        {
            Console.WriteLine($"Telefone: {(!string.IsNullOrEmpty(patient.Phone) ? patient.Phone : "Não informado")}");
            Console.WriteLine($"Telemóvel: {(!string.IsNullOrEmpty(patient.Mobile) ? patient.Mobile : "Não informado")}");
            Console.WriteLine($"Email: {(!string.IsNullOrEmpty(patient.Email) ? patient.Email : "Não informado")}");
        });

        ConsoleUI.DrawCard("Informações Adicionais", () =>
        {
            Console.WriteLine($"Como conheceu a clínica: {patient.HowFoundClinic}");
            if (!string.IsNullOrEmpty(patient.GeneralObservations))
                Console.WriteLine($"Observações: {patient.GeneralObservations}");
        });

        ConsoleUI.DrawCard("Dados do Sistema", () =>
        {
            Console.WriteLine($"Cadastrado em: {patient.CreatedAt:dd/MM/yyyy HH:mm:ss}");
            Console.WriteLine($"Última atualização: {patient.UpdatedAt:dd/MM/yyyy HH:mm:ss}");
        });
    }

    private async Task EditPatientDataAsync(Patient patient)
    {
        ConsoleUI.DrawHeader($"EDITANDO PACIENTE - {patient.FullName}");

        ConsoleUI.DrawCard("Informações Pessoais", () =>
        {
            var newName = ConsoleUI.GetInput($"Nome Completo [{patient.FullName}]");
            if (!string.IsNullOrWhiteSpace(newName))
                patient.FullName = newName;

            Console.WriteLine($"Data de Nascimento atual: {patient.DateOfBirth:dd/MM/yyyy} (Idade: {patient.Age} anos)");
            var changeBirth = ConsoleUI.GetConfirmation("Deseja alterar a data de nascimento?");
            if (changeBirth)
            {
                patient.DateOfBirth = ConsoleUI.GetDateInput("Nova Data de Nascimento", required: true);
            }

            var civilStatusOptions = new[] { "Solteiro(a)", "Casado(a)", "Divorciado(a)", "Viúvo(a)", "União Estável", "Não Informado" };
            Console.WriteLine($"Estado Civil atual: {patient.CivilStatus}");
            var changeCivil = ConsoleUI.GetConfirmation("Deseja alterar o estado civil?");
            if (changeCivil)
            {
                var civilStatusChoice = ConsoleUI.GetChoice("Novo Estado Civil", civilStatusOptions);
                patient.CivilStatus = civilStatusOptions[civilStatusChoice];
            }
        });

        ConsoleUI.DrawCard("Informações de Contato", () =>
        {
            var newPhone = ConsoleUI.GetInput($"Telefone [{patient.Phone}]");
            if (!string.IsNullOrWhiteSpace(newPhone))
                patient.Phone = newPhone;

            var newMobile = ConsoleUI.GetInput($"Telemóvel [{patient.Mobile}]");
            if (!string.IsNullOrWhiteSpace(newMobile))
                patient.Mobile = newMobile;

            var newEmail = ConsoleUI.GetInput($"Email [{patient.Email}]");
            if (!string.IsNullOrWhiteSpace(newEmail))
                patient.Email = newEmail;
        });

        ConsoleUI.DrawCard("Informações Adicionais", () =>
        {
            var howFoundOptions = new[] 
            { 
                "Google", "Instagram", "Facebook", "Indicação de Paciente", 
                "Indicação Médica", "Evento/Palestra", "Folheto/Panfleto", "Outro" 
            };
            Console.WriteLine($"Como conheceu atual: {patient.HowFoundClinic}");
            var changeHowFound = ConsoleUI.GetConfirmation("Deseja alterar como conheceu a clínica?");
            if (changeHowFound)
            {
                var howFoundChoice = ConsoleUI.GetChoice("Como conheceu a clínica", howFoundOptions);
                patient.HowFoundClinic = howFoundOptions[howFoundChoice];
            }

            var newObservations = ConsoleUI.GetInput($"Observações [{patient.GeneralObservations}]");
            if (!string.IsNullOrWhiteSpace(newObservations))
                patient.GeneralObservations = newObservations;
        });

        if (ConsoleUI.GetConfirmation("Confirma as alterações?"))
        {
            var result = await _patientService.UpdatePatientAsync(patient);
            if (result.IsSuccess)
            {
                ConsoleUI.ShowSuccess("Paciente atualizado com sucesso!");
            }
            else
            {
                ConsoleUI.ShowError($"Erro ao atualizar paciente: {result.ErrorMessage}");
            }
        }
        else
        {
            ConsoleUI.ShowWarning("Alterações canceladas.");
        }

        ConsoleUI.PauseForUser();
    }
}