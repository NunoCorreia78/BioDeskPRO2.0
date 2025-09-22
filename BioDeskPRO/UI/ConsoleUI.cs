namespace BioDeskPRO.UI;

/// <summary>
/// Console UI helper for creating clean, organized interfaces
/// </summary>
public static class ConsoleUI
{
    private const int WindowWidth = 120;
    
    public static void Initialize()
    {
        Console.Clear();
        Console.Title = "BioDeskPRO 2.0 - Sistema de Gestão Clínica Holística";
        if (Console.WindowWidth < WindowWidth)
        {
            try
            {
                Console.SetWindowSize(WindowWidth, 40);
            }
            catch
            {
                // Ignore if unable to set window size
            }
        }
    }

    public static void DrawHeader(string title, string subtitle = "")
    {
        Console.Clear();
        DrawLine('═');
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"🏥 {title}".PadLeft((WindowWidth + title.Length) / 2));
        Console.ResetColor();
        
        if (!string.IsNullOrEmpty(subtitle))
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(subtitle.PadLeft((WindowWidth + subtitle.Length) / 2));
            Console.ResetColor();
        }
        
        DrawLine('═');
        Console.WriteLine();
    }

    public static void DrawCard(string title, Action contentAction)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        DrawLine('─', title);
        Console.ResetColor();
        Console.WriteLine();
        
        contentAction();
        
        Console.WriteLine();
        DrawLine('─');
        Console.WriteLine();
    }

    public static void DrawSection(string title, Action contentAction)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"📋 {title}");
        Console.ResetColor();
        DrawLine('·', "", 80);
        Console.WriteLine();
        
        contentAction();
        
        Console.WriteLine();
    }

    public static void DrawLine(char character, string text = "", int width = -1)
    {
        if (width == -1) width = WindowWidth;
        
        if (string.IsNullOrEmpty(text))
        {
            Console.WriteLine(new string(character, width));
        }
        else
        {
            var padding = (width - text.Length - 2) / 2;
            var line = new string(character, padding) + $" {text} " + new string(character, width - padding - text.Length - 2);
            Console.WriteLine(line);
        }
    }

    public static void ShowError(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"❌ Erro: {message}");
        Console.ResetColor();
    }

    public static void ShowSuccess(string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"✅ {message}");
        Console.ResetColor();
    }

    public static void ShowWarning(string message)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"⚠️ {message}");
        Console.ResetColor();
    }

    public static void ShowInfo(string message)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"ℹ️ {message}");
        Console.ResetColor();
    }

    public static string GetInput(string prompt, bool required = false)
    {
        while (true)
        {
            Console.Write($"{prompt}: ");
            var input = Console.ReadLine() ?? "";
            
            if (!required || !string.IsNullOrWhiteSpace(input))
                return input.Trim();
                
            ShowError("Este campo é obrigatório. Por favor, insira um valor.");
        }
    }

    public static DateTime GetDateInput(string prompt, bool required = false)
    {
        while (true)
        {
            var input = GetInput($"{prompt} (dd/MM/yyyy)", required);
            
            if (!required && string.IsNullOrWhiteSpace(input))
                return default;
                
            if (DateTime.TryParseExact(input, "dd/MM/yyyy", null, System.Globalization.DateTimeStyles.None, out var date))
            {
                if (date > DateTime.Today)
                {
                    ShowError("A data não pode ser no futuro.");
                    continue;
                }
                return date;
            }
            
            ShowError("Formato de data inválido. Use dd/MM/yyyy (ex: 15/03/1980).");
        }
    }

    public static int GetChoice(string prompt, string[] options)
    {
        while (true)
        {
            Console.WriteLine($"\n{prompt}:");
            for (int i = 0; i < options.Length; i++)
            {
                Console.WriteLine($"  {i + 1}. {options[i]}");
            }
            
            Console.Write("\nEscolha uma opção: ");
            if (int.TryParse(Console.ReadLine(), out var choice) && choice >= 1 && choice <= options.Length)
            {
                return choice - 1;
            }
            
            ShowError($"Opção inválida. Escolha um número entre 1 e {options.Length}.");
        }
    }

    public static bool GetConfirmation(string message)
    {
        while (true)
        {
            Console.Write($"{message} (s/n): ");
            var input = Console.ReadLine()?.ToLower().Trim();
            
            if (input == "s" || input == "sim" || input == "y" || input == "yes")
                return true;
            if (input == "n" || input == "não" || input == "nao" || input == "no")
                return false;
                
            ShowError("Responda com 's' para sim ou 'n' para não.");
        }
    }

    public static void PauseForUser(string message = "Pressione qualquer tecla para continuar...")
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(message);
        Console.ResetColor();
        Console.ReadKey(true);
    }

    public static void DisplayPatientList(IEnumerable<Models.Patient> patients)
    {
        if (!patients.Any())
        {
            ShowInfo("Nenhum paciente encontrado.");
            return;
        }

        Console.WriteLine($"{"ID",-5} {"Nome",-30} {"Idade",-6} {"Email",-25} {"Telefone",-15}");
        DrawLine('─', "", 85);
        
        foreach (var patient in patients)
        {
            Console.WriteLine($"{patient.Id,-5} {patient.FullName.Substring(0, Math.Min(29, patient.FullName.Length)),-30} " +
                            $"{patient.Age,-6} {patient.Email.Substring(0, Math.Min(24, patient.Email.Length)),-25} " +
                            $"{patient.Phone,-15}");
        }
    }
}