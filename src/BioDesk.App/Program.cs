using System;
using System.Windows;

namespace BioDesk.App
{
    class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            try
            {
                var app = new App();
                return app.Run();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro fatal: {ex}");
                Console.ReadKey();
                return 1;
            }
        }
    }
}