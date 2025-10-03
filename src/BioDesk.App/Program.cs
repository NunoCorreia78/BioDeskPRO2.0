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
                System.Diagnostics.Debug.WriteLine($"💥 ERRO FATAL: {ex}");
                return 1;
            }
        }
    }
}