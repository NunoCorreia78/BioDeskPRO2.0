using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern SafeFileHandle CreateFile(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    IntPtr hTemplateFile);

string[] paths = {
    @"\\?\usb#vid_0e36&pid_0008#6&24c7b282&0&1#{AF43275C-FB24-4371-BAF8-2BA656FB33E6}",
    @"\\.\HS3",
    @"\\.\HS30",
    @"\\.\HS3_0",
    @"\\.\TIEPIESCOPE",
    @"\\.\HS3r",
    @"\\.\Global\HS3"
};

const uint GENERIC_READ = 0x80000000;
const uint GENERIC_WRITE = 0x40000000;
const uint FILE_SHARE_READ = 0x00000001;
const uint FILE_SHARE_WRITE = 0x00000002;
const uint OPEN_EXISTING = 3;
const uint FILE_FLAG_OVERLAPPED = 0x40000000;

Console.WriteLine("🔍 Testando device paths para TiePie HS3...\n");

foreach (var path in paths)
{
    Console.Write($"Tentando: {path}...");
    
    var handle = CreateFile(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        IntPtr.Zero,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        IntPtr.Zero);

    if (!handle.IsInvalid)
    {
        Console.WriteLine($" ✅ SUCESSO!");
        handle.Close();
        Console.WriteLine($"\n🎯 Device path correto: {path}");
        return;
    }
    else
    {
        int error = Marshal.GetLastWin32Error();
        string errorMsg = error switch
        {
            2 => "ERROR_FILE_NOT_FOUND",
            5 => "ERROR_ACCESS_DENIED",
            6 => "ERROR_INVALID_HANDLE",
            32 => "ERROR_SHARING_VIOLATION",
            _ => $"Error {error}"
        };
        Console.WriteLine($" ❌ FALHOU ({errorMsg})");
    }
}

Console.WriteLine("\n❌ Nenhum device path funcionou. Driver pode não expor symbolic link.");
