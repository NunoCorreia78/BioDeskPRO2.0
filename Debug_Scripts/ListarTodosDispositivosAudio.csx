#r "nuget: NAudio, 2.2.1"
#r "nuget: NAudio.Wasapi, 2.2.1"

using NAudio.CoreAudioApi;
using System;

Console.WriteLine("=== DISPOSITIVOS DE ÁUDIO WASAPI ===\n");

var enumerator = new MMDeviceEnumerator();

// Render (Output) devices
Console.WriteLine("📢 OUTPUT (Render) - ACTIVE:");
var activeRender = enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.Active);
foreach (var device in activeRender)
{
    Console.WriteLine($"  ✅ {device.FriendlyName}");
    Console.WriteLine($"     ID: {device.ID}");
}

Console.WriteLine("\n📢 OUTPUT (Render) - DISABLED:");
var disabledRender = enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.Disabled);
foreach (var device in disabledRender)
{
    Console.WriteLine($"  ⛔ {device.FriendlyName}");
    Console.WriteLine($"     ID: {device.ID}");
}

Console.WriteLine("\n📢 OUTPUT (Render) - UNPLUGGED:");
var unplugged = enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.Unplugged);
foreach (var device in unplugged)
{
    Console.WriteLine($"  🔌 {device.FriendlyName}");
    Console.WriteLine($"     ID: {device.ID}");
}

Console.WriteLine("\n📢 OUTPUT (Render) - ALL:");
var allDevices = enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.All);
foreach (var device in allDevices)
{
    Console.WriteLine($"  🎵 {device.FriendlyName} ({device.State})");
    Console.WriteLine($"     ID: {device.ID}");
}

Console.WriteLine($"\n✅ Total: {allDevices.Count} dispositivos");
