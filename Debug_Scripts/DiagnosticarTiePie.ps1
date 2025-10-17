# DiagnosticarTiePie.ps1
# Script para identificar como Windows reconhece o TiePie Handyscope

Write-Host "🔍 DIAGNÓSTICO TIEPIE HANDYSCOPE" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# 1. Procurar dispositivo USB
Write-Host "1️⃣ Procurando dispositivos USB TiePie..." -ForegroundColor Yellow
$usbDevices = Get-PnpDevice | Where-Object {
    $_.FriendlyName -like "*TiePie*" -or
    $_.FriendlyName -like "*Handyscope*" -or
    $_.FriendlyName -like "*HS3*" -or
    $_.FriendlyName -like "*HS4*" -or
    $_.FriendlyName -like "*HS5*" -or
    $_.FriendlyName -like "*HS6*"
}

if ($usbDevices) {
    foreach ($device in $usbDevices) {
        Write-Host "   ✅ Encontrado: $($device.FriendlyName)" -ForegroundColor Green
        Write-Host "      - InstanceId: $($device.InstanceId)" -ForegroundColor Gray
        Write-Host "      - Class: $($device.Class)" -ForegroundColor Gray
        Write-Host "      - Status: $($device.Status)`n" -ForegroundColor Gray
    }
} else {
    Write-Host "   ❌ Nenhum dispositivo TiePie encontrado via USB`n" -ForegroundColor Red
}

# 2. Verificar portas COM (Serial)
Write-Host "2️⃣ Verificando portas COM..." -ForegroundColor Yellow
$comPorts = Get-WmiObject Win32_SerialPort | Where-Object {
    $_.Description -like "*TiePie*" -or $_.Name -like "*TiePie*"
}

if ($comPorts) {
    foreach ($port in $comPorts) {
        Write-Host "   ✅ Porta COM: $($port.DeviceID)" -ForegroundColor Green
        Write-Host "      - Nome: $($port.Name)" -ForegroundColor Gray
        Write-Host "      - Descrição: $($port.Description)`n" -ForegroundColor Gray
    }
} else {
    Write-Host "   ℹ️ Nenhuma porta COM TiePie`n" -ForegroundColor Gray
}

# 3. Dispositivos HID
Write-Host "3️⃣ Verificando dispositivos HID..." -ForegroundColor Yellow
$hidDevices = Get-PnpDevice -Class "HIDClass" | Where-Object {
    $_.Status -eq "OK"
}

$tiepieHid = $hidDevices | Where-Object {
    $id = $_.InstanceId
    # VID da TiePie é normalmente 1234 ou similar
    $id -match "VID_[0-9A-F]{4}" -and $id -match "PID_[0-9A-F]{4}"
}

if ($tiepieHid) {
    Write-Host "   ℹ️ Dispositivos HID encontrados: $($tiepieHid.Count)" -ForegroundColor Cyan
    foreach ($hid in $tiepieHid | Select-Object -First 5) {
        Write-Host "      - $($hid.FriendlyName)" -ForegroundColor Gray

        # Extrair VID/PID
        if ($hid.InstanceId -match "VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})") {
            $vid = $matches[1]
            $pid = $matches[2]
            Write-Host "        VID: $vid, PID: $pid" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
} else {
    Write-Host "   ℹ️ Nenhum HID suspeito`n" -ForegroundColor Gray
}

# 4. Driver instalado
Write-Host "4️⃣ Verificando driver..." -ForegroundColor Yellow
$drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object {
    $_.DeviceName -like "*TiePie*" -or
    $_.DriverProviderName -like "*TiePie*" -or
    $_.InfName -like "*tiepie*"
}

if ($drivers) {
    foreach ($driver in $drivers) {
        Write-Host "   ✅ Driver: $($driver.DeviceName)" -ForegroundColor Green
        Write-Host "      - Fornecedor: $($driver.DriverProviderName)" -ForegroundColor Gray
        Write-Host "      - Versão: $($driver.DriverVersion)" -ForegroundColor Gray
        Write-Host "      - Data: $($driver.DriverDate)" -ForegroundColor Gray
        Write-Host "      - INF: $($driver.InfName)`n" -ForegroundColor Gray
    }
} else {
    Write-Host "   ℹ️ Sem driver TiePie específico (provavelmente usa driver genérico Windows)`n" -ForegroundColor Yellow
}

# 5. Verificar se Inergetix CoRe está a correr
Write-Host "5️⃣ Verificando processos Inergetix..." -ForegroundColor Yellow
$coreProcess = Get-Process | Where-Object {
    ($_.ProcessName -like "*Inergetix*" -or
     $_.MainWindowTitle -like "*Inergetix*CoRe*" -or
     $_.MainWindowTitle -like "*CoRe System*") -and
    $_.ProcessName -ne "Code" # Excluir VS Code
}

if ($coreProcess) {
    Write-Host "   ✅ Inergetix CoRe está a correr!" -ForegroundColor Green
    foreach ($proc in $coreProcess) {
        Write-Host "      - Processo: $($proc.ProcessName)" -ForegroundColor Gray
        Write-Host "      - PID: $($proc.Id)" -ForegroundColor Gray
        Write-Host "      - Janela: $($proc.MainWindowTitle)`n" -ForegroundColor Gray
    }
} else {
    Write-Host "   ℹ️ Inergetix CoRe não está a correr`n" -ForegroundColor Gray
}

# 6. Resumo e Recomendações
Write-Host "`n📋 RESUMO E PRÓXIMOS PASSOS:" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

if ($usbDevices) {
    Write-Host "✅ TiePie detetado via USB - Class: $($usbDevices[0].Class)" -ForegroundColor Green

    if ($usbDevices[0].Class -eq "HIDClass") {
        Write-Host "   → Usar biblioteca HidSharp (NuGet)" -ForegroundColor Yellow
        Write-Host "   → Comunicação via HID packets" -ForegroundColor Yellow
    }
    elseif ($usbDevices[0].Class -eq "Ports") {
        Write-Host "   → Usar SerialPort (System.IO.Ports)" -ForegroundColor Yellow
        Write-Host "   → Comunicação via COM port" -ForegroundColor Yellow
    }
    elseif ($usbDevices[0].Class -eq "USB") {
        Write-Host "   → Usar LibUsbDotNet (NuGet)" -ForegroundColor Yellow
        Write-Host "   → Comunicação via WinUSB" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ TiePie não detetado - conectar dispositivo USB" -ForegroundColor Red
}

Write-Host "`n🔧 Para implementar no BioDeskPro2:" -ForegroundColor Cyan
Write-Host "   1. Executar este script COM O TIEPIE CONECTADO" -ForegroundColor White
Write-Host "   2. Anotar VID/PID do dispositivo" -ForegroundColor White
Write-Host "   3. Escolher biblioteca adequada (HID/Serial/USB)" -ForegroundColor White
Write-Host "   4. Implementar GenericDriverTiePieService.cs`n" -ForegroundColor White

Write-Host "Pressiona ENTER para fechar..." -ForegroundColor Gray
Read-Host
