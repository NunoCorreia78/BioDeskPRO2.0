param(
    [Parameter(Mandatory=$true)]
    [string]$Command,

    [Parameter(Mandatory=$false)]
    [string]$OutFile = ".\run-output.json"
)

# Runs a command, captures stdout/stderr, exit code, timestamps and writes JSON to OutFile
# Usage: .\.scripts\run_and_capture.ps1 -Command 'dotnet --info' -OutFile .\run-output.json

$start = Get-Date
# Start process and capture output
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "powershell"
$psi.Arguments = "-NoProfile -Command \"& { $Command }\""
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi
$proc.Start() | Out-Null

$stdOut = $proc.StandardOutput.ReadToEnd()
$stdErr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
$exitCode = $proc.ExitCode
$end = Get-Date

$result = [PSCustomObject]@{
    TimestampStart = $start.ToString("o")
    TimestampEnd = $end.ToString("o")
    Command = $Command
    ExitCode = $exitCode
    StdOut = $stdOut
    StdErr = $stdErr
}

$result | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "WROTE: $OutFile"
