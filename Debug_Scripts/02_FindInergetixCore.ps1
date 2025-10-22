# Script 2: Localizar instalacao do Inergetix CoRe
# Procura executavel e hs3.dll do sistema CoRe

$ErrorActionPreference = "Continue"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Localizacao do Inergetix CoRe" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Locais comuns de instalacao
$possiveisPastas = @(
    "C:\Program Files\Inergetix",
    "C:\Program Files (x86)\Inergetix",
    "C:\CoRe",
    "C:\Inergetix",
    "C:\Program Files\CoRe",
    "C:\Program Files (x86)\CoRe"
)

Write-Host "[INFO] Procurando instalacao do Inergetix CoRe..." -ForegroundColor Yellow
Write-Host ""

$encontrado = $false
$coreExePath = $null
$hs3DllPath = $null
$coreFolder = $null

foreach ($pasta in $possiveisPastas) {
    if (Test-Path $pasta) {
        Write-Host "[PESQUISA] Verificando: $pasta" -ForegroundColor Gray

        # Procurar executavel (possiveis nomes)
        $exeFiles = Get-ChildItem -Path $pasta -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "core|inergetix" -and $_.Name -notmatch "uninstall|setup" }

        # Procurar hs3.dll
        $dllFiles = Get-ChildItem -Path $pasta -Recurse -Filter "hs3.dll" -ErrorAction SilentlyContinue

        if ($exeFiles -or $dllFiles) {
            $encontrado = $true
            $coreFolder = $pasta

            Write-Host ""
            Write-Host "[ENCONTRADO] Instalacao detectada em: $pasta" -ForegroundColor Green
            Write-Host ""

            if ($exeFiles) {
                Write-Host "Executaveis encontrados:" -ForegroundColor Cyan
                foreach ($exe in $exeFiles) {
                    Write-Host "  - $($exe.Name)" -ForegroundColor White
                    Write-Host "    Path: $($exe.FullName)" -ForegroundColor Gray
                    if (-not $coreExePath) {
                        $coreExePath = $exe.FullName
                    }
                }
                Write-Host ""
            }

            if ($dllFiles) {
                Write-Host "DLLs hs3.dll encontradas:" -ForegroundColor Cyan
                foreach ($dll in $dllFiles) {
                    Write-Host "  - $($dll.FullName)" -ForegroundColor White
                    $tamanho = "{0:N0}" -f $dll.Length
                    $data = $dll.LastWriteTime.ToString("dd/MM/yyyy HH:mm")
                    Write-Host "    Tamanho: $tamanho bytes | Data: $data" -ForegroundColor Gray
                    if (-not $hs3DllPath) {
                        $hs3DllPath = $dll.FullName
                    }
                }
                Write-Host ""
            }

            break
        }
    }
}

# Se nao encontrou, procurar em todo C:\ (mais lento)
if (-not $encontrado) {
    Write-Host "[AVISO] Nao encontrado em locais comuns." -ForegroundColor Yellow
    Write-Host "[INFO] Iniciando pesquisa profunda em C:\ (pode demorar)..." -ForegroundColor Yellow
    Write-Host ""

    try {
        $dllsGlobal = Get-ChildItem -Path "C:\" -Recurse -Filter "hs3.dll" -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -notmatch "BioDeskPro2|Recycle|temp|cache" }

        if ($dllsGlobal) {
            Write-Host "[ENCONTRADO] hs3.dll em localizacao alternativa:" -ForegroundColor Green
            foreach ($dll in $dllsGlobal) {
                Write-Host "  - $($dll.FullName)" -ForegroundColor White
                $hs3DllPath = $dll.FullName
                $coreFolder = $dll.DirectoryName
            }
            $encontrado = $true
        }
    }
    catch {
        Write-Host "[ERRO] Pesquisa profunda falhou: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " RESULTADO DA PESQUISA" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

if ($encontrado) {
    Write-Host "[SUCESSO] Inergetix CoRe localizado!" -ForegroundColor Green
    Write-Host ""

    # Salvar configuracao
    $configPath = "$PSScriptRoot\InergetixCoreConfig.json"
    $config = @{
        CoreFolder = $coreFolder
        CoreExecutable = $coreExePath
        HS3DllPath = $hs3DllPath
        DetectedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }

    $config | ConvertTo-Json | Set-Content $configPath

    Write-Host "Configuracao salva em:" -ForegroundColor Cyan
    Write-Host "  $configPath" -ForegroundColor White
    Write-Host ""
    Write-Host "Detalhes:" -ForegroundColor Cyan
    Write-Host "  Pasta instalacao: $coreFolder" -ForegroundColor White
    if ($coreExePath) {
        Write-Host "  Executavel: $coreExePath" -ForegroundColor White
    }
    if ($hs3DllPath) {
        Write-Host "  hs3.dll: $hs3DllPath" -ForegroundColor White
    }
    Write-Host ""

    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " PROXIMO PASSO" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Analisar hs3.dll com Dependency Walker (opcional):" -ForegroundColor Yellow
    Write-Host "  .\03_AnalyzeHS3_DependencyWalker.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "OU ir direto para monitorizacao:" -ForegroundColor Yellow
    Write-Host "  .\04_ConfigureProcessMonitor.ps1" -ForegroundColor White
    Write-Host ""
}
else {
    Write-Host "[ERRO] Inergetix CoRe NAO encontrado!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Opcoes:" -ForegroundColor Yellow
    Write-Host "  1. Verificar se o Inergetix CoRe esta instalado" -ForegroundColor White
    Write-Host "  2. Informar manualmente o caminho da instalacao" -ForegroundColor White
    Write-Host ""
    Write-Host "Se souber o caminho, edite InergetixCoreConfig.json:" -ForegroundColor Cyan
    Write-Host '  {' -ForegroundColor Gray
    Write-Host '    "CoreFolder": "C:\\Caminho\\Para\\CoRe",' -ForegroundColor Gray
    Write-Host '    "CoreExecutable": "C:\\Caminho\\Para\\CoRe.exe",' -ForegroundColor Gray
    Write-Host '    "HS3DllPath": "C:\\Caminho\\Para\\hs3.dll"' -ForegroundColor Gray
    Write-Host '  }' -ForegroundColor Gray
    Write-Host ""
}
