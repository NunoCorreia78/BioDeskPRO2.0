# ExtrairFrequenciasCoRe.ps1
# Procura e extrai arquivos de frequências do CoRe System
# BUSCA: Instalação do CoRe, AppData, ProgramData

Write-Host "=== EXTRAÇÃO FREQUÊNCIAS CoRe SYSTEM ===" -ForegroundColor Cyan
Write-Host ""

# Caminhos possíveis de instalação CoRe
$possiblePaths = @(
    "C:\Program Files\CoRe",
    "C:\Program Files (x86)\CoRe",
    "C:\CoRe",
    "$env:ProgramData\CoRe",
    "$env:LOCALAPPDATA\CoRe",
    "$env:APPDATA\CoRe"
)

Write-Host "🔍 Procurando instalação do CoRe..." -ForegroundColor Cyan
$foundPaths = @()

foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        Write-Host "✅ Encontrado: $path" -ForegroundColor Green
        $foundPaths += $path
    }
}

if ($foundPaths.Count -eq 0) {
    Write-Host "❌ Nenhuma instalação do CoRe encontrada!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Por favor, indicar caminho manualmente:" -ForegroundColor Yellow
    Write-Host "  .\ExtrairFrequenciasCoRe.ps1 -CustomPath 'C:\Caminho\Para\CoRe'" -ForegroundColor Gray
    exit 1
}

Write-Host ""
Write-Host "=== PROCURANDO ARQUIVOS DE FREQUÊNCIAS ===" -ForegroundColor Cyan
Write-Host ""

$allFrequencyFiles = @()

foreach ($basePath in $foundPaths) {
    Write-Host "📂 Analisando: $basePath" -ForegroundColor White

    # Procurar .TXT, .DAT, .FRQ, .XML (formatos possíveis)
    $extensions = @("*.txt", "*.dat", "*.frq", "*.xml", "*.csv")

    foreach ($ext in $extensions) {
        $files = Get-ChildItem -Path $basePath -Filter $ext -Recurse -ErrorAction SilentlyContinue

        if ($files) {
            Write-Host "   Encontrados $($files.Count) arquivos $ext" -ForegroundColor White
            $allFrequencyFiles += $files
        }
    }
}

Write-Host ""
Write-Host "=== ANÁLISE DE CONTEÚDO ===" -ForegroundColor Yellow
Write-Host ""

if ($allFrequencyFiles.Count -eq 0) {
    Write-Host "⚠️  Nenhum arquivo de dados encontrado" -ForegroundColor Yellow
    exit 0
}

$frequencyData = @()

foreach ($file in $allFrequencyFiles) {
    Write-Host "📄 Analisando: $($file.Name)" -ForegroundColor Cyan

    try {
        $content = Get-Content $file.FullName -ErrorAction Stop

        # Tentar detectar padrões de frequências
        $patterns = @(
            "\d+\.?\d*\s*Hz",           # 432.0 Hz
            "\d+\.?\d*\s*\|\s*\d+",     # 432.0 | 50 (Hz | Duty)
            "frequency[:\s=]+\d+\.?\d*", # frequency: 432.0
            "\d{2,5}\.\d{1,2}"          # Números decimais (possíveis Hz)
        )

        $matches = @()
        foreach ($pattern in $patterns) {
            $found = $content | Select-String -Pattern $pattern -AllMatches
            if ($found) {
                $matches += $found.Matches | ForEach-Object { $_.Value }
            }
        }

        if ($matches.Count -gt 0) {
            Write-Host "   ✅ Detectadas $($matches.Count) frequências" -ForegroundColor Green
            Write-Host "   Exemplos: $($matches | Select-Object -First 5 -Unique -Join ', ')" -ForegroundColor Gray

            $frequencyData += [PSCustomObject]@{
                Arquivo = $file.Name
                Caminho = $file.FullName
                TotalFrequencias = $matches.Count
                Amostra = ($matches | Select-Object -First 10 -Unique)
            }
        } else {
            Write-Host "   ⚠️  Formato não reconhecido" -ForegroundColor Yellow
        }

        # Mostrar primeiras 3 linhas
        Write-Host "   Preview:" -ForegroundColor Gray
        $content | Select-Object -First 3 | ForEach-Object {
            Write-Host "     $_" -ForegroundColor DarkGray
        }
        Write-Host ""

    } catch {
        Write-Host "   ❌ Erro ao ler: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Exportar para CSV
if ($frequencyData.Count -gt 0) {
    $exportPath = "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts\CoRe_Frequencias_Extraidas.csv"
    $frequencyData | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "=== EXPORTAÇÃO ===" -ForegroundColor Green
    Write-Host "✅ Dados exportados para: $exportPath" -ForegroundColor White
    Write-Host ""
}

Write-Host "=== RESUMO ===" -ForegroundColor Cyan
Write-Host "   Total arquivos analisados: $($allFrequencyFiles.Count)" -ForegroundColor White
Write-Host "   Arquivos com frequências: $($frequencyData.Count)" -ForegroundColor White
Write-Host ""
Write-Host "💡 Próximos passos:" -ForegroundColor Yellow
Write-Host "   1. Revisar arquivos CSV exportados" -ForegroundColor White
Write-Host "   2. Importar frequências para BioDeskPro2 (SQL)" -ForegroundColor White
Write-Host "   3. Comparar com frequências já existentes no banco" -ForegroundColor White
Write-Host ""
