# ========================================
# BioDeskPro2 - Setup Automático PC Novo
# ========================================
# Data: 18/10/2025
# Descrição: Automatiza configuração inicial no PC novo após transferência

param(
    [Parameter(Mandatory=$false)]
    [string]$CaminhoBD = "",

    [Parameter(Mandatory=$false)]
    [string]$CaminhoPacientes = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "🚀 BioDeskPro2 - Setup Automático PC Novo" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

# ========================================
# 1. Verificar Pré-requisitos
# ========================================
Write-Host "📋 1. Verificando Pré-requisitos..." -ForegroundColor Yellow

# Verificar .NET 8
try {
    $dotnetVersion = dotnet --version
    if ($dotnetVersion -notmatch "^8\.") {
        Write-Host "  ❌ .NET 8 não encontrado (versão atual: $dotnetVersion)" -ForegroundColor Red
        Write-Host "  📥 Baixe em: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  ✅ .NET SDK: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Host "  ❌ .NET SDK não instalado" -ForegroundColor Red
    Write-Host "  📥 Baixe em: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
    exit 1
}

# Verificar Git
try {
    $gitVersion = git --version
    Write-Host "  ✅ Git: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "  ❌ Git não instalado" -ForegroundColor Red
    Write-Host "  📥 Baixe em: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Verificar se está na pasta do projeto
if (-not (Test-Path "BioDeskPro2.sln")) {
    Write-Host "  ❌ Execute este script da raiz do projeto BioDeskPro2" -ForegroundColor Red
    exit 1
}
Write-Host "  ✅ Pasta do projeto: $(Get-Location)" -ForegroundColor Green

Write-Host ""

# ========================================
# 2. Verificar Branch Git
# ========================================
Write-Host "🌿 2. Verificando Branch Git..." -ForegroundColor Yellow

$currentBranch = git branch --show-current
if ($currentBranch -ne "copilot/vscode1760742399628") {
    Write-Host "  ⚠️  Branch atual: $currentBranch" -ForegroundColor Yellow
    Write-Host "  🔄 Fazendo checkout para: copilot/vscode1760742399628" -ForegroundColor Cyan

    git fetch origin
    git checkout copilot/vscode1760742399628
    git pull origin copilot/vscode1760742399628

    Write-Host "  ✅ Branch atualizada" -ForegroundColor Green
} else {
    Write-Host "  ✅ Branch correta: $currentBranch" -ForegroundColor Green

    # Verificar se há atualizações remotas
    git fetch origin
    $behind = git rev-list HEAD..origin/copilot/vscode1760742399628 --count
    if ([int]$behind -gt 0) {
        Write-Host "  🔄 Atualizando ($behind commits atrás)..." -ForegroundColor Cyan
        git pull origin copilot/vscode1760742399628
    }
}

Write-Host ""

# ========================================
# 3. Restaurar Base de Dados
# ========================================
Write-Host "💾 3. Restaurando Base de Dados..." -ForegroundColor Yellow

$dbDestino = Join-Path (Get-Location) "biodesk.db"

if ($CaminhoBD) {
    if (Test-Path $CaminhoBD) {
        $tamanhoKB = (Get-Item $CaminhoBD).Length / 1KB
        Write-Host "  📊 Tamanho BD origem: $([math]::Round($tamanhoKB, 2)) KB" -ForegroundColor Cyan

        if ($tamanhoKB -lt 10) {
            Write-Host "  ⚠️  BD parece vazia (<10KB) - continuar? (S/N)" -ForegroundColor Yellow
            $resposta = Read-Host
            if ($resposta -ne "S" -and $resposta -ne "s") {
                Write-Host "  ❌ Restauração BD cancelada" -ForegroundColor Red
                exit 1
            }
        }

        Copy-Item $CaminhoBD $dbDestino -Force
        Write-Host "  ✅ BD copiada: $dbDestino" -ForegroundColor Green
        Write-Host "  📊 Tamanho: $([math]::Round((Get-Item $dbDestino).Length / 1KB, 2)) KB" -ForegroundColor Cyan
    } else {
        Write-Host "  ❌ BD não encontrada em: $CaminhoBD" -ForegroundColor Red
        exit 1
    }
} elseif (Test-Path $dbDestino) {
    $tamanhoKB = (Get-Item $dbDestino).Length / 1KB
    Write-Host "  ✅ BD já existe: $([math]::Round($tamanhoKB, 2)) KB" -ForegroundColor Green

    if ($tamanhoKB -lt 10) {
        Write-Host "  ⚠️  BD parece vazia (<10KB)" -ForegroundColor Yellow
        Write-Host "  💡 Restaure manualmente: -CaminhoBD 'C:\Backups\...\biodesk.db'" -ForegroundColor Cyan
    }
} else {
    Write-Host "  ⚠️  BD não encontrada - será criada vazia na primeira execução" -ForegroundColor Yellow
    Write-Host "  💡 Para restaurar BD: -CaminhoBD 'C:\Backups\...\biodesk.db'" -ForegroundColor Cyan
}

Write-Host ""

# ========================================
# 4. Restaurar Pastas Documentais
# ========================================
Write-Host "📁 4. Restaurando Pastas Documentais..." -ForegroundColor Yellow

$pastasDocumentais = @("Pacientes", "Documentos", "Prescricoes", "Consentimentos", "Templates")

if ($CaminhoPacientes) {
    foreach ($pasta in $pastasDocumentais) {
        $origem = Join-Path $CaminhoPacientes $pasta
        $destino = Join-Path (Get-Location) $pasta

        if (Test-Path $origem) {
            Copy-Item -Path $origem -Destination $destino -Recurse -Force
            $ficheiros = (Get-ChildItem $destino -Recurse -File).Count
            Write-Host "  ✅ $pasta`: $ficheiros ficheiros" -ForegroundColor Green
        }
    }
} else {
    foreach ($pasta in $pastasDocumentais) {
        $caminho = Join-Path (Get-Location) $pasta
        if (Test-Path $caminho) {
            $ficheiros = (Get-ChildItem $caminho -Recurse -File -ErrorAction SilentlyContinue).Count
            Write-Host "  ✅ $pasta`: $ficheiros ficheiros" -ForegroundColor Green
        } else {
            New-Item -Path $caminho -ItemType Directory -Force | Out-Null
            Write-Host "  📂 $pasta`: Criada (vazia)" -ForegroundColor Cyan
        }
    }
}

Write-Host ""

# ========================================
# 5. Restaurar Dependências
# ========================================
if (-not $SkipBuild) {
    Write-Host "📦 5. Restaurando Dependências..." -ForegroundColor Yellow

    Write-Host "  🧹 Limpando build anterior..." -ForegroundColor Cyan
    dotnet clean | Out-Null

    Write-Host "  📥 Restaurando pacotes NuGet..." -ForegroundColor Cyan
    dotnet restore

    Write-Host "  ✅ Dependências restauradas" -ForegroundColor Green
    Write-Host ""

    # ========================================
    # 6. Build Completo
    # ========================================
    Write-Host "🔨 6. Compilando Projeto..." -ForegroundColor Yellow

    $buildOutput = dotnet build 2>&1
    $buildSuccess = $LASTEXITCODE -eq 0

    if ($buildSuccess) {
        # Contar errors/warnings
        $errors = ($buildOutput | Select-String "error").Count
        $warnings = ($buildOutput | Select-String "warning").Count

        Write-Host "  ✅ Build concluído" -ForegroundColor Green
        Write-Host "  📊 Errors: $errors | Warnings: $warnings" -ForegroundColor Cyan
    } else {
        Write-Host "  ❌ Build falhou" -ForegroundColor Red
        Write-Host ""
        Write-Host "🔍 Erros de Build:" -ForegroundColor Red
        $buildOutput | Select-String "error" | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }

    Write-Host ""

    # ========================================
    # 7. Executar Testes
    # ========================================
    Write-Host "🧪 7. Executando Testes..." -ForegroundColor Yellow

    $testOutput = dotnet test src/BioDesk.Tests 2>&1
    $testSuccess = $LASTEXITCODE -eq 0

    if ($testSuccess) {
        # Extrair resultados
        $passedLine = $testOutput | Select-String "Passed:.*Total:"
        if ($passedLine) {
            Write-Host "  ✅ $passedLine" -ForegroundColor Green
        }

        # Verificar se são 150 testes
        if ($testOutput -match "Passed:\s+(\d+)") {
            $testsPassed = [int]$matches[1]
            if ($testsPassed -eq 150) {
                Write-Host "  🎉 TODOS os 150 testes passaram!" -ForegroundColor Green
            } else {
                Write-Host "  ⚠️  Apenas $testsPassed de 150 testes passaram" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  ❌ Testes falharam" -ForegroundColor Red
        Write-Host ""
        Write-Host "🔍 Erros de Testes:" -ForegroundColor Red
        $testOutput | Select-String "Failed" | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }
} else {
    Write-Host "⏭️  Build e testes ignorados (-SkipBuild)" -ForegroundColor Cyan
}

Write-Host ""

# ========================================
# 8. Resumo Final
# ========================================
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "✅ SETUP CONCLUÍDO COM SUCESSO!" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

Write-Host "📋 Resumo:" -ForegroundColor Cyan
Write-Host "  ✅ .NET 8 SDK: Instalado" -ForegroundColor Green
Write-Host "  ✅ Git: Configurado" -ForegroundColor Green
Write-Host "  ✅ Branch: copilot/vscode1760742399628" -ForegroundColor Green

if (Test-Path $dbDestino) {
    $tamanhoKB = (Get-Item $dbDestino).Length / 1KB
    $statusBD = if ($tamanhoKB -gt 700) { "✅ Com dados" } elseif ($tamanhoKB -gt 10) { "⚠️  Parcial" } else { "❌ Vazia" }
    Write-Host "  $statusBD BD: $([math]::Round($tamanhoKB, 2)) KB" -ForegroundColor $(if ($tamanhoKB -gt 700) { "Green" } elseif ($tamanhoKB -gt 10) { "Yellow" } else { "Red" })
} else {
    Write-Host "  ⚠️  BD: Não configurada" -ForegroundColor Yellow
}

if (-not $SkipBuild) {
    Write-Host "  ✅ Build: 0 Errors" -ForegroundColor Green
    Write-Host "  ✅ Testes: Passaram" -ForegroundColor Green
}

Write-Host ""
Write-Host "🚀 Próximos Passos:" -ForegroundColor Cyan
Write-Host "  1. Abrir VS Code: code ." -ForegroundColor White
Write-Host "  2. Instalar extensões recomendadas (C# Dev Kit, GitLens)" -ForegroundColor White
Write-Host "  3. Executar aplicação: dotnet run --project src/BioDesk.App" -ForegroundColor White
Write-Host ""

Write-Host "💡 Dicas:" -ForegroundColor Cyan
Write-Host "  • Verificar Dashboard abre corretamente" -ForegroundColor White
Write-Host "  • Testar pesquisa de pacientes" -ForegroundColor White
Write-Host "  • Conferir dados da BD (pacientes recentes)" -ForegroundColor White
Write-Host ""

Write-Host "📚 Documentação:" -ForegroundColor Cyan
Write-Host "  • CHECKLIST_TRANSFERENCIA_PC_18OUT2025.md" -ForegroundColor White
Write-Host "  • GUIA_TRANSFERENCIA_PC_18OUT2025.md" -ForegroundColor White
Write-Host ""

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "Pressione ENTER para sair..." -ForegroundColor Gray
Read-Host
