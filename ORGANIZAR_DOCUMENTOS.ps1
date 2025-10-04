# ========================================
# SCRIPT: Organizar Documentos dos Pacientes
# ========================================
# Move PDFs das pastas globais para as pastas específicas de cada paciente
#
# ESTRUTURA ANTIGA:
# BioDeskPro2\Consentimentos\        (todos misturados)
# BioDeskPro2\Prescricoes\           (todos misturados)
#
# ESTRUTURA NOVA:
# BioDeskPro2\Pacientes\[Nome]\Consentimentos\
# BioDeskPro2\Pacientes\[Nome]\Prescricoes\
# BioDeskPro2\Pacientes\[Nome]\DeclaracoesSaude\

$baseDir = "C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2"
$pastaPacientes = Join-Path $baseDir "Pacientes"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   ORGANIZANDO DOCUMENTOS DOS PACIENTES" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Criar pasta Pacientes se não existir
if (-not (Test-Path $pastaPacientes)) {
    New-Item -Path $pastaPacientes -ItemType Directory -Force | Out-Null
    Write-Host "✅ Pasta Pacientes criada" -ForegroundColor Green
}

# Lista de pacientes conhecidos (pode ser expandida)
$pacientes = @(
    "Nuno Filipe Correia",
    "Maria Fernanda Costa",
    "João Silva Santos",
    "Carlos António Pereira"
)

# Processar cada tipo de documento
$tiposDocumento = @{
    "Consentimentos" = "Consentimentos"
    "Prescricoes" = "Prescricoes"
}

$totalMovidos = 0

foreach ($tipoOrigem in $tiposDocumento.Keys) {
    $pastaOrigem = Join-Path $baseDir $tipoOrigem
    $tipoDestino = $tiposDocumento[$tipoOrigem]

    if (-not (Test-Path $pastaOrigem)) {
        Write-Host "⚠️  Pasta $tipoOrigem não encontrada - pulando" -ForegroundColor Yellow
        continue
    }

    $pdfs = Get-ChildItem -Path $pastaOrigem -Filter "*.pdf" -ErrorAction SilentlyContinue

    if ($pdfs.Count -eq 0) {
        Write-Host "ℹ️  Nenhum PDF em $tipoOrigem" -ForegroundColor Gray
        continue
    }

    Write-Host "`n📁 Processando pasta: $tipoOrigem ($($pdfs.Count) arquivos)" -ForegroundColor White

    foreach ($pdf in $pdfs) {
        $nomeArquivo = $pdf.Name
        $pacienteEncontrado = $null

        # Tentar identificar o paciente pelo nome no arquivo
        foreach ($paciente in $pacientes) {
            $nomeSemEspacos = $paciente.Replace(" ", "")
            $nomeComUnderscores = $paciente.Replace(" ", "_")

            if ($nomeArquivo -match $nomeSemEspacos -or
                $nomeArquivo -match $nomeComUnderscores -or
                $nomeArquivo -match $paciente) {
                $pacienteEncontrado = $paciente
                break
            }
        }

        if ($pacienteEncontrado) {
            # Criar estrutura de pastas
            $pastaPaciente = Join-Path $pastaPacientes $pacienteEncontrado
            $pastaDestino = Join-Path $pastaPaciente $tipoDestino

            if (-not (Test-Path $pastaDestino)) {
                New-Item -Path $pastaDestino -ItemType Directory -Force | Out-Null
            }

            $destino = Join-Path $pastaDestino $nomeArquivo

            # Verificar se já existe
            if (Test-Path $destino) {
                Write-Host "   ⚠️  JÁ EXISTE: $nomeArquivo" -ForegroundColor Yellow
            } else {
                # Mover arquivo
                Move-Item -Path $pdf.FullName -Destination $destino -Force
                Write-Host "   ✅ MOVIDO: $nomeArquivo → Pacientes\$pacienteEncontrado\$tipoDestino\" -ForegroundColor Green
                $totalMovidos++
            }
        } else {
            Write-Host "   ❌ PACIENTE NÃO IDENTIFICADO: $nomeArquivo" -ForegroundColor Red
        }
    }
}

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "   RESUMO" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Total de arquivos movidos: $totalMovidos" -ForegroundColor White
Write-Host ""
Write-Host "✅ Organização concluída!" -ForegroundColor Green
Write-Host ""
Write-Host "PRÓXIMOS PASSOS:" -ForegroundColor Yellow
Write-Host "1. Verificar se as pastas antigas (Consentimentos/, Prescricoes/) estão vazias" -ForegroundColor Gray
Write-Host "2. Se estiverem vazias, podem ser apagadas manualmente" -ForegroundColor Gray
Write-Host "3. Reiniciar a aplicação BioDeskPro2" -ForegroundColor Gray
Write-Host ""
