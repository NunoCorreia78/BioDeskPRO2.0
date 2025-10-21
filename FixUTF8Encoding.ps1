# Fix UTF-8 Encoding Issues - BioDeskPro2
# Corrige caracteres corrompidos em TODOS os ficheiros C# e XAML

Write-Host "🔧 Iniciando correção UTF-8..." -ForegroundColor Cyan

# Mapeamento de caracteres corrompidos → corretos
$replacements = @{
    'Ã¡' = 'á'
    'Ã§Ã£' = 'ção'
    'Ã§'  = 'ç'
    'Ã£' = 'ã'
    'Ã©' = 'é'
    'Ã­' = 'í'
    'Ãº' = 'ú'
    'Ã´' = 'ô'
    'Ã ' = 'à'
    'Ã³' = 'ó'
    'Ãª' = 'ê'
    'Å¡' = 'š'
    '📧' = '📧'
    '📞' = '📞'
    '🌿' = '🌿'
    'â­' = '⭐'
    'âœ…' = '✅'
    'â„¢' = '™'
    'Â ' = ' '
}

$filesProcessed = 0
$filesFixed = 0

# Processar todos os ficheiros .cs e .xaml
Get-ChildItem -Path "src\" -Recurse -Include *.cs,*.xaml | ForEach-Object {
    $filesProcessed++
    $filePath = $_.FullName

    try {
        $content = Get-Content -Path $filePath -Raw -Encoding UTF8 -ErrorAction Stop
        $originalContent = $content

        # Aplicar todas as substituições
        foreach ($key in $replacements.Keys) {
            $content = $content -replace [regex]::Escape($key), $replacements[$key]
        }

        # Se houve alterações, gravar ficheiro
        if ($content -ne $originalContent) {
            $content | Set-Content -Path $filePath -Encoding UTF8 -NoNewline
            Write-Host "  ✅ Corrigido: $($_.Name)" -ForegroundColor Green
            $filesFixed++
        }
    }
    catch {
        Write-Host "  ⚠️ Erro ao processar $($_.Name): $_" -ForegroundColor Yellow
    }
}

Write-Host "`n📊 Resumo:" -ForegroundColor Cyan
Write-Host "  Ficheiros processados: $filesProcessed" -ForegroundColor White
Write-Host "  Ficheiros corrigidos: $filesFixed" -ForegroundColor Green
Write-Host "`n✅ Concluído!" -ForegroundColor Cyan
