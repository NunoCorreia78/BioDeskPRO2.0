$files = Get-ChildItem -Path "src\" -Recurse -Include *.xaml,*.cs
foreach ($file in $files) {
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)

    # Correções específicas
    $text = $text -replace 'Ã','á' -replace 'Ã§','ç' -replace 'Ã£','ã' -replace 'Ã','é' -replace 'Ã','í' -replace 'Ãº','ú' -replace 'Ã´','ô' -replace 'Ã ','à' -replace 'Ã','ó' -replace 'Ãª','ê' -replace 'á','á' -replace 'á§áµes','ções' -replace 'á§áµ','çõ' -replace 'á£o','ão' -replace 'á','é' -replace 'áº','ú' -replace 'á´','ô' -replace 'á','ó' -replace 'áª','ê' -replace 'á ','à' -replace 'Ã§Ã£o','ção' -replace 'Ã§Ãµes','ções' -replace 'Ã§Ã£','çã' -replace 'âšï','' -replace '📧','' -replace '📞','' -replace 'ðŸŒ','' -replace 'Õ','' -replace 'Õš','' -replace 'šœ','' -replace 'š'',''

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($file.FullName, $text, $utf8NoBom)
    Write-Host "Fixed: $($file.Name)"
}
