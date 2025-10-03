# Script PowerShell para gerar imagem de pseudo-íris para testes
# Requer: .NET (System.Drawing)

Add-Type -AssemblyName System.Drawing

# Configurações
$largura = 800
$altura = 600
$raioIris = 150
$centroX = $largura / 2
$centroY = $altura / 2

# Criar bitmap
$bitmap = New-Object System.Drawing.Bitmap($largura, $altura)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Fundo preto (esclerótica)
$brushPreto = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::Black)
$graphics.FillRectangle($brushPreto, 0, 0, $largura, $altura)

# Íris (castanho/verde com gradiente radial)
$corCentro = [System.Drawing.Color]::FromArgb(139, 90, 43)  # Castanho
$corBorda = [System.Drawing.Color]::FromArgb(101, 67, 33)   # Castanho escuro

$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$path.AddEllipse($centroX - $raioIris, $centroY - $raioIris, $raioIris * 2, $raioIris * 2)

$brush = New-Object System.Drawing.Drawing2D.PathGradientBrush($path)
$brush.CenterColor = $corCentro
$brush.SurroundColors = @($corBorda)

$graphics.FillEllipse($brush, $centroX - $raioIris, $centroY - $raioIris, $raioIris * 2, $raioIris * 2)

# Pupila (preto central)
$raioPupila = 50
$brushPupila = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::Black)
$graphics.FillEllipse($brushPupila, $centroX - $raioPupila, $centroY - $raioPupila, $raioPupila * 2, $raioPupila * 2)

# Adicionar alguns "sinais" para testar marcações
$random = New-Object System.Random

# 5 manchas aleatórias
for ($i = 0; $i -lt 5; $i++) {
    $angulo = $random.NextDouble() * 2 * [Math]::PI
    $distancia = $raioPupila + ($random.NextDouble() * ($raioIris - $raioPupila))

    $x = $centroX + ($distancia * [Math]::Cos($angulo))
    $y = $centroY + ($distancia * [Math]::Sin($angulo))

    $tamanho = 3 + ($random.Next(5))

    # Cor variada (manchas escuras)
    $cor = [System.Drawing.Color]::FromArgb(50, 30, 10)
    $brushMancha = New-Object System.Drawing.SolidBrush($cor)
    $graphics.FillEllipse($brushMancha, $x - $tamanho, $y - $tamanho, $tamanho * 2, $tamanho * 2)
}

# Adicionar textura de fibras radiadas (linhas finas)
$penFibra = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(80, 50, 20), 1)

for ($i = 0; $i -lt 24; $i++) {
    $angulo = ($i / 24.0) * 2 * [Math]::PI

    $x1 = $centroX + ($raioPupila * [Math]::Cos($angulo))
    $y1 = $centroY + ($raioPupila * [Math]::Sin($angulo))

    $x2 = $centroX + ($raioIris * [Math]::Cos($angulo))
    $y2 = $centroY + ($raioIris * [Math]::Sin($angulo))

    $graphics.DrawLine($penFibra, $x1, $y1, $x2, $y2)
}

# Adicionar reflexo (realismo)
$corReflexo = [System.Drawing.Color]::FromArgb(150, 255, 255, 255)
$brushReflexo = New-Object System.Drawing.SolidBrush($corReflexo)
$graphics.FillEllipse($brushReflexo, $centroX - $raioPupila + 15, $centroY - $raioPupila + 15, 20, 20)

# Guardar
$caminhoSaida = Join-Path $PSScriptRoot "pseudo_iris_teste.jpg"
$bitmap.Save($caminhoSaida, [System.Drawing.Imaging.ImageFormat]::Jpeg)

Write-Host "✅ Pseudo-íris criada com sucesso: $caminhoSaida" -ForegroundColor Green
Write-Host "   Dimensões: ${largura}x${altura}px" -ForegroundColor Cyan
Write-Host "   Características: pupila, íris castanha, 5 manchas, fibras radiadas, reflexo" -ForegroundColor Cyan

# Limpar recursos
$graphics.Dispose()
$bitmap.Dispose()
$brushPreto.Dispose()
$brush.Dispose()
$brushPupila.Dispose()
$penFibra.Dispose()
$brushReflexo.Dispose()
