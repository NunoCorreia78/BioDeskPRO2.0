using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using BioDesk.Domain.Models;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services;

/// <summary>
/// Implementação do serviço de mapas iridológicos
/// Responsabilidades:
/// - Carregar JSON files (iris_esq.json, iris_drt.json)
/// - Cache em memória
/// - Conversão polar → cartesiano
/// - Hit-testing polar (ray-casting)
/// </summary>
public class IridologyService : IIridologyService
{
    private readonly ILogger<IridologyService> _logger;
    private readonly Dictionary<string, IridologyMap> _cacheMapas = new();
    private readonly string _caminhoJsonBase;

    public IridologyService(ILogger<IridologyService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Caminho correto: BioDesk.App/Resources/IridologyMaps/
        // AppDomain.CurrentDomain.BaseDirectory = bin/Debug/net8.0-windows/
        // Subir 3 níveis até src/BioDesk.App/
        _caminhoJsonBase = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "..", "..", "..", // bin/Debug/net8.0-windows → src/BioDesk.App
            "Resources",
            "IridologyMaps"
        );

        var caminhoResolvido = Path.GetFullPath(_caminhoJsonBase);
        _logger.LogInformation("📂 IridologyService inicializado. Caminho JSON: {Caminho}", caminhoResolvido);

        // Verificar se pasta existe
        if (!Directory.Exists(caminhoResolvido))
        {
            _logger.LogError("❌ PASTA NÃO EXISTE: {Caminho}", caminhoResolvido);
        }
    }

    /// <summary>
    /// Carrega mapa iridológico do JSON com cache
    /// </summary>
    public async Task<IridologyMap?> CarregarMapaAsync(string olho)
    {
        // Normalizar entrada: "Esquerdo" → "esq", "Direito" → "drt"
        var tipoMapa = olho.ToLowerInvariant() switch
        {
            "esquerdo" => "esq",
            "direito" => "drt",
            _ => olho.ToLowerInvariant()
        };

        // Verificar cache
        if (_cacheMapas.TryGetValue(tipoMapa, out var mapaCacheado))
        {
            _logger.LogDebug("✅ Mapa '{Tipo}' carregado do cache", tipoMapa);
            return mapaCacheado;
        }

        try
        {
            // Construir caminho do JSON
            var nomeArquivo = $"iris_{tipoMapa}.json";
            var caminhoCompleto = Path.GetFullPath(Path.Combine(_caminhoJsonBase, nomeArquivo));

            _logger.LogInformation("📄 Carregando mapa iridológico: {Caminho}", caminhoCompleto);

            if (!File.Exists(caminhoCompleto))
            {
                _logger.LogError("❌ Arquivo JSON não encontrado: {Caminho}", caminhoCompleto);
                return null;
            }

            // Ler e deserializar JSON
            var jsonContent = await File.ReadAllTextAsync(caminhoCompleto);
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                AllowTrailingCommas = true
            };

            var mapa = JsonSerializer.Deserialize<IridologyMap>(jsonContent, options);

            if (mapa == null)
            {
                _logger.LogError("❌ Falha ao deserializar JSON: {Arquivo}", nomeArquivo);
                return null;
            }

            // Validar estrutura
            _logger.LogInformation("✅ Mapa carregado: {TotalZonas} zonas, Tipo: {Tipo}, Versão: {Versao}",
                mapa.Metadata.TotalZonas,
                mapa.Metadata.Tipo,
                mapa.Metadata.Versao);

            // Guardar em cache
            _cacheMapas[tipoMapa] = mapa;

            return mapa;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar mapa iridológico '{Tipo}'", tipoMapa);
            return null;
        }
    }

    /// <summary>
    /// Converte coordenada polar (ângulo, raio) para cartesiana (X, Y)
    /// </summary>
    public Point ConverterPolarParaCartesiano(PolarPoint polarPoint, CalibracaoReferencia calibracao)
    {
        // Centro da pupila (origem do sistema polar)
        var centroX = calibracao.CentroPupila[0];
        var centroY = calibracao.CentroPupila[1];

        // Raio em pixels (raio normalizado 0-1 × raio da íris)
        var raioPixels = polarPoint.Raio * calibracao.RaioIris;

        // Converter ângulo de graus para radianos
        var anguloRad = polarPoint.Angulo * Math.PI / 180.0;

        // Coordenadas cartesianas
        var x = centroX + raioPixels * Math.Cos(anguloRad);
        var y = centroY + raioPixels * Math.Sin(anguloRad);

        return new Point(x, y);
    }

    /// <summary>
    /// Converte zona completa (com múltiplas partes) em lista de polígonos WPF
    /// </summary>
    public List<PointCollection> ConverterZonaParaPoligonos(IridologyZone zona, CalibracaoReferencia calibracao)
    {
        var poligonos = new List<PointCollection>();

        foreach (var parte in zona.Partes)
        {
            var pontos = new PointCollection();

            foreach (var polarPoint in parte)
            {
                var cartesiano = ConverterPolarParaCartesiano(polarPoint, calibracao);
                pontos.Add(cartesiano);
            }

            // Apenas adicionar se tiver pelo menos 3 pontos (polígono válido)
            if (pontos.Count >= 3)
            {
                poligonos.Add(pontos);
            }
        }

        return poligonos;
    }

    /// <summary>
    /// Converte zona para polígonos WPF com CANVAS FIXO (600x600px)
    /// Usado para mapa dedicado centralizado
    /// </summary>
    public List<PointCollection> ConverterZonaParaPoligonosCanvasFixo(IridologyZone zona, double canvasWidth = 600, double canvasHeight = 600)
    {
        // Criar calibração virtual para canvas fixo
        // Centro no meio do canvas (300, 300 para 600x600)
        // Raio da íris = 90% do raio disponível (para margem)
        var centroX = canvasWidth / 2;
        var centroY = canvasHeight / 2;
        var raioIris = Math.Min(canvasWidth, canvasHeight) / 2 * 0.9; // 270px para 600x600

        var calibracaoVirtual = new CalibracaoReferencia
        {
            CentroPupila = new List<double> { centroX, centroY },
            RaioIris = raioIris,
            RaioPupila = raioIris * 0.2 // 20% do raio da íris
        };

        return ConverterZonaParaPoligonos(zona, calibracaoVirtual);
    }

    /// <summary>
    /// Detecta zona no CANVAS FIXO (600x600px)
    /// </summary>
    public IridologyZone? DetectarZonaCliqueCanvasFixo(double clickX, double clickY, IridologyMap mapa, double canvasWidth = 600, double canvasHeight = 600)
    {
        // Criar calibração virtual idêntica ao método de conversão
        var centroX = canvasWidth / 2;
        var centroY = canvasHeight / 2;
        var raioIris = Math.Min(canvasWidth, canvasHeight) / 2 * 0.9;

        var calibracaoVirtual = new CalibracaoReferencia
        {
            CentroPupila = new List<double> { centroX, centroY },
            RaioIris = raioIris,
            RaioPupila = raioIris * 0.2
        };

        // Atualizar metadata temporariamente (thread-safe)
        var calibracaoOriginal = mapa.Metadata.Calibracao;
        mapa.Metadata.Calibracao = calibracaoVirtual;

        var resultado = DetectarZonaClique(clickX, clickY, mapa);

        // Restaurar calibração original
        mapa.Metadata.Calibracao = calibracaoOriginal;

        return resultado;
    }

    /// <summary>
    /// Detecta zona iridológica baseada em clique (hit-testing polar)
    /// Algoritmo: Ray-casting em coordenadas polares
    /// </summary>
    public IridologyZone? DetectarZonaClique(double clickX, double clickY, IridologyMap mapa)
    {
        var calibracao = mapa.Metadata.Calibracao;
        var centroX = calibracao.CentroPupila[0];
        var centroY = calibracao.CentroPupila[1];

        // 1. Converter clique para coordenadas polares
        var deltaX = clickX - centroX;
        var deltaY = clickY - centroY;
        var angulo = Math.Atan2(deltaY, deltaX) * 180.0 / Math.PI; // graus
        var raio = Math.Sqrt(deltaX * deltaX + deltaY * deltaY);
        var raioNormalizado = raio / calibracao.RaioIris;

        _logger.LogDebug("🎯 Clique detectado: X={X}, Y={Y} → Ângulo={Ang:F2}°, Raio={Raio:F3}",
            clickX, clickY, angulo, raioNormalizado);

        // 2. Validar se está dentro da íris (raio 0-1)
        if (raioNormalizado < 0 || raioNormalizado > 1.0)
        {
            _logger.LogDebug("⚠️ Clique fora da íris (raio normalizado: {Raio})", raioNormalizado);
            return null;
        }

        // 3. Testar cada zona (ray-casting)
        foreach (var zona in mapa.Zonas)
        {
            foreach (var parte in zona.Partes)
            {
                if (PontoEmPoligonoPolar(angulo, raioNormalizado, parte))
                {
                    _logger.LogInformation("✅ Zona detectada: {Nome}", zona.Nome);
                    return zona;
                }
            }
        }

        _logger.LogDebug("⚠️ Nenhuma zona detectada no clique");
        return null;
    }

    /// <summary>
    /// Algoritmo Ray-Casting para detectar ponto dentro de polígono (coordenadas polares)
    /// </summary>
    private bool PontoEmPoligonoPolar(double angulo, double raio, List<PolarPoint> poligono)
    {
        // Normalizar ângulo para [0, 360)
        while (angulo < 0) angulo += 360;
        while (angulo >= 360) angulo -= 360;

        int intersecoes = 0;
        int n = poligono.Count;

        for (int i = 0; i < n; i++)
        {
            var p1 = poligono[i];
            var p2 = poligono[(i + 1) % n];

            // Normalizar ângulos
            var ang1 = NormalizarAngulo(p1.Angulo);
            var ang2 = NormalizarAngulo(p2.Angulo);

            // Ray horizontal em direção ao infinito (ângulo fixo, raio cresce)
            // Verifica se a aresta cruza o raio
            if ((ang1 <= angulo && angulo < ang2) || (ang2 <= angulo && angulo < ang1))
            {
                // Interpolar raio na aresta
                var t = (angulo - ang1) / (ang2 - ang1);
                var raioInterpolado = p1.Raio + t * (p2.Raio - p1.Raio);

                if (raio < raioInterpolado)
                {
                    intersecoes++;
                }
            }
        }

        // Ponto dentro se número ímpar de interseções
        return (intersecoes % 2) == 1;
    }

    /// <summary>
    /// Normaliza ângulo para intervalo [0, 360)
    /// </summary>
    private double NormalizarAngulo(double angulo)
    {
        while (angulo < 0) angulo += 360;
        while (angulo >= 360) angulo -= 360;
        return angulo;
    }
}
