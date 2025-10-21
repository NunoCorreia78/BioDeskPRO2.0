using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using BioDesk.Domain.Models;

namespace BioDesk.Services;

/// <summary>
/// Serviço para gestão de mapas iridológicos (carregamento JSON, renderização, hit-testing)
/// </summary>
public interface IIridologyService
{
    /// <summary>
    /// Carrega mapa iridológico do JSON ("esq" ou "drt")
    /// </summary>
    /// <param name="olho">Tipo de olho: "Esquerdo" ou "Direito"</param>
    /// <returns>Mapa iridológico completo</returns>
    Task<IridologyMap?> CarregarMapaAsync(string olho);

    /// <summary>
    /// Converte coordenadas polares para cartesianas com base na calibração da íris
    /// </summary>
    /// <param name="polarPoint">Ponto polar (ângulo em graus, raio 0-1)</param>
    /// <param name="calibracao">Calibração da íris (centro pupila + raios)</param>
    /// <returns>Ponto em coordenadas cartesianas (X, Y em pixels)</returns>
    Point ConverterPolarParaCartesiano(PolarPoint polarPoint, CalibracaoReferencia calibracao);

    /// <summary>
    /// Detecta zona iridológica baseada em clique (hit-testing polar)
    /// </summary>
    /// <param name="clickX">Coordenada X do clique (pixels)</param>
    /// <param name="clickY">Coordenada Y do clique (pixels)</param>
    /// <param name="mapa">Mapa iridológico carregado</param>
    /// <returns>Zona detectada ou null se fora de qualquer zona</returns>
    IridologyZone? DetectarZonaClique(double clickX, double clickY, IridologyMap mapa);

    /// <summary>
    /// Converte zona em lista de polígonos WPF (para renderização)
    /// </summary>
    /// <param name="zona">Zona iridológica</param>
    /// <param name="calibracao">Calibração da íris</param>
    /// <returns>Lista de PointCollections (cada parte da zona = 1 polígono)</returns>
    List<System.Windows.Media.PointCollection> ConverterZonaParaPoligonos(IridologyZone zona, CalibracaoReferencia calibracao);

    /// <summary>
    /// Converte zona para polígonos WPF com CANVAS FIXO (600x600px por padrão)
    /// Usado para mapa dedicado centralizado com tamanho fixo
    /// </summary>
    /// <param name="zona">Zona iridológica</param>
    /// <param name="canvasWidth">Largura do canvas (padrão: 600px)</param>
    /// <param name="canvasHeight">Altura do canvas (padrão: 600px)</param>
    /// <returns>Lista de PointCollections para renderização</returns>
    List<System.Windows.Media.PointCollection> ConverterZonaParaPoligonosCanvasFixo(IridologyZone zona, double canvasWidth = 600, double canvasHeight = 600);

    /// <summary>
    /// Detecta zona no CANVAS FIXO (600x600px por padrão)
    /// </summary>
    /// <param name="clickX">Coordenada X do clique</param>
    /// <param name="clickY">Coordenada Y do clique</param>
    /// <param name="mapa">Mapa iridológico carregado</param>
    /// <param name="canvasWidth">Largura do canvas (padrão: 600px)</param>
    /// <param name="canvasHeight">Altura do canvas (padrão: 600px)</param>
    /// <returns>Zona detectada ou null</returns>
    IridologyZone? DetectarZonaCliqueCanvasFixo(double clickX, double clickY, IridologyMap mapa, double canvasWidth = 600, double canvasHeight = 600);

    /// <summary>
    /// Offset de rotação (em graus) aplicado à conversão polar→cartesiano.
    /// Permite calibrar o mapa em runtime (ex.: deslizador na UI).
    /// Positivo = roda no sentido horário.
    /// </summary>
    double RotationOffsetDegrees { get; set; }
}
