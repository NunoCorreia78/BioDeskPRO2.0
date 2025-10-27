using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using BioDesk.Domain.Models;

#nullable enable

namespace BioDesk.Services;

/// <summary>
/// Renderizador centralizado para mapas iridológicos.
/// Delega para IridologyTransform para garantir consistência nas transformações.
/// </summary>
public class IridologyRenderer
{
    /// <summary>
    /// Renderiza o mapa iridológico completo com calibração aplicada.
    /// </summary>
    /// <param name="map">Mapa carregado do JSON (iris_drt.json ou iris_esq.json)</param>
    /// <param name="parameters">Parâmetros de calibração (pupila, íris, transformações)</param>
    /// <returns>GeometryGroup com todos os polígonos, pronto para render no XAML</returns>
    public GeometryGroup Render(IridologyMap map, IridologyTransformParameters parameters)
    {
        if (map?.Zonas == null || parameters == null)
            return new GeometryGroup();

        var group = new GeometryGroup { FillRule = FillRule.EvenOdd };

        foreach (var zona in map.Zonas)
        {
            var pointCollections = IridologyTransform.ConvertZoneToPointCollections(zona, parameters);

            foreach (var pointCollection in pointCollections)
            {
                if (pointCollection.Count < 3)
                    continue;

                var pathFigure = new PathFigure
                {
                    StartPoint = pointCollection[0],
                    IsClosed = true
                };

                for (int i = 1; i < pointCollection.Count; i++)
                {
                    pathFigure.Segments.Add(new LineSegment(pointCollection[i], isStroked: true));
                }

                var pathGeometry = new PathGeometry();
                pathGeometry.Figures.Add(pathFigure);
                group.Children.Add(pathGeometry);
            }
        }

        return group;
    }

    /// <summary>
    /// Cria Clip (máscara) para excluir a área da pupila.
    /// Usar como Canvas.Clip no overlay para garantir centro limpo.
    /// </summary>
    public EllipseGeometry CreatePupilaClip(IridologyTransformParameters parameters)
    {
        if (parameters == null)
            return new EllipseGeometry();

        return new EllipseGeometry
        {
            Center = parameters.Pupila.Center,
            RadiusX = parameters.Pupila.RadiusX,
            RadiusY = parameters.Pupila.RadiusY
        };
    }

    /// <summary>
    /// Hit-test: detecta em que zona o utilizador clicou.
    /// </summary>
    public IridologyZone? HitTest(Point clickPoint, IridologyMap map, IridologyTransformParameters parameters)
    {
        if (map?.Zonas == null || parameters == null)
            return null;

        var (angleDegrees, normalizedRadius) = IridologyTransform.ConvertPointToPolar(clickPoint, parameters);

        // Testar cada zona usando coordenadas polares
        foreach (var zona in map.Zonas)
        {
            foreach (var parte in zona.Partes)
            {
                if (PointInPolarPolygon(angleDegrees, normalizedRadius, parte))
                    return zona;
            }
        }

        return null;
    }

    private bool PointInPolarPolygon(double angle, double radius, List<PolarPoint> polygon)
    {
        if (polygon == null || polygon.Count < 3)
            return false;

        // Ray casting algorithm (versão polar)
        int intersections = 0;
        for (int i = 0; i < polygon.Count; i++)
        {
            var p1 = polygon[i];
            var p2 = polygon[(i + 1) % polygon.Count];

            if ((p1.Angulo <= angle && p2.Angulo > angle) ||
                (p2.Angulo <= angle && p1.Angulo > angle))
            {
                var t = (angle - p1.Angulo) / (p2.Angulo - p1.Angulo);
                var radiusAtAngle = p1.Raio + t * (p2.Raio - p1.Raio);

                if (radius < radiusAtAngle)
                    intersections++;
            }
        }

        return (intersections % 2) == 1;
    }
}
