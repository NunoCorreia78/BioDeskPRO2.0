using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;
using BioDesk.Domain.Models;

namespace BioDesk.Services;

/// <summary>
/// Simple ellipse descriptor used for pupil and iris calibration.
/// </summary>
public readonly record struct CalibrationEllipse(
    Point Center,
    double RadiusX,
    double RadiusY,
    double RotationDegrees);

/// <summary>
/// Aggregates every parameter required to map polar coordinates to the UI space.
/// </summary>
public sealed class IridologyTransformParameters
{
    public CalibrationEllipse Pupila { get; init; }
    public CalibrationEllipse Iris { get; init; }
    public double PupilExclusionMargin { get; init; } = 0.05;

    public static IridologyTransformParameters FromCalibracao(CalibracaoReferencia calibracao)
    {
        if (calibracao == null)
        {
            throw new ArgumentNullException(nameof(calibracao));
        }

        var center = ResolveCenter(calibracao);

        return new IridologyTransformParameters
        {
            Pupila = new CalibrationEllipse(
                center,
                calibracao.RaioPupila,
                calibracao.RaioPupila,
                0), // RotationDegrees
            Iris = new CalibrationEllipse(
                center,
                calibracao.RaioIris,
                calibracao.RaioIris,
                0) // RotationDegrees
        };
    }

    private static Point ResolveCenter(CalibracaoReferencia calibracao)
    {
        if (calibracao.CentroPupila.Count >= 2)
        {
            return new Point(
                calibracao.CentroPupila[0],
                calibracao.CentroPupila[1]);
        }

        return new Point();
    }
}

/// <summary>
/// Centralised helper that keeps hit-test and rendering in sync.
/// </summary>
public static class IridologyTransform
{
    public static Point ConvertPolarToPoint(PolarPoint polarPoint, IridologyTransformParameters parameters)
    {
        if (parameters == null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        var normalizedRadius = Math.Clamp(polarPoint.Raio, 0.0, 1.0);

        var normalizedPupilRadius = ComputeNormalizedPupilRadius(parameters);
        var minimum = Math.Clamp(normalizedPupilRadius + parameters.PupilExclusionMargin, 0.0, 1.0);
        if (normalizedRadius < minimum)
        {
            normalizedRadius = minimum;
        }

        var center = Lerp(parameters.Pupila.Center, parameters.Iris.Center, normalizedRadius);
        var radiusX = Lerp(parameters.Pupila.RadiusX, parameters.Iris.RadiusX, normalizedRadius);
        var radiusY = Lerp(parameters.Pupila.RadiusY, parameters.Iris.RadiusY, normalizedRadius);
        var rotation = LerpAngle(parameters.Pupila.RotationDegrees, parameters.Iris.RotationDegrees, normalizedRadius);

        var angleRad = (polarPoint.Angulo + rotation) * Math.PI / 180.0;

        var x = center.X + radiusX * normalizedRadius * Math.Cos(angleRad);
        var y = center.Y + radiusY * normalizedRadius * Math.Sin(angleRad);

        return new Point(x, y);
    }

    public static List<PointCollection> ConvertZoneToPointCollections(
        IridologyZone zona,
        IridologyTransformParameters parameters)
    {
        if (zona == null)
        {
            throw new ArgumentNullException(nameof(zona));
        }

        if (parameters == null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        var result = new List<PointCollection>(zona.Partes.Count);

        foreach (var parte in zona.Partes)
        {
            if (parte == null || parte.Count == 0)
            {
                continue;
            }

            var pontos = new PointCollection();

            foreach (var polar in parte)
            {
                pontos.Add(ConvertPolarToPoint(polar, parameters));
            }

            if (pontos.Count >= 3)
            {
                result.Add(pontos);
            }
        }

        return result;
    }

    public static (double AngleDegrees, double NormalizedRadius) ConvertPointToPolar(
        Point canvasPoint,
        IridologyTransformParameters parameters)
    {
        if (parameters == null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        var center = parameters.Pupila.Center;
        var dx = canvasPoint.X - center.X;
        var dy = canvasPoint.Y - center.Y;

        var angle = Math.Atan2(dy, dx) * 180.0 / Math.PI;
        angle = NormalizeAngle360(angle);

        var avgRadius = Math.Max(1e-6, (Math.Abs(parameters.Iris.RadiusX) + Math.Abs(parameters.Iris.RadiusY)) / 2.0);
        var normalizedRadius = Math.Sqrt(dx * dx + dy * dy) / avgRadius;

        return (angle, normalizedRadius);
    }

    private static double ComputeNormalizedPupilRadius(IridologyTransformParameters parameters)
    {
        var pupilMean = (Math.Abs(parameters.Pupila.RadiusX) + Math.Abs(parameters.Pupila.RadiusY)) / 2.0;
        var irisMean = Math.Max(1e-6, (Math.Abs(parameters.Iris.RadiusX) + Math.Abs(parameters.Iris.RadiusY)) / 2.0);
        return Math.Clamp(pupilMean / irisMean, 0.0, 1.0);
    }

    private static Point Lerp(Point a, Point b, double t) =>
        new(
            Lerp(a.X, b.X, t),
            Lerp(a.Y, b.Y, t));

    private static double Lerp(double a, double b, double t) =>
        a + ((b - a) * t);

    private static double LerpAngle(double a, double b, double t)
    {
        var delta = NormalizeAngle180(b - a);
        return a + (delta * t);
    }

    private static double NormalizeAngle180(double angle)
    {
        while (angle > 180.0) angle -= 360.0;
        while (angle < -180.0) angle += 360.0;
        return angle;
    }

    private static double NormalizeAngle360(double angle)
    {
        while (angle < 0.0) angle += 360.0;
        while (angle >= 360.0) angle -= 360.0;
        return angle;
    }
}
