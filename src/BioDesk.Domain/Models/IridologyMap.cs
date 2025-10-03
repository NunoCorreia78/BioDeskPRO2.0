using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BioDesk.Domain.Models;

/// <summary>
/// Modelo completo do mapa iridológico carregado do JSON
/// </summary>
public class IridologyMap
{
    [JsonPropertyName("metadata")]
    public IridologyMetadata Metadata { get; set; } = new();

    [JsonPropertyName("zonas")]
    public List<IridologyZone> Zonas { get; set; } = new();
}

/// <summary>
/// Metadados do mapa iridológico
/// </summary>
public class IridologyMetadata
{
    [JsonPropertyName("versao")]
    public string Versao { get; set; } = string.Empty;

    [JsonPropertyName("tipo")]
    public string Tipo { get; set; } = string.Empty; // "esq" ou "drt"

    [JsonPropertyName("imagem_modelo")]
    public string ImagemModelo { get; set; } = string.Empty;

    [JsonPropertyName("calibracao_referencia")]
    public CalibracaoReferencia Calibracao { get; set; } = new();

    [JsonPropertyName("total_zonas")]
    public int TotalZonas { get; set; }

    [JsonPropertyName("criado_para")]
    public string CriadoPara { get; set; } = string.Empty;
}

/// <summary>
/// Calibração da íris (centro da pupila e raios)
/// </summary>
public class CalibracaoReferencia
{
    [JsonPropertyName("centro_pupila")]
    public List<double> CentroPupila { get; set; } = new();

    [JsonPropertyName("raio_pupila")]
    public double RaioPupila { get; set; }

    [JsonPropertyName("raio_iris")]
    public double RaioIris { get; set; }
}

/// <summary>
/// Zona reflexa da íris (órgão/sistema)
/// </summary>
public class IridologyZone
{
    [JsonPropertyName("nome")]
    public string Nome { get; set; } = string.Empty;

    [JsonPropertyName("descricao")]
    public string Descricao { get; set; } = string.Empty;

    [JsonPropertyName("partes")]
    public List<List<PolarPoint>> Partes { get; set; } = new();
}

/// <summary>
/// Ponto em coordenadas polares (ângulo em graus, raio normalizado 0-1)
/// </summary>
public class PolarPoint
{
    [JsonPropertyName("angulo")]
    public double Angulo { get; set; }

    [JsonPropertyName("raio")]
    public double Raio { get; set; }
}
