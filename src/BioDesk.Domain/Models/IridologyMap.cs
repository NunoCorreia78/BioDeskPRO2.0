using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BioDesk.Domain.Models;

/// <summary>
/// Modelo completo do mapa iridológico carregado do JSON
/// ✨ SUPORTE v4.0: Compatível com mapas bi-dimensionais (corporal + comportamental)
/// </summary>
public class IridologyMap
{
    [JsonPropertyName("metadata")]
    public IridologyMetadata Metadata { get; set; } = new();

    /// <summary>
    /// Zonas diretas (compatibilidade v3.x e anteriores)
    /// </summary>
    [JsonPropertyName("zonas")]
    public List<IridologyZone>? Zonas { get; set; }

    /// <summary>
    /// Mapa corporal v4.0 (Jensen/Deck)
    /// </summary>
    [JsonPropertyName("mapa_corporal")]
    public MapaCorporal? MapaCorporal { get; set; }

    /// <summary>
    /// Mapa comportamental v4.0 (Rayid Model)
    /// </summary>
    [JsonPropertyName("mapa_comportamental")]
    public MapaComportamental? MapaComportamental { get; set; }

    /// <summary>
    /// Tipos Rayid v4.0
    /// </summary>
    [JsonPropertyName("tipos_rayid")]
    public Dictionary<string, RayidType>? TiposRayid { get; set; }

    /// <summary>
    /// 🔧 HELPER: Retorna zonas do mapa ativo (corporal por padrão)
    /// Garante compatibilidade retroativa
    /// </summary>
    [JsonIgnore]
    public List<IridologyZone> ZonasAtivas => 
        MapaCorporal?.Zonas ?? Zonas ?? new List<IridologyZone>();
}

/// <summary>
/// Mapa corporal v4.0 (Jensen/Deck)
/// </summary>
public class MapaCorporal
{
    [JsonPropertyName("zonas")]
    public List<IridologyZone> Zonas { get; set; } = new();
}

/// <summary>
/// Mapa comportamental v4.0 (Rayid Model)
/// </summary>
public class MapaComportamental
{
    [JsonPropertyName("zonas")]
    public List<ZonaComportamental> Zonas { get; set; } = new();
}

/// <summary>
/// Zona comportamental (análise psicoemocional)
/// </summary>
public class ZonaComportamental
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("nome")]
    public string Nome { get; set; } = string.Empty;

    [JsonPropertyName("aspecto")]
    public string Aspecto { get; set; } = string.Empty;

    [JsonPropertyName("interpretacao_rayid")]
    public string InterpretacaoRayid { get; set; } = string.Empty;

    [JsonPropertyName("desequilibrio")]
    public string Desequilibrio { get; set; } = string.Empty;

    [JsonPropertyName("equilibrio")]
    public string Equilibrio { get; set; } = string.Empty;
}

/// <summary>
/// Tipo Rayid v4.0
/// </summary>
public class RayidType
{
    [JsonPropertyName("nome")]
    public string Nome { get; set; } = string.Empty;

    [JsonPropertyName("tipo_energia")]
    public string TipoEnergia { get; set; } = string.Empty;

    [JsonPropertyName("arquetipo")]
    public string Arquetipo { get; set; } = string.Empty;

    [JsonPropertyName("palavras_chave")]
    public List<string> PalavrasChave { get; set; } = new();

    [JsonPropertyName("fortalezas")]
    public List<string> Fortalezas { get; set; } = new();

    [JsonPropertyName("desafios")]
    public List<string> Desafios { get; set; } = new();
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
