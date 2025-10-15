using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Services.Core;

/// <summary>
/// Resultado de análise de ressonância para um item
/// </summary>
public class ResultadoRessonancia
{
    /// <summary>
    /// Item do banco Core analisado
    /// </summary>
    public ItemBancoCore Item { get; set; } = null!;

    /// <summary>
    /// Valor de ressonância (0-100%)
    /// Quanto maior, maior a ressonância com o campo informacional do paciente
    /// </summary>
    public double ValuePercentage { get; set; }

    /// <summary>
    /// Ranking relativo (1 = mais alto)
    /// </summary>
    public int Ranking { get; set; }

    /// <summary>
    /// Timestamp da análise
    /// </summary>
    public DateTime AnalisadoEm { get; set; }

    /// <summary>
    /// Tipo de RNG usado na análise
    /// </summary>
    public TipoRng TipoRng { get; set; }
}

/// <summary>
/// Parâmetros para scanning de ressonância
/// </summary>
public class ParametrosScanning
{
    /// <summary>
    /// Seed gerado a partir dos dados do paciente (Nome + DataNascimento + Foto hash)
    /// </summary>
    public int Seed { get; set; }

    /// <summary>
    /// Categorias a incluir no scanning (null = todas)
    /// </summary>
    public List<CategoriaCore>? Categorias { get; set; }

    /// <summary>
    /// Filtro de género ("Masculino", "Feminino", "Ambos", null = todos)
    /// </summary>
    public string? GeneroFiltro { get; set; }

    /// <summary>
    /// Número de iterações RNG por item (padrão: 100)
    /// Mais iterações = mais preciso mas mais lento
    /// </summary>
    public int IteracoesPorItem { get; set; } = 100;

    /// <summary>
    /// Tipo de RNG a usar
    /// </summary>
    public TipoRng TipoRng { get; set; } = TipoRng.Cryptographic;

    /// <summary>
    /// Limitar resultados aos top N itens (null = todos)
    /// </summary>
    public int? TopN { get; set; }

    /// <summary>
    /// Incluir apenas itens com Value% acima deste threshold (0-100)
    /// </summary>
    public double ThresholdMinimo { get; set; } = 0;
}

/// <summary>
/// Interface para serviço de análise Core inspirado no Inergetix CoRe 5.0
/// Realiza scanning de ressonância entre campo informacional do paciente e itens do banco
/// </summary>
public interface ICoreAnaliseService
{
    /// <summary>
    /// Executa scanning de ressonância para um paciente
    /// </summary>
    Task<List<ResultadoRessonancia>> ScanAsync(ParametrosScanning parametros);

    /// <summary>
    /// Gera seed determinístico a partir dos dados do paciente
    /// </summary>
    int GenerateSeed(string nomeCompleto, DateTime? dataNascimento, string? fotoHash);
}

/// <summary>
/// Implementação do serviço de análise Core
/// Algoritmo inspirado no Inergetix CoRe 5.0
/// </summary>
public class CoreAnaliseService : ICoreAnaliseService
{
    private readonly BioDeskDbContext _context;
    private readonly RngServiceFactory _rngFactory;
    private readonly ILogger<CoreAnaliseService> _logger;

    public CoreAnaliseService(
        BioDeskDbContext context,
        RngServiceFactory rngFactory,
        ILogger<CoreAnaliseService> logger)
    {
        _context = context;
        _rngFactory = rngFactory;
        _logger = logger;
    }

    /// <summary>
    /// Executa scanning de ressonância
    /// Algoritmo: Para cada item, gera N valores RNG usando seed do paciente
    /// Value% = (hits acima do threshold / total iterações) * 100
    /// </summary>
    public async Task<List<ResultadoRessonancia>> ScanAsync(ParametrosScanning parametros)
    {
        _logger.LogInformation($"🔍 Iniciando scanning com seed {parametros.Seed}, {parametros.IteracoesPorItem} iterações, RNG: {parametros.TipoRng}");

        // 1. Carregar itens aplicáveis do banco
        var query = _context.ItensBancoCore.AsQueryable().Where(x => x.IsActive);

        // Filtro de categorias
        if (parametros.Categorias != null && parametros.Categorias.Any())
        {
            query = query.Where(x => parametros.Categorias.Contains(x.Categoria));
        }

        // Filtro de género
        if (!string.IsNullOrEmpty(parametros.GeneroFiltro))
        {
            query = query.Where(x =>
                x.GeneroAplicavel == "Ambos" ||
                x.GeneroAplicavel == parametros.GeneroFiltro);
        }

        var itens = await query.ToListAsync();
        _logger.LogInformation($"📊 {itens.Count} itens carregados para análise");

        if (itens.Count == 0)
        {
            _logger.LogWarning("⚠️ Nenhum item encontrado para análise");
            return new List<ResultadoRessonancia>();
        }

        // 2. Criar RNG apropriado
        var rng = _rngFactory.Create(parametros.TipoRng);
        if (!rng.IsAvailable)
        {
            _logger.LogWarning($"⚠️ RNG {parametros.TipoRng} não disponível - usando fallback");
            rng = _rngFactory.CreateBest();
        }

        // 3. Calcular Value% para cada item
        var resultados = new List<ResultadoRessonancia>();
        var timestamp = DateTime.UtcNow;

        foreach (var item in itens)
        {
            // Seed específico para este item (combina seed do paciente + hash do item)
            int itemSeed = CombineSeeds(parametros.Seed, item.ExternalId.GetHashCode());

            // Executar iterações RNG
            int hits = 0;
            for (int i = 0; i < parametros.IteracoesPorItem; i++)
            {
                // Gera valor 0-99 usando seed
                int valor = rng.NextWithSeed(itemSeed + i, 0, 100);

                // Hit se valor está acima do threshold (50 = ponto médio)
                if (valor >= 50)
                {
                    hits++;
                }
            }

            // Calcular Value% (0-100)
            double valuePercentage = (double)hits / parametros.IteracoesPorItem * 100.0;

            // Aplicar threshold mínimo
            if (valuePercentage >= parametros.ThresholdMinimo)
            {
                resultados.Add(new ResultadoRessonancia
                {
                    Item = item,
                    ValuePercentage = Math.Round(valuePercentage, 2),
                    AnalisadoEm = timestamp,
                    TipoRng = parametros.TipoRng
                });
            }
        }

        // 4. Ordenar por Value% (descendente) e atribuir rankings
        resultados = resultados
            .OrderByDescending(x => x.ValuePercentage)
            .ThenBy(x => x.Item.Nome)
            .ToList();

        for (int i = 0; i < resultados.Count; i++)
        {
            resultados[i].Ranking = i + 1;
        }

        // 5. Limitar a top N se especificado
        if (parametros.TopN.HasValue && parametros.TopN.Value > 0)
        {
            resultados = resultados.Take(parametros.TopN.Value).ToList();
        }

        _logger.LogInformation($"✅ Scanning completo: {resultados.Count} itens em ressonância");

        if (resultados.Count > 0)
        {
            var top3 = resultados.Take(3).Select(r => $"{r.Item.Nome} ({r.ValuePercentage}%)");
            _logger.LogInformation($"🏆 Top 3: {string.Join(", ", top3)}");
        }

        return resultados;
    }

    /// <summary>
    /// Gera seed determinístico a partir dos dados do paciente
    /// Usa SHA256 para criar seed único e reproduzível
    /// </summary>
    public int GenerateSeed(string nomeCompleto, DateTime? dataNascimento, string? fotoHash)
    {
        // Combinar dados do paciente
        var input = $"{nomeCompleto.ToLowerInvariant()}|{dataNascimento?.ToString("yyyyMMdd") ?? "00000000"}|{fotoHash ?? "no-photo"}";

        // Gerar hash SHA256
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));

        // Converter primeiros 4 bytes para int32
        int seed = BitConverter.ToInt32(hashBytes, 0);

        _logger.LogInformation($"🔑 Seed gerado: {seed} (input: {input.Substring(0, Math.Min(30, input.Length))}...)");

        return seed;
    }

    /// <summary>
    /// Combina dois seeds usando XOR
    /// </summary>
    private int CombineSeeds(int seed1, int seed2)
    {
        return seed1 ^ seed2;
    }
}
