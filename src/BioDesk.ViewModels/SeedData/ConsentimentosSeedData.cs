using BioDesk.Domain.Entities;
using System;
using System.Collections.Generic;

namespace BioDesk.ViewModels.SeedData;

/// <summary>
/// Dados de exemplo para desenvolvimento e testes
/// Usar apenas em ambiente DEBUG
/// </summary>
public static class ConsentimentosSeedData
{
    /// <summary>
    /// Retorna lista de consentimentos de exemplo para testes
    /// </summary>
    public static List<ConsentimentoInformado> GetExemplos()
    {
        return new List<ConsentimentoInformado>
        {
            new ConsentimentoInformado
            {
                Id = 1,
                TipoTratamento = "Fitoterapia",
                DescricaoTratamento = "Tratamento com plantas medicinais para ansiedade",
                DataCriacao = DateTime.Now.AddDays(-30),
                Estado = "Ativo",
                NumeroSessoesPrevistas = 10,
                CustoPorSessao = 45,
                CustoTotalEstimado = 450
            },
            new ConsentimentoInformado
            {
                Id = 2,
                TipoTratamento = "Acupunctura",
                DescricaoTratamento = "Tratamento para dores lombares",
                DataCriacao = DateTime.Now.AddDays(-15),
                Estado = "Ativo",
                NumeroSessoesPrevistas = 8,
                CustoPorSessao = 50,
                CustoTotalEstimado = 400
            },
            new ConsentimentoInformado
            {
                Id = 3,
                TipoTratamento = "Massagem",
                DescricaoTratamento = "Massagem relaxante mensal",
                DataCriacao = DateTime.Now.AddDays(-60),
                Estado = "Revogado",
                DataRevogacao = DateTime.Now.AddDays(-10),
                MotivoRevogacao = "Mudança de terapeuta",
                NumeroSessoesPrevistas = 12,
                CustoPorSessao = 40,
                CustoTotalEstimado = 480
            }
        };
    }

    /// <summary>
    /// Verifica se deve carregar dados de exemplo
    /// </summary>
    public static bool ShouldLoadSampleData()
    {
#if DEBUG
        return System.Diagnostics.Debugger.IsAttached;
#else
        return false;
#endif
    }
}
