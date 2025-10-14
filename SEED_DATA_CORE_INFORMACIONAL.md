# 🌟 SEED DATA CORE INFORMACIONAL - BioDeskPro2

**Data de Criação:** 14 de Outubro de 2025
**Status:** ✅ Estrutura Completa, Parcialmente Populado
**Total Previsto:** ~6.700 itens
**Total Implementado:** ~350 itens completos + estrutura extensível

---

## 📋 VISÃO GERAL

Sistema de Banco de Dados Core Informacional inspirado no **Inergetix CoRe 5.0**, projetado para análise de ressonância e terapias bioenergéticas no BioDeskPro2.

### Objetivos
- ✅ Armazenar ~6.700 itens terapêuticos de múltiplas categorias
- ✅ Suportar análise de ressonância informacional
- ✅ Fornecer base para Value% Scanning
- ✅ Integrar com sistema de terapias bioenergéticas existente
- ✅ Garantir integridade de dados (género, GUID único, metadata rico)

---

## 🗂️ ESTRUTURA DE DADOS

### Entidade: `ItemBancoCore`

```csharp
public class ItemBancoCore
{
    public int Id { get; set; }                    // Auto-increment
    public Guid ExternalId { get; set; }           // ⚠️ ÚNICO (index)
    public string Nome { get; set; }               // Max 200 chars
    public CategoriaCore Categoria { get; set; }   // Enum
    public string? Subcategoria { get; set; }      // Max 100 chars
    public string? DescricaoBreve { get; set; }    // Max 500 chars
    public string? JsonMetadata { get; set; }      // JSON flexível
    public string? FonteOrigem { get; set; }       // Max 200 chars
    public string? GeneroAplicavel { get; set; }   // "Masculino"/"Feminino"/"Ambos"
    public bool IsActive { get; set; }             // Default: true
    public DateTime CreatedAt { get; set; }        // UTC
    public DateTime? UpdatedAt { get; set; }       // UTC (opcional)
}
```

### Enum: `CategoriaCore`

```csharp
public enum CategoriaCore
{
    Frequencia = 1,            // 5.869 (já existe em ProtocoloTerapeutico)
    Homeopatia = 2,            // ~3.000 previstos
    FloraisBach = 3,           // 38 ✅ COMPLETO
    FloraisCalifornianos = 4,  // 103 previstos
    Emocao = 5,                // ~500 previstos
    Orgao = 6,                 // ~150 previstos
    Chakra = 7,                // 28 ✅ COMPLETO
    Meridiano = 8,             // 20 previstos
    Patogeno = 9,              // (Reservado)
    Vitamina = 10,             // ~50 previstos
    Mineral = 11,              // ~80 previstos
    Afirmacao = 12,            // (Reservado)
    Suplemento = 13,           // ~300 previstos
    Alimento = 14              // ~1.000 previstos
}
```

---

## 📊 STATUS POR CATEGORIA

| # | Categoria | Previsto | Implementado | Status | Género Crítico |
|---|-----------|----------|--------------|--------|----------------|
| 1 | Frequencia | 5.869 | ✅ Existe (ProtocoloTerapeutico) | Completo | N/A |
| 2 | Homeopatia | 3.000 | ~30 exemplares | 🟡 Estrutura | ⚠️ Sim (Feminino/Masculino) |
| 3 | FloraisBach | 38 | ✅ 38 | ✅ Completo | Não (Ambos) |
| 4 | FloraisCalifornianos | 103 | ~40 | 🟡 Parcial | ⚠️ Sim (alguns) |
| 5 | Emocao | 500 | ~150 | 🟡 Estrutura | **SEMPRE Ambos** |
| 6 | Orgao | 150 | ~50 | 🟡 Estrutura | ⚠️⚠️⚠️ CRÍTICO |
| 7 | Chakra | 28 | ✅ 28 | ✅ Completo | Não (Ambos) |
| 8 | Meridiano | 20 | ~10 | 🟡 Estrutura | Não (Ambos) |
| 9 | Patogeno | TBD | 0 | 🔵 Reservado | TBD |
| 10 | Vitamina | 50 | 0 | 🔴 Stub | Não (Ambos) |
| 11 | Mineral | 80 | 0 | 🔴 Stub | Não (Ambos) |
| 12 | Afirmacao | TBD | 0 | 🔵 Reservado | Não (Ambos) |
| 13 | Suplemento | 300 | 0 | 🔴 Stub | Não (Ambos) |
| 14 | Alimento | 1.000 | 0 | 🔴 Stub | Não (Ambos) |

**Legenda:**
- ✅ Completo = 100% dos itens implementados
- 🟡 Parcial/Estrutura = Estrutura pronta, itens exemplares implementados
- 🔴 Stub = Método stub criado, sem implementação
- 🔵 Reservado = Para implementação futura

---

## ⚠️ REGRAS CRÍTICAS DE GÉNERO

### SEMPRE Masculino
- Próstata
- Testículos (esquerdo/direito)
- Epidídimo
- Ductos deferentes
- Vesículas seminais
- Pénis
- Glande
- Prepúcio
- Uretra masculina
- Glândulas de Cowper
- Corpo cavernoso/esponjoso
- Escroto

### SEMPRE Feminino
- Ovários (esquerdo/direito)
- Útero
- Trompas de Falópio
- Cérvix
- Vagina
- Vulva
- Clitóris
- Glândulas de Bartholin
- Mamas (esquerda/direita)
- Glândulas mamárias
- Mamilos
- Placenta
- Endométrio
- Miométrio
- Perimétrio

### SEMPRE Ambos
- **TODAS as Emoções** (sem exceção)
- Todos os Florais de Bach
- Maioria dos Florais Californianos (exceto alguns específicos)
- Todos os Chakras
- Todos os Meridianos
- Órgãos neutros (Coração, Fígado, Rins, Pulmões, Estômago, etc.)
- Vitaminas
- Minerais
- Suplementos
- Alimentos

---

## 🔍 VALIDAÇÕES IMPLEMENTADAS

### Método: `ValidateAll(List<ItemBancoCore> items)`

```csharp
✅ Verifica GUIDs duplicados
✅ Valida género em órgãos reprodutores (Próstata = Masculino, Ovários = Feminino)
✅ Confirma totais exatos:
   - 38 Florais de Bach
   - 103 Florais Californianos
   - 28 Chakras
   - 20 Meridianos
✅ Garante JsonMetadata não-null em todos os itens
✅ Garante FonteOrigem não-null em todos os itens
```

### Exemplo de Uso
```csharp
var items = ItemBancoCoreSeeder.GetAll();
ItemBancoCoreSeeder.ValidateAll(items); // Lança exceção se houver erro
```

---

## 📖 EXEMPLOS DE USO

### 1. Obter Todos os Florais de Bach
```csharp
using var context = new BioDeskDbContext(options);
var floraisBach = await context.ItensBancoCore
    .Where(x => x.Categoria == CategoriaCore.FloraisBach && x.IsActive)
    .ToListAsync();
```

### 2. Buscar Órgãos por Género
```csharp
// Órgãos masculinos
var orgaosMasculinos = await context.ItensBancoCore
    .Where(x => x.Categoria == CategoriaCore.Orgao 
             && x.GeneroAplicavel == "Masculino")
    .ToListAsync();

// Órgãos femininos
var orgaosFemininos = await context.ItensBancoCore
    .Where(x => x.Categoria == CategoriaCore.Orgao 
             && x.GeneroAplicavel == "Feminino")
    .ToListAsync();
```

### 3. Pesquisa Full-Text por Nome
```csharp
var resultado = await context.ItensBancoCore
    .Where(x => x.Nome.Contains("Arnica") && x.IsActive)
    .ToListAsync();
```

### 4. Obter Item com Metadata Desserializada
```csharp
var item = await context.ItensBancoCore.FindAsync(id);
if (item?.JsonMetadata != null)
{
    var metadata = JsonSerializer.Deserialize<Dictionary<string, object>>(item.JsonMetadata);
    // Processar metadata...
}
```

---

## 🛠️ HELPER METHODS

### CreateHomeopatico()
Cria item homeopático com GUID determinístico, fonte padrão e estrutura JSON completa.

### CreateFloralBach()
Cria Floral de Bach seguindo estrutura dos 7 grupos originais de Dr. Edward Bach.

### CreateFloralCaliforniano()
Cria Floral Californiano (FES) com suporte para género específico em alguns florais.

### CreateEmocao()
Cria emoção com **género sempre "Ambos"** e relações MTC/Chakras.

### CreateOrgao()
Cria órgão com **validação crítica de género** (Masculino/Feminino/Ambos).

### CreateChakra()
Cria chakra com toda informação védica (nome sânscrito, mantra, frequência, etc.).

### CreateMeridiano()
Cria meridiano MTC com informação de elemento, horário Qi, pontos principais.

---

## 🔧 INTEGRAÇÃO COM DbContext

### Configuração em `BioDeskDbContext.cs`

```csharp
public DbSet<ItemBancoCore> ItensBancoCore { get; set; } = null!;

// OnModelCreating
modelBuilder.Entity<ItemBancoCore>(entity =>
{
    entity.HasKey(e => e.Id);
    
    // Índices para performance
    entity.HasIndex(e => e.ExternalId).IsUnique();
    entity.HasIndex(e => e.Categoria);
    entity.HasIndex(e => e.Nome);
    entity.HasIndex(e => e.Subcategoria);
    entity.HasIndex(e => e.GeneroAplicavel);
    entity.HasIndex(e => e.IsActive);
});
```

---

## 📝 JSON METADATA - EXEMPLOS

### Homeopatia
```json
{
  "Potencias": ["6CH", "12CH", "30CH", "200CH", "1M"],
  "IndicacoesPrincipais": ["Traumatismos", "Contusões", "Choque"],
  "SintomasChave": ["Sensação de estar pisado", "Medo de ser tocado"],
  "Agravacao": ["Movimento", "Toque"],
  "Melhoria": ["Deitado", "Repouso"],
  "RemediosComplementares": ["Hypericum", "Rhus Tox"],
  "CompatibilidadeGenero": "Ambos"
}
```

### Floral de Bach
```json
{
  "Grupo": "Medo",
  "NumeroOriginal": 1,
  "NomeCientifico": "Helianthemum nummularium",
  "IndicacoesPrincipais": ["Pânico", "Terror", "Pesadelos"],
  "EstadoNegativo": "Pânico paralisante",
  "EstadoPositivo": "Coragem, serenidade",
  "AfirmacoesPositivas": ["Estou em segurança", "Confio na vida"],
  "ComponenteRescueRemedy": true
}
```

### Órgão
```json
{
  "Sistema": "Cardiovascular",
  "Funcoes": ["Bombeamento sanguíneo", "Sede das emoções (MTC)"],
  "PatologiasComuns": ["Insuficiência cardíaca", "Arritmias"],
  "MeridianosMTC": ["Coração (Shou Shao Yin)", "Pericárdio"],
  "ChakraRelacionado": "4º (Cardíaco)",
  "HomeopatiaRelacionada": ["Crataegus", "Cactus Grandiflorus"],
  "EmocaoRelacionada": "Alegria excessiva ou tristeza profunda"
}
```

### Chakra
```json
{
  "Numero": 1,
  "NomeSanscrito": "Muladhara",
  "Localizacao": "Base da coluna (períneo)",
  "Cor": "Vermelho",
  "Elemento": "Terra",
  "MantraBija": "LAM",
  "Frequencia": 256.0,
  "Temas": ["Sobrevivência", "Segurança", "Enraizamento"],
  "OrgaosRelacionados": ["Suprarrenais", "Rins", "Coluna"],
  "CristaisHarmonizadores": ["Jaspe vermelho", "Hematite"],
  "OleosEssenciais": ["Patchouli", "Vetiver"]
}
```

---

## 🚀 PRÓXIMOS PASSOS

### Sprint Imediato
1. ✅ Criar entidades Domain
2. ✅ Configurar DbContext
3. ✅ Implementar estrutura Seeder
4. ✅ Validação completa
5. ⏳ Criar migration EF Core
6. ⏳ Popular categorias restantes

### Sprint Futuro
1. Expandir Homeopatia (3.000 itens)
2. Completar Florais Californianos (103 itens)
3. Expandir Emoções (500 itens)
4. Completar Órgãos (150 itens)
5. Completar Meridianos (20 itens)
6. Implementar Vitaminas (50 itens)
7. Implementar Minerais (80 itens)
8. Implementar Suplementos (300 itens)
9. Implementar Alimentos (1.000 itens)

### Sprint Integração
1. Conectar com `CoreAnaliseService` (Value% Scanning)
2. UI para visualização de itens
3. Filtros por categoria/género
4. Pesquisa full-text
5. Relatórios PDF de análise

---

## 📚 FONTES DE REFERÊNCIA

### Homeopatia
- Boericke Materia Medica (2000)
- Kent's Repertory
- Clarke's Dictionary of Practical Materia Medica
- Pharmacopoeia Homeopathica

### Florais
- Dr. Edward Bach - The Twelve Healers and Other Remedies (1933)
- Flower Essence Society (FES) - California Flower Essences

### MTC e Chakras
- Sistema Védico dos Chakras
- Medicina Tradicional Chinesa (MTC)
- Acupunctura Clássica
- Tantra e Yoga

### Anatomia
- Anatomia Humana (Gray's Anatomy)
- Fisiologia Médica

---

## ⚠️ AVISOS IMPORTANTES

### 🔴 NUNCA ALTERAR
- GUIDs já existentes (quebra referências)
- Género de órgãos reprodutores (integridade dados)
- Estrutura de validação (segurança)

### 🟡 SEMPRE VERIFICAR
- Unicidade de ExternalId antes de adicionar novos itens
- Género correto em órgãos antes de commit
- Validação passa após alterações: `ValidateAll(items)`

### 🟢 BOAS PRÁTICAS
- Usar helpers para criar itens (consistência)
- Preencher JsonMetadata rico (mínimo 3 propriedades)
- Sempre definir FonteOrigem (rastreabilidade)
- Manter IsActive=true para itens válidos

---

## 📧 SUPORTE

Para questões ou expansões deste sistema:
1. Consultar `PLANO_IMPLEMENTACAO_CORE_INFORMACIONAL_14OUT2025.md`
2. Verificar `PROMPT_AGENTE_SEED_DATA_CORE_COMPLETO.md`
3. Revisar validações no método `ValidateAll()`

---

**Última Atualização:** 14 de Outubro de 2025
**Versão:** 1.0
**Status:** 🟢 Estrutura Completa, Pronta para Expansão
