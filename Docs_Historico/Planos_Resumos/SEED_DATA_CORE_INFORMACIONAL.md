# 🧬 Sistema Core Informacional - Seed Data

**Data**: 15 de Outubro de 2025
**Inspiração**: Inergetix CoRe 5.0
**Status**: ✅ Estrutura criada | ⏳ Aguardando seed data completo

---

## 📊 Visão Geral

Sistema de banco de dados de itens terapêuticos para análise de ressonância bioenergética. Permite scanning de ~6.700 itens através de RNG (Random Number Generator) para identificar frequências/substâncias em ressonância com o campo informacional do paciente.

### **Total Planeado**: ~6.700 itens
### **Total Implementado**: ⏳ Em geração (Codex + ChatGPT)

---

## 🗂️ Estrutura de Dados

### **Entidade: ItemBancoCore**

```csharp
public class ItemBancoCore
{
    public int Id { get; set; }                     // Auto-increment
    public Guid ExternalId { get; set; }            // GUID único (SHA256 hash)
    public string Nome { get; set; }                // Ex: "Arnica Montana 30CH"
    public CategoriaCore Categoria { get; set; }    // Enum (14 categorias)
    public string? Subcategoria { get; set; }       // Ex: "Trauma Físico"
    public string? DescricaoBreve { get; set; }     // 50-200 caracteres
    public string? JsonMetadata { get; set; }       // JSON rico (min 3 props)
    public string? FonteOrigem { get; set; }        // Referência bibliográfica
    public string? GeneroAplicavel { get; set; }    // "Masculino"/"Feminino"/"Ambos"
    public bool IsActive { get; set; }              // Disponível para scanning
    public DateTime CreatedAt { get; set; }         // UTC timestamp
}
```

### **Enum: CategoriaCore**

| ID | Categoria | Itens | Status |
|----|-----------|-------|--------|
| 1  | Frequencia | 5.869 | ✅ Já existe (importado Excel) |
| 2  | Homeopatia | ~3.000 | ⏳ Em geração |
| 3  | FloraisBach | 38 | ⏳ Em geração |
| 4  | FloraisCalifornianos | 103 | ⏳ Em geração |
| 5  | Emocao | ~500 | ⏳ Em geração |
| 6  | Orgao | ~150 | ⏳ Em geração |
| 7  | Chakra | 28 | ⏳ Em geração |
| 8  | Meridiano | 20 | ⏳ Em geração |
| 10 | Vitamina | ~50 | 📋 Planeado |
| 11 | Mineral | ~80 | 📋 Planeado |
| 13 | Suplemento | ~300 | 📋 Planeado |
| 14 | Alimento | ~1.000 | 📋 Planeado |

---

## 🎯 Categorias Detalhadas

### **1. Homeopatia (~3.000 itens)**

**Fontes**: Boericke, Kent's Repertory, Clarke's Dictionary

**Subcategorias**:
- Trauma Físico (150)
- Sistema Nervoso (200)
- Digestivo (250)
- Respiratório (200)
- Pele (300)
- Mental/Emocional (250)
- Feminino (300) → `GeneroAplicavel = "Feminino"`
- Masculino (150) → `GeneroAplicavel = "Masculino"`
- Infantil (200)
- Agudos (300)
- Crónicos (400)
- Nosódios (100)
- Sarcódios (100)
- Policrestos (100)

**Exemplo**:
```json
{
  "Nome": "Arnica Montana 30CH",
  "Categoria": "Homeopatia",
  "Subcategoria": "Trauma Físico",
  "GeneroAplicavel": "Ambos",
  "JsonMetadata": {
    "Potencias": ["6CH", "12CH", "30CH", "200CH", "1M"],
    "IndicacoesPrincipais": ["Traumatismos musculares", "Contusões"],
    "SintomasChave": ["Sensação de estar pisado", "Medo de ser tocado"],
    "Agravacao": ["Movimento", "Toque"],
    "Melhoria": ["Deitado com cabeça baixa"],
    "RemediosComplementares": ["Hypericum", "Rhus Tox"]
  }
}
```

---

### **2. Florais de Bach (38 itens + Rescue Remedy)**

**Fonte**: Dr. Edward Bach - Sistema Original

**7 Grupos Emocionais**:
1. **Medo** (5): Rock Rose, Mimulus, Cherry Plum, Aspen, Red Chestnut
2. **Incerteza** (6): Cerato, Scleranthus, Gentian, Gorse, Hornbeam, Wild Oat
3. **Desinteresse** (7): Clematis, Honeysuckle, Wild Rose, Olive, White Chestnut, Mustard, Chestnut Bud
4. **Solidão** (3): Water Violet, Impatiens, Heather
5. **Hipersensibilidade** (4): Agrimony, Centaury, Walnut, Holly
6. **Desespero** (8): Larch, Pine, Elm, Sweet Chestnut, Star of Bethlehem, Willow, Oak, Crab Apple
7. **Preocupação Excessiva** (5): Chicory, Vervain, Vine, Beech, Rock Water

**Especial**: Rescue Remedy (combinação de 5 essências)

**Sempre**: `GeneroAplicavel = "Ambos"`

---

### **3. Florais Californianos (103 itens)**

**Fonte**: Flower Essence Society (FES)

**Subcategorias**:
- Relações & Sexualidade (15)
- Criatividade & Expressão (12)
- Vitalidade & Energia (10)
- Clareza Mental (15)
- Transformação Espiritual (18)
- Questões Femininas (12) → `GeneroAplicavel = "Feminino"`
- Questões Masculinas (8) → `GeneroAplicavel = "Masculino"`
- Crianças (13)

---

### **4. Emoções (~500 itens)**

**Sempre**: `GeneroAplicavel = "Ambos"`

**Categorias**:
- Medo (50): Pânico, Fobia, Ansiedade, Terror
- Raiva (50): Fúria, Ressentimento, Irritabilidade
- Tristeza (50): Depressão, Melancolia, Luto
- Alegria/Amor (50): Euforia, Gratidão, Compaixão
- Vergonha/Culpa (50): Humilhação, Remorso
- Surpresa/Nojo (50)
- Complexas (200): Inveja, Ciúme, Frustração

**Metadata inclui**:
- Órgãos relacionados (MTC)
- Chakras afetados
- Sintomas físicos associados
- Florais/Homeopatia sugeridos
- Afirmações transformadoras

---

### **5. Órgãos & Sistemas (~150 itens)** ⚠️ **GÉNERO CRÍTICO!**

#### **Sistemas Neutros** (`GeneroAplicavel = "Ambos"` - ~100 itens):
- Cardiovascular (15): Coração, Artérias, Veias
- Respiratório (12): Pulmões, Brônquios
- Digestivo (20): Estômago, Fígado, Intestinos
- Nervoso (25): Cérebro, Medula
- Endócrino Neutro (10): Hipófise, Tiróide
- Urinário Neutro (8): Rins, Bexiga
- Músculo-esquelético (10)

#### **Sistema Reprodutor FEMININO** (`GeneroAplicavel = "Feminino"` - ~25 itens):
✅ **OBRIGATÓRIO**: Ovários, Útero, Trompas, Cérvix, Vagina, Vulva, Mamas, Glândulas mamárias

#### **Sistema Reprodutor MASCULINO** (`GeneroAplicavel = "Masculino"` - ~25 itens):
✅ **OBRIGATÓRIO**: Próstata, Testículos, Epidídimo, Pénis, Vesículas seminais

**Regra de Ouro**:
```
❌ NUNCA: Próstata com "Feminino"
❌ NUNCA: Ovários com "Masculino"
✅ SEMPRE: Validar género em órgãos reprodutores!
```

---

### **6. Chakras (28 itens)**

#### **7 Principais**:
1. Muladhara (Raiz) - Vermelho
2. Svadhisthana (Sacral) - Laranja
3. Manipura (Plexo Solar) - Amarelo
4. Anahata (Cardíaco) - Verde
5. Vishuddha (Laríngeo) - Azul
6. Ajna (Terceiro Olho) - Índigo
7. Sahasrara (Coroa) - Violeta

#### **21 Secundários**:
Pés, Joelhos, Palmas, Cotovelos, Ombros, Ouvidos, Olhos, Alta Major, Timo, Baço, etc.

**Metadata inclui**:
- Nome sânscrito
- Localização anatómica
- Cor, Elemento, Mantra Bija
- Frequência (Hz)
- Temas psicológicos
- Órgãos relacionados
- Desequilíbrios físicos/emocionais
- Cristais harmonizadores
- Óleos essenciais

---

### **7. Meridianos (20 itens - MTC)**

#### **12 Principais**:
Pulmão, Intestino Grosso, Estômago, Baço-Pâncreas, Coração, Intestino Delgado, Bexiga, Rim, Pericárdio, Triplo Aquecedor, Vesícula Biliar, Fígado

#### **8 Extraordinários**:
Du Mai, Ren Mai, Chong Mai, Dai Mai, Yang Wei Mai, Yin Wei Mai, Yang Qiao Mai, Yin Qiao Mai

**Metadata inclui**:
- Nome pinyin
- Elemento MTC
- Horário máximo Qi
- Polaridade (Yin/Yang)
- Pontos principais
- Órgão acoplado
- Emoção equilibrada/desequilibrada
- Patologias associadas

---

## 🔐 Validação de Integridade

### **Método: ItemBancoCoreSeeder.ValidateAll()**

Verifica automaticamente:

1. ✅ **Zero GUIDs duplicados** (ExternalId único)
2. ✅ **Género correto em órgãos reprodutores**
   - Próstata/Testículos → "Masculino"
   - Ovários/Útero/Mama → "Feminino"
3. ✅ **Totais esperados por categoria**
   - 38 Florais Bach
   - 28 Chakras
   - 20 Meridianos
4. ✅ **JsonMetadata não-null** (todos os itens)
5. ✅ **FonteOrigem preenchida** (rastreabilidade)

**Execução**:
```csharp
var items = ItemBancoCoreSeeder.GetAll();
ItemBancoCoreSeeder.ValidateAll(items);
// Lança Exception se qualquer validação falhar
```

---

## 🗄️ Índices de Base de Dados

Configurados no `BioDeskDbContext.cs`:

```csharp
// Único (garante integridade)
IX_ItensBancoCore_ExternalId (UNIQUE)

// Performance de queries
IX_ItensBancoCore_Categoria
IX_ItensBancoCore_Nome
IX_ItensBancoCore_Subcategoria
IX_ItensBancoCore_GeneroAplicavel
IX_ItensBancoCore_IsActive

// Composto (filtros combinados)
IX_ItensBancoCore_Categoria_Active_Genero
```

---

## 📖 Fontes Bibliográficas

### **Homeopatia**:
- Boericke, William. *Materia Medica with Repertory* (2000)
- Kent, James Tyler. *Repertory of the Homeopathic Materia Medica* (1877)
- Clarke, John Henry. *Dictionary of Practical Materia Medica* (1900)

### **Florais de Bach**:
- Bach, Edward. *The Twelve Healers and Other Remedies* (1933)

### **Florais Californianos**:
- Flower Essence Society (FES). *Repertory of Flower Essences* (2019)

### **Chakras**:
- Sistema Védico dos Chakras (tradição hindu)
- Judith, Anodea. *Wheels of Life* (1987)

### **Meridianos**:
- Medicina Tradicional Chinesa (MTC)
- Deadman, Peter. *A Manual of Acupuncture* (1998)

---

## 🚀 Uso no Sistema Core

### **1. Scanning de Ressonância** (Value%)
```csharp
var paciente = await _pacienteService.GetByIdAsync(pacienteId);
var seed = GenerateSeed(paciente); // Nome + DataNascimento + Foto

var resultados = await _coreAnaliseService.ScanAsync(
    seed: seed,
    categorias: new[] { CategoriaCore.FloraisBach, CategoriaCore.Orgao },
    genero: paciente.Genero // Filtra automaticamente
);

// Retorna itens com Value% de 0-100 (ordenados por ressonância)
```

### **2. Filtragem por Género**
```csharp
// Paciente Masculino → exclui automaticamente Ovários/Útero
// Paciente Feminino → exclui automaticamente Próstata/Testículos
// "Outro" → inclui apenas itens "Ambos"

var itensAplicaveis = await context.ItensBancoCore
    .Where(x => x.IsActive)
    .Where(x => x.Categoria == CategoriaCore.Orgao)
    .Where(x => x.GeneroAplicavel == "Ambos" ||
                x.GeneroAplicavel == paciente.Genero)
    .ToListAsync();
```

### **3. Transmissão Informacional**
```csharp
// Após identificar itens em ressonância (Value% > 80%)
var transmissao = new TransmissaoInformacional
{
    PacienteId = pacienteId,
    ItemBancoCoreId = item.Id,
    TipoTransmissao = "Local", // ou "Remoto"
    DuracaoMinutos = 15,
    InicioEm = DateTime.UtcNow
};

await _coreTransmissaoService.IniciarAsync(transmissao);
```

---

## 📊 Estatísticas Esperadas (Após Seed Completo)

| Métrica | Valor |
|---------|-------|
| **Total Itens** | ~6.700 |
| **Itens "Ambos"** | ~6.400 (95%) |
| **Itens "Masculino"** | ~150 (2.5%) |
| **Itens "Feminino"** | ~150 (2.5%) |
| **Categorias** | 12 (11 novas + Frequencia) |
| **Fontes Bibliográficas** | 15+ |
| **GUIDs Únicos** | 100% (SHA256 hash) |

---

## ⚠️ Regras Críticas de Implementação

### **NUNCA FAZER**:
1. ❌ Criar itens duplicados (ExternalId único!)
2. ❌ Misturar géneros (Próstata ≠ Feminino!)
3. ❌ Omitir JsonMetadata (obrigatório!)
4. ❌ Usar placeholders ("TODO", "...")
5. ❌ Código incompleto

### **SEMPRE FAZER**:
1. ✅ Validar GUIDs únicos
2. ✅ JsonMetadata rico (min 3 props)
3. ✅ FonteOrigem com referência
4. ✅ DescricaoBreve de 50-200 chars
5. ✅ Compilar sem warnings

---

## 🔄 Próximos Passos

1. ⏳ **Aguardar seed data completo** (Codex + ChatGPT)
2. 📥 **Integrar** `ItemBancoCoreSeeder.cs` no projeto
3. 🏗️ **Criar migration**: `Add-Migration AddItemBancoCore`
4. ▶️ **Aplicar migration**: `Update-Database`
5. ✅ **Validar**: Executar `ValidateAll()`
6. 🧪 **Testar queries** filtradas por género
7. 🔗 **Integrar** com `CoreAnaliseService`
8. 🎨 **UI** para pesquisa e listagem

---

**Status**: ✅ Estrutura pronta | ⏳ Aguardando dados | 🚀 Pronto para integração
