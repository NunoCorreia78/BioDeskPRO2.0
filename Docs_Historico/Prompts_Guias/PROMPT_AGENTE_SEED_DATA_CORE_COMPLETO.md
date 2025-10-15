# 🤖 PROMPT PARA AGENTE DE CODIFICAÇÃO - SEED DATA CORE INFORMACIONAL

**Data**: 14 de Outubro de 2025
**Objetivo**: Gerar seed data completo e validado para sistema Core Informacional
**Total Itens**: ~6.700 registos
**Formato Output**: C# code-behind para `ItemBancoCoreSeeder.cs`

---

## ⚠️ REGRAS CRÍTICAS - LEITURA OBRIGATÓRIA

### 🚫 **NUNCA FAZER**
1. ❌ **NUNCA** criar itens duplicados (validar por `ExternalId` GUID único)
2. ❌ **NUNCA** omitir categorias completas (se iniciar uma categoria, COMPLETÁ-LA)
3. ❌ **NUNCA** misturar géneros incorretamente:
   - Próstata/Testículos/Pénis → APENAS `GeneroAplicavel = "Masculino"`
   - Ovários/Útero/Vagina/Mama → APENAS `GeneroAplicavel = "Feminino"`
   - Órgãos neutros (Fígado, Rim, Coração) → `GeneroAplicavel = "Ambos"`
4. ❌ **NUNCA** usar placeholder text tipo "TODO", "...", "etc"
5. ❌ **NUNCA** gerar código incompleto ou com comentários "continuar aqui"

### ✅ **SEMPRE FAZER**
1. ✅ **SEMPRE** validar que todos os GUIDs são únicos (verificação automática)
2. ✅ **SEMPRE** incluir `JsonMetadata` rico (mínimo 3 propriedades)
3. ✅ **SEMPRE** especificar `FonteOrigem` com referência válida
4. ✅ **SEMPRE** incluir `DescricaoBreve` de 50-200 caracteres
5. ✅ **SEMPRE** adicionar `Subcategoria` específica
6. ✅ **SEMPRE** compilar sem warnings (nullable correctos, strings não vazias)

---

## 📊 CONTEXTO DO SISTEMA

### **Entidade Paciente (Dados Disponíveis)**
```csharp
public class Paciente
{
    public int Id { get; set; }
    public string NomeCompleto { get; set; }        // ✅ Usado para seed RNG
    public DateTime? DataNascimento { get; set; }   // ✅ Usado para seed RNG
    public string Genero { get; set; }              // ✅ "Masculino"/"Feminino"/"Outro"
    public int? Idade { get; }                      // Calculado automaticamente
    public string? FotoPath { get; set; }           // ✅ Hash usado para seed (se existir)
}
```

### **Entidade ItemBancoCore (Alvo a Popular)**
```csharp
public class ItemBancoCore
{
    public int Id { get; set; }                     // Auto-increment (não preencher)
    public Guid ExternalId { get; set; }            // ✅ GUID único (gerar novo para cada)
    public string Nome { get; set; }                // ✅ Nome legível (ex: "Arnica Montana 30CH")
    public CategoriaCore Categoria { get; set; }    // ✅ Enum (ver lista abaixo)
    public string? Subcategoria { get; set; }       // ✅ Especificar (ex: "Trauma físico")
    public string? DescricaoBreve { get; set; }     // ✅ 50-200 chars (ex: "Para traumatismos...")
    public string? JsonMetadata { get; set; }       // ✅ JSON rico (mínimo 3 props)
    public string? FonteOrigem { get; set; }        // ✅ Referência (ex: "Materia Medica Boericke")
    public string? GeneroAplicavel { get; set; }    // ✅ "Masculino"/"Feminino"/"Ambos"
    public bool IsActive { get; set; } = true;      // ✅ Sempre true
    public DateTime CreatedAt { get; set; }         // ✅ DateTime.UtcNow
}
```

### **Enum CategoriaCore (14 categorias)**
```csharp
public enum CategoriaCore
{
    Frequencia = 1,           // ✅ JÁ EXISTE (5.869 itens) - NÃO RECRIAR!
    Homeopatia = 2,           // 🔴 CRIAR ~3.000 itens
    FloraisBach = 3,          // 🔴 CRIAR 38 itens (completo)
    FloraisCalifornianos = 4, // 🔴 CRIAR 103 itens (completo)
    Emocao = 5,               // 🔴 CRIAR ~500 itens
    Orgao = 6,                // 🔴 CRIAR ~150 itens (+ género!)
    Chakra = 7,               // 🔴 CRIAR 7 principais + 21 secundários
    Meridiano = 8,            // 🔴 CRIAR 12 principais + 8 extraordinários
    Vitamina = 10,            // 🔴 CRIAR ~50 itens
    Mineral = 11,             // 🔴 CRIAR ~80 itens
    Suplemento = 13,          // 🔴 CRIAR ~300 itens
    Alimento = 14             // 🔴 CRIAR ~1.000 itens (terapêuticos)
}
```

---

## 🎯 ESPECIFICAÇÃO DETALHADA POR CATEGORIA

### **1. HOMEOPATIA (~3.000 itens)**

#### **Fontes de Referência Obrigatórias**:
- Materia Medica de Boericke
- Kent's Repertory
- Pharmacopoeia Homeopathica
- Clarke's Dictionary

#### **Estrutura Completa**:
```csharp
new ItemBancoCore
{
    ExternalId = Guid.Parse("HOM-00001-ARNICA"),  // Padrão: HOM-XXXXX-NOME
    Nome = "Arnica Montana 30CH",
    Categoria = CategoriaCore.Homeopatia,
    Subcategoria = "Trauma físico",              // Trauma/Inflamação/Digestivo/Mental/etc
    DescricaoBreve = "Traumatismos, contusões, choque pós-cirúrgico. Primeira escolha para lesões físicas com equimose.",
    JsonMetadata = JsonSerializer.Serialize(new
    {
        Potencias = new[] { "6CH", "12CH", "30CH", "200CH", "1M" },
        IndicacoesPrincipais = new[]
        {
            "Traumatismos musculares",
            "Contusões com equimose",
            "Choque pós-cirúrgico",
            "Fadiga por esforço excessivo"
        },
        SintomasChave = new[]
        {
            "Sensação de estar pisado",
            "Medo de ser tocado",
            "Cama parece muito dura",
            "Diz que está bem quando está muito doente"
        },
        Agravacao = new[] { "Movimento", "Toque", "Repouso prolongado" },
        Melhoria = new[] { "Deitado com cabeça baixa", "Repouso" },
        RemediosComplementares = new[] { "Hypericum", "Rhus Tox", "Ruta" },
        CompatibilidadeGenero = "Ambos"
    }),
    FonteOrigem = "Boericke Materia Medica (2000), Kent's Repertory",
    GeneroAplicavel = "Ambos",
    IsActive = true,
    CreatedAt = DateTime.UtcNow
}
```

#### **Categorias Obrigatórias (Homeopatia)**:
1. **Trauma Físico** (150 itens): Arnica, Hypericum, Ruta, Symphytum, etc.
2. **Sistema Nervoso** (200 itens): Ignatia, Kali Phos, Mag Phos, etc.
3. **Digestivo** (250 itens): Nux Vomica, Carbo Veg, Lycopodium, etc.
4. **Respiratório** (200 itens): Bryonia, Phosphorus, Antimonium Tart, etc.
5. **Pele** (300 itens): Sulphur, Graphites, Petroleum, etc.
6. **Mental/Emocional** (250 itens): Aurum Met, Sepia, Natrum Mur, etc.
7. **Feminino** (300 itens): Pulsatilla, Sepia, Caulophyllum, etc. → `GeneroAplicavel = "Feminino"`
8. **Masculino** (150 itens): Sabal Serrulata, Selenium, etc. → `GeneroAplicavel = "Masculino"`
9. **Infantil** (200 itens): Chamomilla, Calcarea Carb, etc.
10. **Agudos** (300 itens): Aconitum, Belladonna, etc.
11. **Crónicos** (400 itens): Tuberculinum, Medorrhinum, etc.
12. **Nosódios** (100 itens): Psorinum, Syphilinum, etc.
13. **Sarcódios** (100 itens): Thyroidinum, Pancreatin, etc.
14. **Policrestos** (100 itens): Top 100 mais prescritos

**TOTAL: 3.000 itens**

---

### **2. FLORAIS DE BACH (38 itens - COMPLETO)**

#### **Fonte**: Dr. Edward Bach - Sistema Original

#### **TODOS os 38 Florais (Obrigatório incluir TODOS)**:
```csharp
// Grupo 1: Medo (5 florais)
1. Rock Rose - Pânico, terror
2. Mimulus - Medo de coisas conhecidas (fobias)
3. Cherry Plum - Medo de perder controlo
4. Aspen - Ansiedade vaga, pressentimentos
5. Red Chestnut - Medo excessivo pelos outros

// Grupo 2: Incerteza (6 florais)
6. Cerato - Dúvida, falta confiança no próprio julgamento
7. Scleranthus - Indecisão entre duas opções
8. Gentian - Desânimo após contratempo
9. Gorse - Desesperança extrema
10. Hornbeam - Cansaço mental, procrastinação
11. Wild Oat - Incerteza sobre direção de vida

// Grupo 3: Desinteresse (7 florais)
12. Clematis - Sonhador, desatenção
13. Honeysuckle - Vive no passado
14. Wild Rose - Resignação, apatia
15. Olive - Exaustão total (física/mental)
16. White Chestnut - Pensamentos obsessivos
17. Mustard - Tristeza profunda sem causa
18. Chestnut Bud - Repete mesmos erros

// Grupo 4: Solidão (3 florais)
19. Water Violet - Orgulho, isolamento
20. Impatiens - Impaciência, irritabilidade
21. Heather - Centrado em si, tagarela

// Grupo 5: Hipersensibilidade (4 florais)
22. Agrimony - Esconde sofrimento por trás de alegria
23. Centaury - Fraqueza de vontade, submissão
24. Walnut - Proteção em mudanças
25. Holly - Raiva, inveja, ciúme

// Grupo 6: Desespero (8 florais)
26. Larch - Falta de confiança, inferioridade
27. Pine - Culpa, auto-recriminação
28. Elm - Sobrecarregado por responsabilidades
29. Sweet Chestnut - Angústia extrema
30. Star of Bethlehem - Trauma, choque
31. Willow - Ressentimento, autocomiseração
32. Oak - Lutador exausto que não desiste
33. Crab Apple - Limpeza física/mental

// Grupo 7: Preocupação excessiva (5 florais)
34. Chicory - Amor possessivo
35. Vervain - Entusiasmo excessivo, tensão
36. Vine - Dominador, inflexível
37. Beech - Intolerância, crítica
38. Rock Water - Auto-repressão, rigidez

// ESPECIAL: Rescue Remedy (combinação)
39. Rescue Remedy - Emergências (Star of Bethlehem + Rock Rose + Impatiens + Cherry Plum + Clematis)
```

#### **Template JSON Metadata (Florais Bach)**:
```csharp
JsonMetadata = JsonSerializer.Serialize(new
{
    Grupo = "Medo",  // Um dos 7 grupos
    EssenciaOriginal = "Rock Rose",
    IndicacoesPrincipais = new[] { "Pânico", "Terror", "Pesadelos" },
    AfirmacoesPositivas = new[] { "Estou em segurança", "Confio na vida" },
    CombinacoesSugeridas = new[] { "Star of Bethlehem", "Cherry Plum" },
    ContraindicacoesMedicas = "Nenhuma",
    CompatibilidadeGenero = "Ambos"
})
```

---

### **3. FLORAIS CALIFORNIANOS (103 itens - COMPLETO)**

#### **Fonte**: Flower Essence Society (FES)

#### **Categorias Obrigatórias**:
1. **Relações & Sexualidade** (15 itens): Bleeding Heart, Sticky Monkeyflower, etc.
2. **Criatividade & Expressão** (12 itens): Iris, Larch, etc.
3. **Vitalidade & Energia** (10 itens): Hornbeam, Morning Glory, etc.
4. **Clareza Mental** (15 itens): Shasta Daisy, Madia, etc.
5. **Transformação Espiritual** (18 itens): Angelica, Saint John's Wort, etc.
6. **Questões Femininas** (12 itens): Pomegranate, Evening Primrose, etc. → `GeneroAplicavel = "Feminino"`
7. **Questões Masculinas** (8 itens): Mountain Pride, Sunflower, etc. → `GeneroAplicavel = "Masculino"`
8. **Crianças** (13 itens): Baby Blue Eyes, Mariposa Lily, etc.

**TOTAL: 103 itens** (sistema completo FES)

---

### **4. EMOÇÕES (~500 itens)**

#### **Estrutura de Categorização**:
1. **Medo** (50 itens): Pânico, Fobia, Ansiedade, Terror, etc.
2. **Raiva** (50 itens): Fúria, Ressentimento, Irritabilidade, Ódio, etc.
3. **Tristeza** (50 itens): Depressão, Melancolia, Luto, Desespero, etc.
4. **Alegria/Amor** (50 itens): Euforia, Gratidão, Compaixão, etc.
5. **Vergonha/Culpa** (50 itens): Humilhação, Remorso, etc.
6. **Surpresa/Nojo** (50 itens)
7. **Complexas** (200 itens): Inveja, Ciúme, Frustração, Confusão, etc.

#### **Template JSON Metadata (Emoções)**:
```csharp
JsonMetadata = JsonSerializer.Serialize(new
{
    EmocaoPrimaria = "Raiva",
    Intensidade = "Alta",  // Baixa/Média/Alta/Extrema
    OrgaosRelacionadosMTC = new[] { "Fígado", "Vesícula Biliar" },
    ChakrasAfetados = new[] { "3º (Plexo Solar)", "4º (Cardíaco)" },
    SintomasFisicos = new[]
    {
        "Tensão muscular no pescoço",
        "Dores de cabeça tensionais",
        "Bruxismo noturno",
        "Gastrite"
    },
    FloraisSugeridos = new[] { "Holly", "Willow", "Vervain" },
    HomeopatiaSugerida = new[] { "Nux Vomica", "Chamomilla", "Staphysagria" },
    AfirmacoesTransformadoras = new[]
    {
        "Liberto a raiva de forma saudável",
        "Perdoo-me e perdoo os outros",
        "Escolho paz interior"
    }
})
```

**⚠️ IMPORTANTE**: Emoções são SEMPRE `GeneroAplicavel = "Ambos"`

---

### **5. ÓRGÃOS & SISTEMAS (~150 itens) - ATENÇÃO AO GÉNERO!**

#### **Estrutura de Categorização**:

##### **A) Sistemas Neutros** (`GeneroAplicavel = "Ambos"` - ~100 itens)
1. **Cardiovascular** (15): Coração, Artérias, Veias, Pericárdio, etc.
2. **Respiratório** (12): Pulmões, Brônquios, Traqueia, etc.
3. **Digestivo** (20): Estômago, Fígado, Vesícula, Intestinos, etc.
4. **Nervoso** (25): Cérebro, Medula, Nervos, etc.
5. **Endócrino Neutro** (10): Hipófise, Tiróide, Suprarrenais, etc.
6. **Urinário Neutro** (8): Rins, Bexiga, Ureteres
7. **Músculo-esquelético** (10): Músculos, Ossos, Articulações

##### **B) Sistema Reprodutor FEMININO** (`GeneroAplicavel = "Feminino"` - ~25 itens)
```csharp
// ✅ CORRETO - Género explícito
new ItemBancoCore
{
    Nome = "Ovários",
    Categoria = CategoriaCore.Orgao,
    Subcategoria = "Sistema Reprodutor Feminino",
    GeneroAplicavel = "Feminino",  // ⚠️ OBRIGATÓRIO!
    JsonMetadata = JsonSerializer.Serialize(new
    {
        Funcoes = new[] { "Produção de óvulos", "Síntese hormonal (estrogénio, progesterona)" },
        PatologiasComuns = new[] { "Síndrome dos ovários policísticos", "Quistos", "Endometriose" },
        MeridianosMTC = new[] { "Fígado", "Rim", "Vaso Governador" },
        HomeopatiaRelacionada = new[] { "Apis Mellifica", "Lachesis", "Sepia" }
    })
}
```

**Lista Completa Feminina** (25 itens):
1. Ovários (2 itens: esquerdo + direito)
2. Útero
3. Trompas de Falópio (2)
4. Cérvix
5. Vagina
6. Vulva
7. Clitóris
8. Glândulas de Bartholin (2)
9. Mamas (2 itens: esquerda + direita)
10. Glândulas mamárias
11. Mamilos
12. Placenta (durante gravidez)
13. Endométrio
14. Miométrio
15. Perimétrio

##### **C) Sistema Reprodutor MASCULINO** (`GeneroAplicavel = "Masculino"` - ~25 itens)
```csharp
// ✅ CORRETO - Género explícito
new ItemBancoCore
{
    Nome = "Próstata",
    Categoria = CategoriaCore.Orgao,
    Subcategoria = "Sistema Reprodutor Masculino",
    GeneroAplicavel = "Masculino",  // ⚠️ OBRIGATÓRIO!
    JsonMetadata = JsonSerializer.Serialize(new
    {
        Funcoes = new[] { "Produção de fluido seminal", "Controlo de micção" },
        PatologiasComuns = new[] { "Hiperplasia benigna", "Prostatite", "Adenocarcinoma" },
        MeridianosMTC = new[] { "Rim", "Fígado", "Bexiga" },
        HomeopatiaRelacionada = new[] { "Sabal Serrulata", "Conium", "Selenium" }
    })
}
```

**Lista Completa Masculina** (25 itens):
1. Próstata
2. Testículos (2 itens: esquerdo + direito)
3. Epidídimo (2)
4. Ductos deferentes (2)
5. Vesículas seminais (2)
6. Pénis
7. Glande
8. Prepúcio
9. Uretra masculina
10. Glândulas de Cowper (2)
11. Corpo cavernoso (2)
12. Corpo esponjoso
13. Escroto

---

### **6. CHAKRAS (28 itens - Sistema Completo)**

#### **7 Principais** (obrigatórios):
```csharp
new ItemBancoCore
{
    ExternalId = Guid.Parse("CHK-00001-RAIZ"),
    Nome = "Chakra Raiz (Muladhara)",
    Categoria = CategoriaCore.Chakra,
    Subcategoria = "Principal",
    DescricaoBreve = "Localização: base da coluna. Elemento: Terra. Cor: Vermelho. Tema: Sobrevivência, segurança, enraizamento.",
    JsonMetadata = JsonSerializer.Serialize(new
    {
        Numero = 1,
        NomeSanscrito = "Muladhara",
        Localizacao = "Base da coluna (períneo)",
        Cor = "Vermelho",
        Elemento = "Terra",
        MantraBija = "LAM",
        Frequencia = 256.0,  // Hz
        Temas = new[] { "Sobrevivência", "Segurança", "Enraizamento", "Instintos básicos" },
        OrgaosRelacionados = new[] { "Suprarrenais", "Rins", "Coluna vertebral", "Ossos" },
        DesequilibriosFisicos = new[] { "Dores lombares", "Problemas intestinais", "Fadiga crónica" },
        DesequilibriosEmocionais = new[] { "Insegurança", "Medo de mudanças", "Materialismo excessivo" },
        CristaisHarmonizadores = new[] { "Jaspe vermelho", "Hematite", "Turmalina negra" },
        OleosEssenciais = new[] { "Patchouli", "Vetiver", "Cedro" }
    }),
    FonteOrigem = "Sistema Védico dos Chakras",
    GeneroAplicavel = "Ambos",
    IsActive = true,
    CreatedAt = DateTime.UtcNow
}
```

**Lista Completa**:
1. Muladhara (Raiz) - Vermelho
2. Svadhisthana (Sacral) - Laranja
3. Manipura (Plexo Solar) - Amarelo
4. Anahata (Cardíaco) - Verde
5. Vishuddha (Laríngeo) - Azul
6. Ajna (Terceiro Olho) - Índigo
7. Sahasrara (Coroa) - Violeta/Branco

#### **21 Chakras Secundários** (complementares):
8. Pés (2)
9. Joelhos (2)
10. Palmas das mãos (2)
11. Cotovelos (2)
12. Ombros (2)
13. Ouvidos (2)
14. Olhos (2)
15. Alta Major (nuca)
16. Timo (entre cardíaco e laríngeo)
17. Baço
18. Lunar (lado esquerdo do plexo solar)
19. Solar (lado direito do plexo solar)
20-28. Mais 9 chakras menores

**TOTAL: 28 itens**

---

### **7. MERIDIANOS (20 itens - MTC Completo)**

#### **12 Principais**:
1. Pulmão (Shou Tai Yin)
2. Intestino Grosso (Shou Yang Ming)
3. Estômago (Zu Yang Ming)
4. Baço-Pâncreas (Zu Tai Yin)
5. Coração (Shou Shao Yin)
6. Intestino Delgado (Shou Tai Yang)
7. Bexiga (Zu Tai Yang)
8. Rim (Zu Shao Yin)
9. Pericárdio (Shou Jue Yin)
10. Triplo Aquecedor (Shou Shao Yang)
11. Vesícula Biliar (Zu Shao Yang)
12. Fígado (Zu Jue Yin)

#### **8 Extraordinários**:
13. Vaso Governador (Du Mai)
14. Vaso Concepção (Ren Mai)
15. Chong Mai
16. Dai Mai
17. Yang Wei Mai
18. Yin Wei Mai
19. Yang Qiao Mai
20. Yin Qiao Mai

#### **Template JSON Metadata (Meridianos)**:
```csharp
JsonMetadata = JsonSerializer.Serialize(new
{
    NomePinyin = "Shou Tai Yin",
    ElementoMTC = "Metal",
    HorarioMaximoQi = "03h-05h",
    Polaridade = "Yin",
    PontosPrincipais = new[] { "P1 (Zhongfu)", "P7 (Lieque)", "P9 (Taiyuan)" },
    OrgaoAcoplado = "Intestino Grosso",
    EmocaoEquilibrada = "Coragem, integridade",
    EmocaoDesequilibrada = "Tristeza, melancolia",
    PatologiasAssociadas = new[] { "Asma", "Rinite", "Problemas de pele" }
})
```

---

### **8. VITAMINAS (50 itens - Completo)**

**Lista Completa**:
- Vitamina A (Retinol)
- Vitaminas B (B1-B12 - 12 itens)
- Vitamina C (Ácido Ascórbico)
- Vitamina D (D2, D3 - 2 itens)
- Vitamina E (Tocoferóis - 4 tipos)
- Vitamina K (K1, K2 - 2 itens)
- Vitaminas lipossolúveis vs hidrossolúveis
- Formas ativas (ex: Metilcobalamina vs Cianocobalamina)

#### **Template JSON Metadata (Vitaminas)**:
```csharp
JsonMetadata = JsonSerializer.Serialize(new
{
    NomeQuimico = "Ácido ascórbico",
    Tipo = "Hidrossolúvel",
    FuncoesPrincipais = new[] { "Antioxidante", "Síntese de colagénio", "Imunidade" },
    DeficienciaSintomas = new[] { "Escorbuto", "Fadiga", "Gengivas sangrantes" },
    FontesAlimentares = new[] { "Laranja", "Kiwi", "Pimentão", "Acerola" },
    DoseRecomendadaDiaria = "75-90 mg",
    ToxicidadePossivel = "Rara (diarreia acima de 2g/dia)"
})
```

---

### **9. MINERAIS (80 itens)**

**Categorias**:
1. **Macrominerais** (7): Cálcio, Magnésio, Potássio, Sódio, Fósforo, Enxofre, Cloro
2. **Microminerais** (15): Ferro, Zinco, Cobre, Manganês, Iodo, Selénio, etc.
3. **Oligoelementos** (58): Boro, Crómio, Molibdénio, Silício, etc.

---

### **10. SUPLEMENTOS (~300 itens)**



**Categorias**:
1. **Probióticos** (50)
2. **Ácidos Gordos** (30): Omega-3, Omega-6, CLA, etc.
3. **Aminoácidos** (50): L-Glutamina, L-Carnitina, etc.
4. **Enzimas Digestivas** (20)
5. **Antioxidantes** (40): CoQ10, NAC, Glutationa, etc.
6. **Adaptógenos** (30): Ashwagandha, Rhodiola, etc.
7. **Outros** (80)

---

### **11. ALIMENTOS TERAPÊUTICOS (~1.000 itens)**

**Categorias**:
1. **Frutas** (150)
2. **Vegetais** (200)
3. **Ervas/Especiarias** (150)
4. **Sementes/Nozes** (100)
5. **Cereais/Leguminosas** (150)
6. **Proteínas** (100)
7. **Superalimentos** (150)

#### **Template JSON Metadata (Alimentos)**:
```csharp
JsonMetadata = JsonSerializer.Serialize(new
{
    NomeCientifico = "Curcuma longa",
    PartesUsadas = new[] { "Rizoma (raiz)" },
    PropriedadesTerapeuticas = new[] { "Anti-inflamatório", "Antioxidante", "Hepatoprotetor" },
    IndicacoesPrincipais = new[] { "Artrite", "Problemas digestivos", "Prevenção cancro" },
    DosagemSugerida = "500-1000mg curcumina/dia",
    Contraindicacoes = new[] { "Gravidez (altas doses)", "Pedras biliares" },
    ElementoMTC = "Terra",
    OrgaosAlvo = new[] { "Fígado", "Estômago", "Baço" }
})
```

---

## 🔧 ESTRUTURA DE OUTPUT ESPERADA

### **Ficheiro Único: `ItemBancoCoreSeeder.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Text.Json;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.SeedData;

/// <summary>
/// Seed data completo para sistema Core Informacional
/// TOTAL: ~6.700 itens (11 categorias)
/// Gerado automaticamente em: 14/10/2025
/// </summary>
public static class ItemBancoCoreSeeder
{
    /// <summary>
    /// Método principal que retorna TODOS os itens
    /// </summary>
    public static List<ItemBancoCore> GetAll()
    {
        var items = new List<ItemBancoCore>();

        // ⚠️ NÃO incluir Frequências (já existem 5.869)
        // items.AddRange(GetFrequencias());  // SKIP!

        items.AddRange(GetHomeopatia());              // 3.000 itens
        items.AddRange(GetFloraisBach());             // 38 itens
        items.AddRange(GetFloraisCalifornianos());    // 103 itens
        items.AddRange(GetEmocoes());                 // 500 itens
        items.AddRange(GetOrgaos());                  // 150 itens
        items.AddRange(GetChakras());                 // 28 itens
        items.AddRange(GetMeridianos());              // 20 itens
        items.AddRange(GetVitaminas());               // 50 itens
        items.AddRange(GetMinerais());                // 80 itens
        items.AddRange(GetSuplementos());             // 300 itens
        items.AddRange(GetAlimentos());               // 1.000 itens

        return items;
    }

    // ========================================================================
    // CATEGORIA 1: HOMEOPATIA (3.000 itens)
    // ========================================================================
    private static List<ItemBancoCore> GetHomeopatia()
    {
        return new List<ItemBancoCore>
        {
            // Trauma Físico (150 itens)
            new()
            {
                ExternalId = Guid.Parse("00000001-0000-0000-0000-000000000001"),
                Nome = "Arnica Montana 30CH",
                Categoria = CategoriaCore.Homeopatia,
                Subcategoria = "Trauma Físico",
                DescricaoBreve = "Traumatismos, contusões, choque pós-cirúrgico. Primeira escolha para lesões físicas com equimose.",
                JsonMetadata = JsonSerializer.Serialize(new
                {
                    Potencias = new[] { "6CH", "12CH", "30CH", "200CH", "1M" },
                    IndicacoesPrincipais = new[]
                    {
                        "Traumatismos musculares",
                        "Contusões com equimose",
                        "Choque pós-cirúrgico",
                        "Fadiga por esforço excessivo"
                    },
                    SintomasChave = new[]
                    {
                        "Sensação de estar pisado",
                        "Medo de ser tocado",
                        "Cama parece muito dura",
                        "Diz que está bem quando está muito doente"
                    },
                    Agravacao = new[] { "Movimento", "Toque", "Repouso prolongado" },
                    Melhoria = new[] { "Deitado com cabeça baixa", "Repouso" },
                    RemediosComplementares = new[] { "Hypericum", "Rhus Tox", "Ruta" },
                    CompatibilidadeGenero = "Ambos"
                }),
                FonteOrigem = "Boericke Materia Medica (2000), Kent's Repertory",
                GeneroAplicavel = "Ambos",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            },

            // ⚠️ CONTINUAR com os restantes 2.999 itens...
            // NÃO usar "...", "TODO", "etc" - GERAR TODOS!
        };
    }

    // ========================================================================
    // CATEGORIA 2: FLORAIS DE BACH (38 itens - COMPLETO)
    // ========================================================================
    private static List<ItemBancoCore> GetFloraisBach()
    {
        return new List<ItemBancoCore>
        {
            // Grupo 1: Medo (5 florais)
            new()
            {
                ExternalId = Guid.Parse("10000001-0000-0000-0000-000000000001"),
                Nome = "Rock Rose",
                Categoria = CategoriaCore.FloraisBach,
                Subcategoria = "Medo",
                DescricaoBreve = "Para pânico, terror extremo, pesadelos. Primeira escolha em situações de emergência psicológica.",
                JsonMetadata = JsonSerializer.Serialize(new
                {
                    Grupo = "Medo",
                    NumeroOriginal = 1,
                    NomeCientifico = "Helianthemum nummularium",
                    IndicacoesPrincipais = new[] { "Pânico", "Terror", "Pesadelos", "Acidentes" },
                    AfirmacoesPositivas = new[] { "Estou em segurança", "Confio na vida", "Mantenho-me calmo perante o desconhecido" },
                    CombinacoesSugeridas = new[] { "Star of Bethlehem", "Cherry Plum", "Mimulus" },
                    ComponenteRescueRemedy = true
                }),
                FonteOrigem = "Dr. Edward Bach - The Twelve Healers (1933)",
                GeneroAplicavel = "Ambos",
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            },

            // ⚠️ INCLUIR TODOS OS 38 FLORAIS - SEM EXCEÇÃO!
        };
    }

    // ========================================================================
    // [... CONTINUAR com todas as outras categorias ...]
    // ========================================================================
}
```

---

## ✅ CHECKLIST DE VALIDAÇÃO FINAL

Antes de submeter o código, VERIFICAR:

### **1. Completude**
- [ ] Todas as 11 categorias implementadas (exceto Frequencia)
- [ ] Totais corretos por categoria (ex: exatamente 38 Florais Bach)
- [ ] Zero placeholders ("TODO", "...", "etc")

### **2. Unicidade**
- [ ] Todos os `ExternalId` são GUID únicos (verificar duplicados)
- [ ] Nomes únicos dentro de cada categoria
- [ ] Script de validação executado e passou

### **3. Género**
- [ ] Próstata/Testículos → `GeneroAplicavel = "Masculino"` ✅
- [ ] Ovários/Útero/Mama → `GeneroAplicavel = "Feminino"` ✅
- [ ] Órgãos neutros → `GeneroAplicavel = "Ambos"` ✅
- [ ] Emoções → SEMPRE `"Ambos"` ✅

### **4. JSON Metadata**
- [ ] Todos os itens têm JsonMetadata não-null
- [ ] Mínimo 3 propriedades por JSON
- [ ] JSON válido (sem erros de sintaxe)

### **5. Compilação**
- [ ] Código compila sem erros ✅
- [ ] Zero warnings de nullable ✅
- [ ] Strings não vazias onde obrigatório ✅

### **6. Fontes**
- [ ] Todas as `FonteOrigem` preenchidas
- [ ] Referências válidas e verificáveis

---

## 🎯 EXEMPLO DE VALIDAÇÃO AUTOMÁTICA

```csharp
public static class ItemBancoCoreValidator
{
    public static void ValidateAll(List<ItemBancoCore> items)
    {
        // 1. Verificar duplicados de GUID
        var duplicates = items
            .GroupBy(x => x.ExternalId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key);

        if (duplicates.Any())
            throw new Exception($"GUIDs duplicados: {string.Join(", ", duplicates)}");

        // 2. Verificar género em órgãos reprodutores
        var prostata = items.FirstOrDefault(x => x.Nome.Contains("Próstata"));
        if (prostata?.GeneroAplicavel != "Masculino")
            throw new Exception("Próstata deve ter GeneroAplicavel='Masculino'");

        var ovarios = items.FirstOrDefault(x => x.Nome.Contains("Ovário"));
        if (ovarios?.GeneroAplicavel != "Feminino")
            throw new Exception("Ovários devem ter GeneroAplicavel='Feminino'");

        // 3. Verificar totais por categoria
        var floraisBach = items.Count(x => x.Categoria == CategoriaCore.FloraisBach);
        if (floraisBach != 38)
            throw new Exception($"Esperados 38 Florais Bach, encontrados {floraisBach}");

        // 4. Verificar JsonMetadata não-null
        var semJson = items.Where(x => string.IsNullOrEmpty(x.JsonMetadata)).ToList();
        if (semJson.Any())
            throw new Exception($"{semJson.Count} itens sem JsonMetadata");

        Console.WriteLine("✅ VALIDAÇÃO COMPLETA - SEM ERROS!");
    }
}
```

---

## 📝 NOTAS FINAIS PARA O AGENTE

1. **PRIORIDADE MÁXIMA**: Completude > Velocidade
2. **ZERO TOLERÂNCIA**: Duplicados, omissões, erros de género
3. **FORMATO**: C# code-behind puro (sem SQL, sem CSV)
4. **TAMANHO**: Ficheiro único ~15k-25k linhas (aceitável)
5. **TEMPO ESTIMADO**: 3-4 horas de geração assistida por IA
6. **VALIDAÇÃO**: Executar script de validação antes de submeter

---

## � FORMATO DE ENTREGA (OBRIGATÓRIO)

### **Output Esperado**: Ficheiro ÚNICO em bloco de código markdown

```markdown
### ItemBancoCoreSeeder.cs - PARTE 1/1

```csharp
using System;
using System.Collections.Generic;
using System.Text.Json;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.SeedData;

public static class ItemBancoCoreSeeder
{
    // ... CÓDIGO COMPLETO AQUI ...
}
```
```

### **⚠️ INSTRUÇÕES CRÍTICAS DE ENTREGA**:

1. **Ficheiro ÚNICO**: Não dividir em múltiplos ficheiros ou mensagens
2. **Formato Markdown**: Usar bloco ```csharp ... ``` para facilitar copy-paste
3. **Código Completo**: NUNCA usar "... continuar aqui" ou "restantes X itens"
4. **Validação Inline**: Incluir método `ValidateAll()` no final do ficheiro
5. **Sem Explicações**: Apenas o código C# puro (comentários inline são OK)

### **Ordem de Prioridade (se houver timeout)**:

**PRIORIDADE ALTA** (Implementar SEMPRE):
1. ✅ Florais de Bach (38 itens) - Sistema fechado oficial
2. ✅ Chakras (28 itens) - Sistema completo
3. ✅ Meridianos (20 itens) - MTC tradicional
4. ✅ Órgãos (150 itens) - **CRÍTICO: Validação de género!**

**PRIORIDADE MÉDIA** (Implementar se possível):
5. ⚡ Vitaminas (50 itens)
6. ⚡ Minerais (80 itens)
7. ⚡ Florais Californianos (103 itens)
8. ⚡ Emoções (500 itens)

**PRIORIDADE BAIXA** (Pode ser incremental):
9. 🔄 Suplementos (300 itens)
10. 🔄 Alimentos (1.000 itens)
11. 🔄 Homeopatia (3.000 itens) - Maior categoria

**⚠️ ATENÇÃO**: Se não conseguires gerar TUDO, gera pelo menos **Prioridade Alta** (236 itens) completos e compiláveis. Posso adicionar o resto depois.

---

## 🔍 MÉTODO DE VALIDAÇÃO AUTOMÁTICA (INCLUIR NO CÓDIGO)

**Adicionar ao final de `ItemBancoCoreSeeder.cs`**:

```csharp
    /// <summary>
    /// Valida integridade de todos os itens gerados
    /// EXECUTAR antes de usar em produção!
    /// </summary>
    public static void ValidateAll()
    {
        var items = GetAll();
        var errors = new List<string>();

        // 1. Verificar total esperado
        Console.WriteLine($"Total itens gerados: {items.Count}");

        // 2. Verificar duplicados de GUID
        var duplicateGuids = items
            .GroupBy(x => x.ExternalId)
            .Where(g => g.Count() > 1)
            .Select(g => $"{g.Key} ({g.Count()}x)")
            .ToList();

        if (duplicateGuids.Any())
            errors.Add($"❌ {duplicateGuids.Count} GUIDs duplicados: {string.Join(", ", duplicateGuids)}");
        else
            Console.WriteLine("✅ Zero GUIDs duplicados");

        // 3. Verificar género em órgãos reprodutores
        var orgaosGeneroErrado = items
            .Where(x => x.Categoria == CategoriaCore.Orgao)
            .Where(x =>
                (x.Nome.Contains("Próstata") && x.GeneroAplicavel != "Masculino") ||
                (x.Nome.Contains("Testículo") && x.GeneroAplicavel != "Masculino") ||
                (x.Nome.Contains("Pénis") && x.GeneroAplicavel != "Masculino") ||
                (x.Nome.Contains("Ovário") && x.GeneroAplicavel != "Feminino") ||
                (x.Nome.Contains("Útero") && x.GeneroAplicavel != "Feminino") ||
                (x.Nome.Contains("Mama") && x.GeneroAplicavel != "Feminino") ||
                (x.Nome.Contains("Vagina") && x.GeneroAplicavel != "Feminino")
            )
            .Select(x => $"{x.Nome} (género: {x.GeneroAplicavel})")
            .ToList();

        if (orgaosGeneroErrado.Any())
            errors.Add($"❌ {orgaosGeneroErrado.Count} órgãos com género incorreto: {string.Join(", ", orgaosGeneroErrado)}");
        else
            Console.WriteLine("✅ Todos os órgãos reprodutores com género correto");

        // 4. Verificar JsonMetadata não-null
        var semMetadata = items
            .Where(x => string.IsNullOrEmpty(x.JsonMetadata))
            .Select(x => x.Nome)
            .ToList();

        if (semMetadata.Any())
            errors.Add($"❌ {semMetadata.Count} itens sem JsonMetadata");
        else
            Console.WriteLine("✅ Todos os itens têm JsonMetadata");

        // 5. Verificar totais por categoria
        var totaisPorCategoria = items
            .GroupBy(x => x.Categoria)
            .Select(g => new { Categoria = g.Key, Total = g.Count() })
            .ToList();

        Console.WriteLine("\n📊 Totais por Categoria:");
        foreach (var cat in totaisPorCategoria)
            Console.WriteLine($"   {cat.Categoria}: {cat.Total} itens");

        // Totais esperados
        var esperados = new Dictionary<CategoriaCore, int>
        {
            { CategoriaCore.FloraisBach, 38 },
            { CategoriaCore.Chakra, 28 },
            { CategoriaCore.Meridiano, 20 }
            // Adicionar outros conforme implementado
        };

        foreach (var (categoria, totalEsperado) in esperados)
        {
            var totalReal = totaisPorCategoria.FirstOrDefault(x => x.Categoria == categoria)?.Total ?? 0;
            if (totalReal != totalEsperado)
                errors.Add($"❌ {categoria}: esperados {totalEsperado}, encontrados {totalReal}");
        }

        // 6. Resultado final
        Console.WriteLine("\n" + new string('=', 60));
        if (errors.Any())
        {
            Console.WriteLine("❌ VALIDAÇÃO FALHOU:\n");
            errors.ForEach(e => Console.WriteLine(e));
            throw new Exception($"Validação falhou com {errors.Count} erro(s)");
        }
        else
        {
            Console.WriteLine("✅✅✅ VALIDAÇÃO COMPLETA - CÓDIGO PRONTO PARA PRODUÇÃO! ✅✅✅");
        }
    }
}
```

---

## 🚀 COMANDO PARA INICIAR

**Copia e cola este prompt no ChatGPT/Claude/Gemini**:

```
🤖 TAREFA: Gerar ItemBancoCoreSeeder.cs completo para BioDeskPro2

📋 ESPECIFICAÇÕES:
- Linguagem: C# 12 (.NET 8)
- Namespace: BioDesk.Data.SeedData
- Entidade: ItemBancoCore (ver estrutura no documento)
- Total: ~6.700 itens (11 categorias)
- Ficheiro: ÚNICO (não dividir)

⚠️ REGRAS CRÍTICAS:
1. ❌ ZERO duplicados de GUID
2. ❌ ZERO placeholders ("TODO", "...", "etc")
3. ✅ Género CORRETO em órgãos reprodutores:
   - Próstata/Testículos/Pénis → "Masculino"
   - Ovários/Útero/Mama/Vagina → "Feminino"
   - Outros órgãos → "Ambos"
4. ✅ JsonMetadata rico (mínimo 3 propriedades)
5. ✅ Compilável sem warnings

📊 CATEGORIAS (por ordem de prioridade):
1. Florais de Bach (38) - COMPLETO
2. Chakras (28) - COMPLETO
3. Meridianos (20) - COMPLETO
4. Órgãos (150) - ATENÇÃO GÉNERO!
5. Vitaminas (50)
6. Minerais (80)
7. Florais Californianos (103)
8. Emoções (500)
9. Suplementos (300)
10. Alimentos (1.000)
11. Homeopatia (3.000)

📤 FORMATO DE ENTREGA:
- Bloco markdown: ```csharp ... ```
- Incluir método ValidateAll() no final
- NENHUMA explicação fora do código
- Se timeout: entregar pelo menos categorias 1-4 (236 itens)

🎯 EXEMPLO de estrutura esperada:
```csharp
public static class ItemBancoCoreSeeder
{
    public static List<ItemBancoCore> GetAll() { ... }

    private static List<ItemBancoCore> GetFloraisBach()
    {
        return new List<ItemBancoCore>
        {
            new() {
                ExternalId = Guid.Parse("..."),
                Nome = "Rock Rose",
                Categoria = CategoriaCore.FloraisBach,
                JsonMetadata = JsonSerializer.Serialize(new { ... }),
                GeneroAplicavel = "Ambos",
                // ... resto dos campos
            },
            // ... TODOS os 38 florais (NUNCA "restantes X itens")
        };
    }

    // ... outros Get*() methods

    public static void ValidateAll() { ... }
}
```

🚀 COMEÇAR AGORA!
```

---

## 📝 APÓS RECEBER O CÓDIGO

1. **Copy-Paste direto** para `src/BioDesk.Data/SeedData/ItemBancoCoreSeeder.cs`
2. **Build**: `dotnet build`
3. **Validar**: Executar método `ItemBancoCoreSeeder.ValidateAll()` em teste
4. **Integrar**: Adicionar ao `BioDeskDbContext.OnModelCreating()`

---

**FIM DO PROMPT OTIMIZADO** 🎉

**Pronto para enviar ao agente de codificação!**
