# 📋 Templates de Terapias Bioenergéticas

## 📁 Como Adicionar Seus Dados Excel

### **COLE SEU EXCEL AQUI**: `PROTOCOLOS_FREQUENCIAS.xlsx`

### Schema Esperado (Colunas):

| Coluna | Tipo | Obrigatório | Descrição | Exemplo |
|--------|------|-------------|-----------|---------|
| `ExternalId` | GUID | Sim | Identificador único (gerar se não existir) | `a3f2e1d0-1234-5678-9abc-def012345678` |
| `Nome` | Texto | Sim | Nome da questão/condição de saúde | `Stress Emocional` |
| `Categoria` | Texto | Não | Categoria/Sistema (Emocional, Digestivo, etc.) | `Emocional` |
| `FrequenciaHz` | Número | Sim | Frequência em Hertz (>0) | `528` |
| `AmplitudeV` | Número | Não | Amplitude em Volts (0-20, default 5V) | `5.0` |
| `LimiteCorrenteMa` | Número | Não | Limite de corrente em mA (0-50, default 10mA) | `10` |
| `FormaOnda` | Texto | Não | Sine/Square/Triangle/Saw (default Sine) | `Sine` |
| `Modulacao` | Texto | Não | None/AM/FM/Burst (default None) | `None` |
| `DuracaoMin` | Número | Não | Duração em minutos (1-180, default 5 min) | `5` |
| `Canal` | Texto | Não | Canal de saída (1/2/Both, default 1) | `1` |
| `Contraindicacoes` | Texto | Não | Contraindicações clínicas | `Gravidez, Pacemaker` |
| `Notas` | Texto | Não | Notas adicionais | `Aplicar durante meditação` |

### Exemplo Real (primeiras 3 linhas):

```
ExternalId                              | Nome                  | Categoria    | FrequenciaHz | AmplitudeV | DuracaoMin
a3f2e1d0-1234-5678-9abc-def012345678   | Stress Emocional      | Emocional    | 528          | 5.0        | 5
b4e3f2d1-2345-6789-abcd-ef0123456789   | Ansiedade             | Emocional    | 396          | 5.0        | 5
c5f4e3d2-3456-789a-bcde-f01234567890   | Digestão Lenta        | Digestivo    | 285          | 4.0        | 10
```

### 🚀 Como Processar:

1. **Cole seu Excel** nesta pasta: `Templates/Terapias/PROTOCOLOS_FREQUENCIAS.xlsx`
2. Abra o BioDeskPro2 → **Tab Terapias**
3. Clique **"Importar Excel"**
4. Selecione `PROTOCOLOS_FREQUENCIAS.xlsx`
5. **Pré-visualização** → Verificar OK/Warnings/Erros
6. Clique **"Confirmar Importação"**
7. Protocolos aparecem no **Catálogo** prontos a usar

### ⚠️ Notas Importantes:

- **ExternalId** é **chave única** (se reimportar, atualiza em vez de duplicar)
- Se faltarem colunas opcionais, usa **defaults seguros**
- **Validação automática**: ranges, enums, obrigatoriedade
- Importação é **idempotente** (rodar 10× = mesmo resultado)

### 📊 Defaults Seguros (se omitir):

- `AmplitudeV`: **5.0 V**
- `LimiteCorrenteMa`: **10 mA**
- `FormaOnda`: **Sine**
- `Modulacao`: **None**
- `DuracaoMin`: **5 minutos**
- `Canal`: **1**

---

## 📝 COLE AQUI OS SEUS DADOS:

**Ficheiro**: `PROTOCOLOS_FREQUENCIAS.xlsx`

Pode ter:
- ✅ Centenas ou milhares de linhas
- ✅ Qualquer ordem de colunas
- ✅ Colunas extra (ignoradas)
- ✅ Linhas vazias (ignoradas)

**O sistema vai processar tudo automaticamente!** 🚀
