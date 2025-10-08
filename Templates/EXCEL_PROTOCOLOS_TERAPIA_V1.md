# 📋 Exemplo de Excel de Protocolos v1 - Terapia Bioenergética

## Formato Excel (.xlsx)

### Colunas Obrigatórias

| Coluna | Tipo | Validação | Descrição | Exemplo |
|--------|------|-----------|-----------|---------|
| ExternalId | GUID | Único | Identificador externo (Upsert) | 550e8400-e29b-41d4-a716-446655440000 |
| Nome | String(200) | Obrigatório | Nome do protocolo | Dor Lombar Aguda |
| FrequenciaHz | Decimal | > 0, ≤ 2000000 | Frequência em Hz | 528.0 |
| AmplitudeV | Decimal | 0-20 | Amplitude em volts | 5.0 |
| LimiteCorrenteMa | Decimal | 0-50 | Limite de corrente em mA | 10.0 |
| FormaOnda | String | Sine/Square/Triangle/Saw | Forma de onda | Sine |
| Modulacao | String | AM/FM/Burst/None | Tipo de modulação | None |
| DuracaoMin | Integer | 1-180 | Duração em minutos | 5 |
| Canal | Integer | 1-2 | Canal de saída (TiePie HS3) | 1 |
| Versao | String(10) | - | Versão do schema | 1.0 |

### Colunas Opcionais

| Coluna | Tipo | Descrição | Exemplo |
|--------|------|-----------|---------|
| Categoria | String(100) | Categoria do protocolo | Dor |
| SequenciaJSON | JSON | Override passo-a-passo | [{"step":1, "freqHz":100, "durationSec":30}] |
| Contraindicacoes | String(1000) | Contraindicações clínicas | Gravidez, pacemaker |
| Notas | String(2000) | Observações adicionais | Baseado no protocolo CoRe v5.0 |

## Exemplo de Linha Excel

```
ExternalId: 550e8400-e29b-41d4-a716-446655440000
Nome: Dor Lombar Aguda
Categoria: Dor
FrequenciaHz: 528.0
AmplitudeV: 5.0
LimiteCorrenteMa: 10.0
FormaOnda: Sine
Modulacao: None
DuracaoMin: 5
Canal: 1
SequenciaJSON: (vazio)
Contraindicacoes: Pacemaker, gravidez
Notas: Protocolo base para dor inflamatória
Versao: 1.0
```

## Protocolos de Exemplo

### 1. Dor Lombar Aguda
- **Frequência**: 528 Hz (Reparação de tecidos)
- **Amplitude**: 5V
- **Corrente**: 10mA
- **Duração**: 5 min
- **Forma**: Sine

### 2. Stress Crónico
- **Frequência**: 7.83 Hz (Ressonância Schumann)
- **Amplitude**: 3V
- **Corrente**: 5mA
- **Duração**: 10 min
- **Forma**: Sine

### 3. Inflamação Geral
- **Frequência**: 174 Hz (Frequência Solfeggio)
- **Amplitude**: 4V
- **Corrente**: 8mA
- **Duração**: 8 min
- **Forma**: Square

### 4. Ansiedade
- **Frequência**: 10 Hz (Alpha)
- **Amplitude**: 2V
- **Corrente**: 3mA
- **Duração**: 15 min
- **Forma**: Sine

### 5. Fadiga Crónica
- **Frequência**: 40 Hz (Gamma)
- **Amplitude**: 6V
- **Corrente**: 12mA
- **Duração**: 10 min
- **Forma**: Triangle

## Importação Idempotente

- **Upsert**: Baseado em `ExternalId`
- Se `ExternalId` já existe → UPDATE
- Se `ExternalId` não existe → INSERT
- **Relatório**: Exibe OK/Erros/Warnings após importação
- **Pré-visualização**: Mostra linhas antes de gravar na BD

## Validações na Importação

1. ✅ ExternalId é GUID válido
2. ✅ Nome não vazio
3. ✅ FrequenciaHz > 0 e ≤ 2MHz
4. ✅ AmplitudeV entre 0-20V
5. ✅ LimiteCorrenteMa entre 0-50mA
6. ✅ FormaOnda é um dos valores válidos
7. ✅ Modulacao é um dos valores válidos
8. ✅ DuracaoMin entre 1-180 min
9. ✅ Canal é 1 ou 2
10. ✅ SequenciaJSON é JSON válido (se fornecido)

## Erros Comuns

❌ **Erro**: ExternalId duplicado
**Solução**: Gerar novo GUID único

❌ **Erro**: Frequência fora de limites
**Solução**: Ajustar para 0.01-2000000 Hz

❌ **Erro**: Amplitude > 20V
**Solução**: Segurança clínica - máximo 20V

❌ **Erro**: Corrente > 50mA
**Solução**: Segurança clínica - máximo 50mA
