# 🎯 TiePie HS3 - Guia de Uso Prático (BioDeskPro2)

**Data**: 19 de outubro de 2025
**Objetivo**: Emitir frequências através do TiePie Handyscope HS3

---

## ✅ COMO USAR

### 1. Preparação do Hardware

```
1. Ligar HS3 ao USB do PC
2. Aguardar LED aceso no dispositivo
3. Verificar Device Manager: "TiePie Handyscope HS3" sem avisos
4. Conectar eletrodos ao BNC do HS3
```

### 2. Usar no BioDeskPro2

```
1. Dashboard → Ficha Paciente → Terapias
2. Verificar: "[HS3] Conectado (SN: xxxxxxxx)"
3. Selecionar frequências desejadas
4. Clicar "Iniciar Emissão"
```

**Pronto!** HS3 está a emitir.

---

## 🔧 FUNCIONALIDADES DISPONÍVEIS

### Emissão Simples
- **Frequência**: 0.1 Hz a 1 MHz
- **Amplitude**: 0-10V (ajustável)
- **Forma de Onda**: Sine, Square, Triangle, DC, Noise, Pulse
- **Duração**: Configurável por utilizador

### Emissão de Lista
- Carregar listas de frequências (ex: banco Inergetix CoRe)
- Emissão sequencial automática
- Duração por frequência configurável

### Status em Tempo Real
- Frequência atual a emitir
- Amplitude configurada
- Tempo decorrido

---

## ⚠️ RESOLUÇÃO DE PROBLEMAS

### Problema: "[HS3] Não detectado"

**Causas possíveis**:
1. ❌ HS3 não está ligado ao USB
2. ❌ Drivers não instalados
3. ❌ `hs3.dll` não está na pasta da aplicação
4. ❌ Inergetix CoRe está a usar o HS3 simultaneamente

**Soluções**:
```bash
# 1. Verificar USB
- Ligar HS3 ao USB
- Aguardar LED aceso

# 2. Verificar Device Manager
Win+X → Device Manager → Procurar "TiePie"
- Se tem ⚠️ amarelo: Reinstalar drivers

# 3. Verificar DLL
Confirmar existe: BioDeskPro2\src\BioDesk.App\hs3.dll

# 4. Fechar CoRe
- Fechar Inergetix CoRe se estiver aberto
- HS3 só aceita 1 conexão por vez
```

---

### Problema: "Conectado mas não emite nada"

**Diagnóstico**:
```
1. Verificar eletrodos bem conectados ao BNC
2. Testar com multímetro/osciloscópio:
   - Configurar 100 Hz, 5V, Sine
   - Medir no BNC: deve ver ~5V pico-a-pico
3. Se não medir nada: Hardware pode não estar realmente conectado
```

**Nota Técnica**:
A DLL `hs3.dll` (Inergetix) não valida conexão física USB. Por isso pode mostrar "Conectado" mesmo sem hardware. A **única forma de confirmar 100%** é medir com equipamento.

---

## 📊 COMPATIBILIDADE COM INERGETIX CORE

### ✅ O QUE FUNCIONA
- Ambos programas podem estar instalados no mesmo PC
- Mesma DLL `hs3.dll` usada por ambos
- Sem conflitos de software

### ❌ LIMITAÇÃO IMPORTANTE
**HS3 só aceita 1 conexão ativa por vez!**

```
Workflow Recomendado:

Usar BioDeskPro2 com HS3:
  1. Fechar Inergetix CoRe
  2. Abrir BioDeskPro2
  3. Emitir frequências

Usar Inergetix CoRe com HS3:
  1. Fechar BioDeskPro2
  2. Abrir Inergetix CoRe
  3. Emitir frequências
```

**Se ambos tentarem controlar HS3 simultaneamente**: Comportamento imprevisível!

---

## 🎛️ PARÂMETROS RECOMENDADOS

### Terapia Energética (Padrão)
```
Frequência: Conforme protocolo (ex: 7.83 Hz Schumann)
Amplitude: 5-8V
Forma: Sine (onda suave)
Duração: 10-20 minutos
```

### Teste Rápido (Verificação)
```
Frequência: 100 Hz
Amplitude: 1V
Forma: Square
Duração: 5 segundos
```

### Limites de Segurança
```
⚠️ Amplitude Máxima: 10V (hardware)
⚠️ Frequência Máxima: 1 MHz (recomendado: até 100 kHz)
⚠️ Corrente: Limitada pelo HS3 (baixa, segura)
```

---

## 📝 LOGS E DEBUG

### Verificar Logs da Aplicação
```powershell
# Windows
notepad C:\ProgramData\BioDeskPro2\Logs\biodesk-YYYYMMDD.log

# Desenvolvimento (VS Code)
notepad BioDeskPro2\Logs\biodesk-YYYYMMDD.log
```

### Linhas-chave a procurar:
```
✅ "[HS3] InitInstrument() succeeded"
✅ "[HS3] Device initialized"
✅ "[HS3] ✅ Emission started successfully!"

❌ "[HS3] InitInstrument() failed"
❌ "[HS3] hs3.dll not found"
❌ "[HS3] Error during emission configuration"
```

---

## 🔗 FICHEIROS TÉCNICOS (Para Programadores)

- **Código Principal**: `src/BioDesk.Services/Hardware/TiePie/TiePieHS3Service.cs`
- **P/Invoke API**: `src/BioDesk.Services/Hardware/TiePie/HS3Native.cs`
- **ViewModel**: `src/BioDesk.ViewModels/UserControls/Terapia/EmissaoConfiguracaoViewModel.cs`
- **DLL Nativa**: `src/BioDesk.App/hs3.dll` (32-bit, Inergetix CoRe wrapper)

**Documentação Técnica**:
- `IMPLEMENTACAO_HS3_COMPLETA_17OUT2025.md` - Implementação detalhada
- `CONCLUSAO_DLL_HS3_INUTIL_19OUT2025.md` - Limitações conhecidas da DLL

---

## ✅ CHECKLIST RÁPIDO

**Antes de usar HS3**:
- [ ] HS3 ligado ao USB (LED aceso)
- [ ] Device Manager mostra dispositivo OK
- [ ] BioDeskPro2 mostra "[HS3] Conectado"
- [ ] Inergetix CoRe fechado
- [ ] Eletrodos conectados ao BNC

**Teste de Emissão**:
- [ ] Configurar 100 Hz, 5V, Sine
- [ ] Clicar "Iniciar Emissão"
- [ ] Log mostra "✅ Emission started successfully"
- [ ] (Opcional) Medir com osciloscópio: ~5V @ 100 Hz

**Se funcionar** → Tudo OK! Usar conforme necessário.
**Se não funcionar** → Ver "Resolução de Problemas" acima.

---

**Princípio**: "Se emite, está tudo bem. Se não emite, verificar hardware/conexões."
