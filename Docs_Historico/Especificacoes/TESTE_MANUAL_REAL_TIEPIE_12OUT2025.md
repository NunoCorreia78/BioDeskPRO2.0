# 🧪 TESTE MANUAL - RealTiePieHardwareService

**Data**: 12 de outubro de 2025  
**Hardware**: TiePie Handyscope HS5

---

## ⚠️ PRÉ-REQUISITOS

Antes de executar a aplicação, confirmar:

### 1. LibTiePie SDK Instalado
- [ ] **Download**: https://www.tiepie.com/en/libtiepie-sdk
- [ ] **Instalação**: Executar instalador (x64 ou x86 conforme arquitetura)
- [ ] **Verificar DLL**: `libtiepie.dll` deve estar em:
  - `C:\Program Files\TiePie Engineering\LibTiePie\bin\x64\` (64-bit)
  - `C:\Program Files\TiePie Engineering\LibTiePie\bin\x86\` (32-bit)

### 2. Hardware Conectado
- [ ] **USB**: TiePie Handyscope HS5 ligado via USB
- [ ] **Drivers**: Device Manager mostra "TiePie Handyscope HS5" (sem ⚠️)
- [ ] **LED**: LED no aparelho está aceso (verde/azul)

---

## 🚀 PASSOS DE TESTE

### Teste 1: Detecção de Hardware

1. Executar aplicação BioDeskPro2
2. Verificar logs no arranque:
   ```log
   🔌 RealTiePieHardwareService: Inicializando LibTiePie SDK...
   ✅ LibTiePie SDK v[VERSION] inicializado com sucesso
   ```

**ESPERADO**: ✅ SDK inicializa sem erros  
**SE FALHAR**: ❌ `libtiepie.dll NÃO ENCONTRADO!` → Instalar SDK

---

### Teste 2: GetStatus (via Debug/Código)

**Opção A - Via C# Interactive**:
```csharp
var service = _host.Services.GetRequiredService<ITiePieHardwareService>();
var status = await service.GetStatusAsync();
Console.WriteLine(status);
```

**Opção B - Via Aplicação** (criar botão teste):
- Dashboard → Botão "🧪 Testar Hardware"
- Executar `GetStatusAsync()`
- Mostrar MessageBox com status

**ESPERADO**:
```
✅ TiePie Handyscope HS5 (S/N: 12345) - 2 canais, Max: 5.00 MHz
```

**SE FALHAR**:
```
❌ Desconectado: Nenhum dispositivo TiePie encontrado. Verifique conexão USB.
```

---

### Teste 3: Sinal de Teste (1 kHz, 1V, Sine, 2s)

**Código**:
```csharp
var service = _host.Services.GetRequiredService<ITiePieHardwareService>();
var sucesso = await service.TestHardwareAsync();

if (sucesso)
    MessageBox.Show("✅ Teste de hardware PASSOU!", "Sucesso");
else
    MessageBox.Show("❌ Teste de hardware FALHOU!", "Erro");
```

**VALIDAÇÃO FÍSICA**:
1. **Osciloscópio**: Conectar à saída do HS5
2. **Forma de onda**: Onda senoidal, 1 kHz, 1Vpp
3. **Duração**: 2 segundos
4. **Paragem**: Sinal para automaticamente após 2s

**ESPERADO**: ✅ Logs mostram:
```log
🧪 Teste de hardware: 1 kHz, 1V, Sine, 2s
🔊 Enviando sinal: Ch1: 1000,00 Hz, 1,00V, Sine, 2,0s
✅ Sinal iniciado com sucesso
✅ Sinal completado (2s)
✅ Teste de hardware: PASSOU
```

---

### Teste 4: Múltiplas Frequências (RNG + TiePie)

**Código Completo**:
```csharp
// 1. Carregar protocolo da BD
var protocoloRepo = _host.Services.GetRequiredService<IProtocoloRepository>();
var protocolo = await protocoloRepo.GetByIdAsync(Guid.Parse("..."));

// 2. Selecionar 3 frequências aleatórias (RNG)
var rngService = _host.Services.GetRequiredService<IRngService>();
rngService.CurrentSource = EntropySource.HardwareCrypto;
var frequencias = await rngService.SelectRandomFrequenciesAsync(protocolo, count: 3);

// Exemplo output: [2720.0, 1600.0, 987.6] Hz

// 3. Aplicar via TiePie (Canal 1, 1.5V, Sine, 5s cada)
var tiepieService = _host.Services.GetRequiredService<ITiePieHardwareService>();
var sucesso = await tiepieService.SendMultipleFrequenciesAsync(
    frequencias,
    SignalChannel.Channel1,
    voltageV: 1.5,
    waveform: SignalWaveform.Sine,
    durationPerFreqSeconds: 5.0
);

Console.WriteLine(sucesso ? "✅ SUCESSO" : "❌ FALHOU");
```

**VALIDAÇÃO**:
- [ ] 1ª frequência: 2720 Hz, 1.5Vpp, Sine, 5s
- [ ] 2ª frequência: 1600 Hz, 1.5Vpp, Sine, 5s
- [ ] 3ª frequência: 987.6 Hz, 1.5Vpp, Sine, 5s
- [ ] Paragem automática após 15s total

---

### Teste 5: Formas de Onda (Sine, Square, Triangle, Sawtooth)

```csharp
var tiepieService = _host.Services.GetRequiredService<ITiePieHardwareService>();

var formasDeOnda = new[] { 
    SignalWaveform.Sine, 
    SignalWaveform.Square, 
    SignalWaveform.Triangle, 
    SignalWaveform.Sawtooth 
};

foreach (var waveform in formasDeOnda)
{
    var config = new SignalConfiguration
    {
        Channel = SignalChannel.Channel1,
        FrequencyHz = 1000.0,
        VoltageV = 2.0,
        Waveform = waveform,
        DurationSeconds = 3.0
    };

    var sucesso = await tiepieService.SendSignalAsync(config);
    Console.WriteLine($"{waveform}: {(sucesso ? "✅" : "❌")}");
}
```

**VALIDAÇÃO OSCILOSCÓPIO**:
- [ ] Sine: Onda senoidal suave
- [ ] Square: Onda quadrada (subidas/descidas abruptas)
- [ ] Triangle: Onda triangular (rampa linear)
- [ ] Sawtooth: Dente de serra (rampa + queda abrupta)

---

### Teste 6: 2 Canais (Ch1 e Ch2)

```csharp
var tiepieService = _host.Services.GetRequiredService<ITiePieHardwareService>();

// Ch1: 1 kHz, Sine
var config1 = new SignalConfiguration
{
    Channel = SignalChannel.Channel1,
    FrequencyHz = 1000.0,
    VoltageV = 1.0,
    Waveform = SignalWaveform.Sine,
    DurationSeconds = 5.0
};

// Ch2: 2 kHz, Square (simultâneo? ou sequencial?)
var config2 = new SignalConfiguration
{
    Channel = SignalChannel.Channel2,
    FrequencyHz = 2000.0,
    VoltageV = 1.5,
    Waveform = SignalWaveform.Square,
    DurationSeconds = 5.0
};

await tiepieService.SendSignalAsync(config1);
await tiepieService.SendSignalAsync(config2);
```

**NOTA**: Implementação atual é SEQUENCIAL (Ch1 → Ch2). Para SIMULTÂNEO precisa refactoring (2 handles).

---

## ❌ ERROS COMUNS E SOLUÇÕES

### Erro 1: `DllNotFoundException: libtiepie.dll`
**Causa**: LibTiePie SDK não instalado  
**Solução**: Instalar SDK de https://www.tiepie.com/en/libtiepie-sdk

### Erro 2: `Nenhum dispositivo TiePie encontrado`
**Causa**: USB desligado ou drivers não instalados  
**Solução**:
1. Verificar LED no HS5 está aceso
2. Device Manager → "TiePie Handyscope HS5" sem ⚠️
3. Reinstalar drivers se necessário

### Erro 3: `Falha ao abrir dispositivo (handle nulo)`
**Causa**: Dispositivo já em uso (outro processo)  
**Solução**:
1. Fechar TiePie software (se aberto)
2. Reiniciar aplicação BioDeskPro2
3. Desligar/religar USB

### Erro 4: `Falha ao configurar frequência/voltagem`
**Causa**: Valores fora do range do hardware  
**Solução**: Validar configuração com `config.IsValid()` antes de enviar

---

## ✅ CHECKLIST FINAL

### Hardware
- [ ] TiePie HS5 ligado via USB
- [ ] LED aceso
- [ ] Device Manager mostra dispositivo OK

### Software
- [ ] LibTiePie SDK instalado
- [ ] libtiepie.dll acessível
- [ ] BioDeskPro2 compila (0 errors)
- [ ] RealTiePieHardwareService registado no DI

### Testes Executados
- [ ] GetStatus: Hardware detectado
- [ ] TestHardware: 1 kHz, 1V, Sine, 2s
- [ ] Múltiplas frequências: 3 frequências sequenciais
- [ ] 4 formas de onda: Sine, Square, Triangle, Sawtooth
- [ ] 2 canais: Ch1 e Ch2

### Validação Física
- [ ] Osciloscópio confirma sinais correctos
- [ ] Frequências medidas correspondem às enviadas
- [ ] Voltagens medidas correspondem às configuradas
- [ ] Formas de onda visualmente correctas

---

## 📝 PRÓXIMOS PASSOS (após validação)

1. **Criar UI para Terapias** (FASE 5):
   - View: `TerapiasBioenergeticasView.xaml`
   - ViewModel: `TerapiasBioenergeticasViewModel`
   - Funcionalidades: Pesquisa protocolos, RNG selection, aplicação sinais, histórico

2. **Gestão de Sessões**:
   - Gravar em `SessaoTerapia` tabela
   - Tracking: frequências aplicadas, duração, resultado

3. **Relatórios PDF**:
   - QuestPDF: Relatório de sessão com frequências aplicadas
   - Export: Histórico de terapias para análise

---

**Autor**: GitHub Copilot  
**Data**: 12 de outubro de 2025  
**Status**: ⏳ AGUARDA VALIDAÇÃO COM HARDWARE FÍSICO
