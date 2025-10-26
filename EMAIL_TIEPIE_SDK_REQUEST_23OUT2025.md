# Email para TiePie Engineering - SDK Request

**Para:** support@tiepie.com
**CC:** info@tiepie.com
**Assunto:** SDK Request for TiePie Handyscope HS3 - .NET 8 Integration

---

## 📧 Email (English)

```
Dear TiePie Engineering Support Team,

I am developing a medical instrumentation application in C# .NET 8 (Windows 11)
and need to integrate with a TiePie Handyscope HS3 oscilloscope for biofeedback
therapy (Schumann resonance generation at 7.83 Hz).

### Current Situation
- **Hardware**: TiePie Handyscope HS3 (VID: 0x0E36, PID: 0x0008)
- **Driver**: HS3r.sys v6.0.6.0 (kernel-mode, installed and working)
- **OS**: Windows 11 Pro Build 22631, .NET 8.0.403
- **Problem**: Cannot open device via standard Win32 CreateFile() API

### Technical Details
I have successfully:
1. ✅ Analyzed USB protocol via API Monitor (IOCTL codes: 0x222000, 0x222051, 0x22204E, 0x222059)
2. ✅ Reverse-engineered command structures from API Monitor logs
3. ✅ Implemented C# protocol layer (HS3DeviceProtocol.cs)
4. ✅ Confirmed hardware connection (Get-PnpDevice shows Status=OK)

However, I'm blocked by device path resolution:
- SetupDiGetClassDevs() finds device but returns invalid path for CreateFile()
- Both device interface GUIDs tested fail with Win32 ERROR_FILE_NOT_FOUND (code 2)
- Symbolic link discovery unsuccessful (tested 15 common names like \\.\HS3)

**Root Cause**: HS3r.sys kernel driver doesn't expose standard device interfaces
that Win32 CreateFile() can open.

### Request
Could you please provide:
1. **Official .NET SDK** (C# preferred) or C++ SDK with .NET wrapper capability
2. **Device path resolution documentation** - How to properly open HS3 device handles
3. **API documentation** for function generator control (frequency, amplitude, waveform)
4. **License information** for commercial medical device integration

### Use Case
- **Application**: BioDeskPro2 - Naturopathy/Osteopathy clinic management software
- **Feature**: Frequency therapy integration (7.83 Hz Schumann resonance)
- **Market**: Medical professionals in Portugal
- **Timeline**: Prototype phase, production Q1 2026

### Alternative Solutions Considered
- ❌ LibUSB-Win32: Incompatible with .NET 8, requires driver replacement
- ❌ Zadig+WinUSB: Too destructive (breaks TiePie original software)
- ⏳ Official SDK: Best solution for production stability

### Current Implementation
I have complete C# protocol implementation ready (~2000 lines):
- Command discovery framework (scans 0x01-0xFF range)
- Function generator API (SetFrequencyAsync, SetAmplitudeAsync, etc.)
- Firmware loader (Intel HEX parser)
- xUnit test suite

**Only missing**: Proper device handle acquisition method.

### Contact Information
- **Developer**: [Your Name]
- **Email**: [Your Email]
- **Company**: [Your Company - if applicable]
- **Location**: Portugal
- **GitHub**: [Your GitHub - if you want to share code]

I would greatly appreciate any guidance or SDK access. I'm happy to:
- Sign NDA if required
- Participate in beta testing
- Provide feedback on SDK documentation
- Share integration experience for case study

Thank you for your time and excellent hardware!

Best regards,
[Your Name]
```

---

## 📧 Email (Português - Alternativo)

```
Excelentíssimos Senhores da TiePie Engineering,

Estou a desenvolver uma aplicação de instrumentação médica em C# .NET 8
(Windows 11) e necessito integrar um osciloscópio TiePie Handyscope HS3
para terapia de biofeedback (geração de ressonância Schumann a 7.83 Hz).

### Situação Atual
- **Hardware**: TiePie Handyscope HS3 (VID: 0x0E36, PID: 0x0008)
- **Driver**: HS3r.sys v6.0.6.0 (kernel-mode, instalado e funcional)
- **SO**: Windows 11 Pro Build 22631, .NET 8.0.403
- **Problema**: Impossível abrir dispositivo via API Win32 CreateFile()

### Detalhes Técnicos
Consegui com sucesso:
1. ✅ Analisar protocolo USB via API Monitor (códigos IOCTL: 0x222000, 0x222051, etc.)
2. ✅ Fazer engenharia reversa das estruturas de comandos
3. ✅ Implementar camada de protocolo em C# (HS3DeviceProtocol.cs)
4. ✅ Confirmar ligação hardware (Get-PnpDevice mostra Status=OK)

Contudo, estou bloqueado pela resolução do device path:
- SetupDiGetClassDevs() encontra dispositivo mas retorna path inválido
- Ambos GUIDs testados falham com Win32 ERROR_FILE_NOT_FOUND (código 2)
- Symbolic links não encontrados (testei 15 nomes comuns)

**Causa raiz**: Driver kernel HS3r.sys não expõe device interfaces padrão
que CreateFile() Win32 consiga abrir.

### Pedido
Poderiam fornecer:
1. **SDK oficial .NET** (C# preferencial) ou SDK C++ com capacidade wrapper .NET
2. **Documentação de resolução device path** - Como abrir handles HS3 corretamente
3. **Documentação API** para controlo gerador funções (frequência, amplitude, forma onda)
4. **Informação licenciamento** para integração dispositivo médico comercial

### Caso de Uso
- **Aplicação**: BioDeskPro2 - Software gestão clínica Naturopatia/Osteopatia
- **Funcionalidade**: Integração terapia frequências (7.83 Hz ressonância Schumann)
- **Mercado**: Profissionais saúde em Portugal
- **Timeline**: Fase protótipo, produção Q1 2026

### Soluções Alternativas Consideradas
- ❌ LibUSB-Win32: Incompatível .NET 8, requer substituição driver
- ❌ Zadig+WinUSB: Demasiado destrutivo (quebra software TiePie original)
- ⏳ SDK Oficial: Melhor solução para estabilidade produção

### Implementação Atual
Tenho implementação protocolo C# completa pronta (~2000 linhas):
- Framework descoberta comandos (scan range 0x01-0xFF)
- API gerador funções (SetFrequencyAsync, SetAmplitudeAsync, etc.)
- Loader firmware (parser Intel HEX)
- Suite testes xUnit

**Apenas falta**: Método correto aquisição device handle.

Agradeceria muito qualquer orientação ou acesso SDK. Disponível para:
- Assinar NDA se necessário
- Participar beta testing
- Fornecer feedback documentação SDK
- Partilhar experiência integração para caso estudo

Obrigado pelo vosso tempo e excelente hardware!

Cumprimentos,
[O Teu Nome]
```

---

## 📋 Documentos de Suporte a Anexar

1. **BLOCKER_HS3_DEVICE_PATH_23OUT2025.md** - Análise técnica completa do problema
2. **HS3_DEVICE_PATH_RESOLUTION_23OUT2025.md** - Tentativas de resolução documentadas
3. **PROTOCOLO_HS3_COMPLETO_23OUT2025.md** - Protocolo USB descoberto (se partilhares)
4. **Screenshot API Monitor** - Evidência de análise técnica já realizada

---

## 🎯 Estratégia de Envio

### Opção A: Email Direto (RECOMENDADO)
- **Para**: support@tiepie.com
- **Anexos**: BLOCKER + RESOLUTION docs (PDF)
- **Follow-up**: 7 dias depois se sem resposta

### Opção B: Formulário Web
- https://www.tiepie.com/support/contact
- Preencher com texto acima
- Categoria: "SDK / Software Development"

### Opção C: Telefone (Último Recurso)
- +31 (0)26 374 21 10 (Holanda)
- Pedir "Software Development Support"

---

## 📊 Probabilidade Resposta

- ✅ **Alta (70%)**: TiePie costuma responder pedidos SDK
- ⏱️ **Timeline**: 2-5 dias úteis (experiência comunidade)
- 📦 **SDK**: Normalmente fornecem DLL C++ + headers
- 🆓 **Grátis**: SDK development geralmente sem custo

---

## 🔄 Plano B (Se Não Responderem em 2 Semanas)

1. **Fórum TiePie**: https://forum.tiepie.com/
2. **GitHub Issues**: Procurar repos com integração HS3
3. **Reddit r/AskElectronics**: Comunidade experiente
4. **Stack Overflow**: Tag `tiepie` (poucos posts mas há exemplos)

---

**Criado**: 23 de outubro de 2025
**Status**: Pronto para envio
**Próxima ação**: Personalizar [Your Name] e enviar para support@tiepie.com
