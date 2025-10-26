# RESOLUÇÃO BLOCKER HS3 - Device Path Inválido (23/10/2025)

## 🎯 Objetivo
Resolver Win32 Error 2 (FILE_NOT_FOUND) em `CreateFile()` ao tentar abrir TiePie HS3.

## 📊 Sumário Executivo
**STATUS: NÃO RESOLVIDO - Aguardando TiePie SDK**

Após 3h de troubleshooting intensivo:
- ❌ **Symbolic links**: 15 nomes testados, todos falharam (ERROR_FILE_NOT_FOUND)
- ❌ **LibUsbDotNet**: Versão 2.2.29 incompatível com .NET 8, versão 3.0 alpha sem documentação
- ✅ **Root cause confirmado**: Driver `HS3r.sys` kernel-mode não expõe device interfaces padrão
- ✅ **Email enviado**: TiePie Engineering pedindo SDK oficial (22/10/2025)

## 🔬 Testes Executados

### 1. Symbolic Link Discovery (23/10/2025 18:40)
**Script:** `Test-HS3SymbolicLinks.ps1`
**Nomes testados:** 15 variações comuns
**Resultado:** Todos falharam com `Error 2` (FILE_NOT_FOUND)

```powershell
# Nomes testados:
\\.\HS3, \\.\HS3_0, \\.\HS3-0, \\.\TiePie_HS3, \\.\TiePieHS3
\\.\TIEPIESCOPE, \\.\TiePieScope, \\.\HS3r, \\.\HS3R
\\.\TIEPIE0, \\.\TIEPIE1, \\.\HANDYSCOPE, \\.\HandyScope
\\.\HS3_USB, \\.\TIEPIE_USB
```

**Conclusão:** Driver `HS3r.sys` não cria symbolic links `\\.\` acessíveis.

### 2. LibUsbDotNet Integration (23/10/2025 18:45-19:15)
**Package testado:** LibUsbDotNet 2.2.29 (stable) e 3.0.102-alpha
**Resultado:** Ambos incompatíveis

- **2.2.29:** API pré-.NET Core, não compila com .NET 8
- **3.0.102-alpha:** Estrutura alterada, sem documentação, sem exemplos

**Problemas encontrados:**
```csharp
// LibUsbDotNet 2.2.29 - Types não encontrados
UsbDevice? _device;              // ❌ CS0246
IUsbDevice? _wholeUsbDevice;      // ❌ CS0246
UsbEndpointReader? _reader;       // ❌ CS0246
UsbEndpointWriter? _writer;       // ❌ CS0246
```

**Conclusão:** LibUSB requer refactor massivo (2-3 dias) ou wrapper P/Invoke manual.

## 🧪 Código Gerado

### Test-HS3SymbolicLinks.ps1 ✅
**Localização:** `d:\BioDeskPro2\Test-HS3SymbolicLinks.ps1`
**Função:** Testar 15 nomes de symbolic links via CreateFile Win32
**Status:** Completo e funcional
**Uso futuro:** Debug de outros devices USB

### HS3LibUsbProtocol.cs ❌
**Localização:** Removido (incompatível)
**Tentativa:** Implementar acesso USB via LibUsbDotNet
**Motivo remoção:** LibUsbDotNet 2.x/3.x incompatível com .NET 8

## 📋 Opções Restantes

### ✅ OPÇÃO 1: TiePie SDK Oficial (RECOMENDADO)
**Status:** Email enviado 22/10/2025
**Timeline:** 3-7 dias úteis
**Pros:**
- ✅ Solução oficial suportada
- ✅ Documentação completa
- ✅ API estável e testada
- ✅ Não mexe no driver existente

**Cons:**
- ⏳ Depende de resposta TiePie
- ⏳ Pode demorar 1 semana+

**Ação:** Aguardar resposta em `support@tiepie.com`

### ⚠️ OPÇÃO 2: Zadig + WinUSB (DESTRUTIVO)
**Status:** Não testado
**Timeline:** 15-30 minutos
**Pros:**
- ✅ Rápido de implementar
- ✅ LibUSB funcionaria imediatamente

**Cons:**
- ❌ **DESTRUTIVO** - Substitui driver HS3r.sys
- ❌ Software TiePie original para de funcionar
- ❌ Difícil reverter (requer reinstalação driver)

**Ação:** **NÃO RECOMENDADO** - Só se TiePie não responder em 2 semanas

### 🔬 OPÇÃO 3: Engenharia Reversa Avançada (COMPLEXO)
**Status:** Não iniciado
**Timeline:** 1-2 semanas
**Técnicas:**
1. **WinDbg kernel debugging** - Analisar `HS3r.sys` em runtime
2. **IDA Pro disassembly** - Reverter `HS3r.sys` para encontrar IOCTL handlers
3. **API Monitor Advanced** - Capturar CreateFile de software TiePie oficial
4. **Custom kernel driver** - Criar wrapper sobre `HS3r.sys`

**Pros:**
- ✅ Solução permanente
- ✅ Entendimento completo do protocolo

**Cons:**
- ❌ Altíssima complexidade técnica
- ❌ Requer conhecimento kernel Windows
- ❌ 80-120h de trabalho estimado
- ❌ Pode violar EULA TiePie

**Ação:** **NÃO RECOMENDADO** - Só se projeto exigir independência total

## 🎯 Plano de Ação (Prioritizado)

### IMEDIATO (Hoje 23/10/2025)
1. ✅ **Documentar blocker** - Este documento
2. ✅ **Atualizar BLOCKER_HS3_DEVICE_PATH_23OUT2025.md** com testes executados
3. ⏳ **Commit + Push** - Preservar progresso antes de mudar abordagem

### CURTO PRAZO (24-30/10/2025)
1. ⏳ **Monitorar email TiePie** - Verificar diariamente
2. ⏳ **Desenvolver outras features** - Não bloquear projeto no HS3
3. ⏳ **Pesquisar alternativas** - Outros osciloscópios USB com .NET SDK

### MÉDIO PRAZO (Nov 2025)
1. ⏳ **Se TiePie responder:** Integrar SDK oficial
2. ⏳ **Se TiePie não responder (2 semanas):** Considerar Zadig+WinUSB (destrutivo)
3. ⏳ **Se projeto exigir:** Iniciar engenharia reversa kernel

## 📊 Lições Aprendidas

### ✅ O que funcionou
1. **PowerShell diagnostics** - Get-PnpDevice/Get-WmiObject revelou driver tipo
2. **Symbolic link testing** - Script reutilizável para debug USB
3. **Root cause analysis** - Kernel driver identificado corretamente
4. **Documentação progressiva** - Blocker documentado em tempo real

### ❌ O que não funcionou
1. **SetupDiGetClassDevs** - Retorna paths mas CreateFile falha
2. **LibUsbDotNet** - Incompatível com .NET 8
3. **Symbolic link bruteforce** - Driver não expõe `\\.\` names
4. **GUID testing** - Ambos GUIDs (original + ClassGUID) falharam

### 🎓 Conhecimento Adquirido
1. **Kernel drivers** podem não expor device interfaces mesmo registados
2. **LibUSB** não é silver bullet - requer driver libusb-win32/WinUSB
3. **Osciloscópios comerciais** geralmente exigem SDK proprietário
4. **Windows USB stack** tem 3 camadas: PDO → FDO → Device Interface (HS3 quebra última)

## 📁 Ficheiros Relacionados

### Criados/Atualizados
- ✅ `Test-HS3SymbolicLinks.ps1` - Script teste symbolic links (mantido)
- ✅ `HS3_DEVICE_PATH_RESOLUTION_23OUT2025.md` - Este documento
- ⏳ `BLOCKER_HS3_DEVICE_PATH_23OUT2025.md` - Atualizar com resultados testes

### Removidos
- ❌ `HS3LibUsbProtocol.cs` - Rascunho incompatível (removido)
- ❌ `LibUsbDotNet 2.2.29` - Package NuGet (removido)

## 🔗 Referências

### Documentação Técnica
- [BLOCKER_HS3_DEVICE_PATH_23OUT2025.md](./BLOCKER_HS3_DEVICE_PATH_23OUT2025.md) - Análise inicial
- [PROTOCOLO_HS3_COMPLETO_23OUT2025.md](./PROTOCOLO_HS3_COMPLETO_23OUT2025.md) - Protocolo USB descoberto
- [AUDITORIA_INTEGRACAO_HS3_17OUT2025.md](./AUDITORIA_INTEGRACAO_HS3_17OUT2025.md) - Implementação anterior

### Recursos Externos
- [TiePie Support](https://www.tiepie.com/support) - Aguardando resposta SDK
- [LibUSB Documentation](https://libusb.info/) - Library USB genérica
- [Zadig](https://zadig.akeo.ie/) - Tool para substituir drivers USB

### Código Relevante
- `HS3DeviceProtocol.cs` linha 167 - CreateFile que falha
- `HS3Protocol.cs` linha 73-90 - GUIDs testados documentados
- `HS3CommandDiscovery.cs` - Discovery bloqueado por device path

---

**Data:** 23 de outubro de 2025
**Autor:** GitHub Copilot + Utilizador
**Status:** BLOCKER NÃO RESOLVIDO - Aguardando TiePie SDK
**Próxima revisão:** 30/10/2025 (verificar resposta email)
