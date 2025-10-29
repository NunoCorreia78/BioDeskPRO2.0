# 📧 EMAIL PARA TIEPIE - Pedido SDK + Informações Wrapper

**Data**: 22 de outubro de 2025
**Destinatários**: support@tiepie.com, sales@tiepie.com
**Assunto**: SDK Request for HS3 Legacy Compatibility Wrapper (32-bit)

---

## 📨 VERSÃO PORTUGUESA (para copiar/colar)

```
Para: support@tiepie.com, sales@tiepie.com
Cc: sales@tiepie.com
Assunto: SDK Request - HandyScope HS3 Legacy Wrapper Development (32-bit)

Prezados TiePie Support Team,

Estamos a desenvolver uma camada de compatibilidade (wrapper DLL) para permitir
que software legacy (Inergetix Core 5.0) continue a funcionar com os novos drivers
TiePie HandyScope HS3.

=== CONTEXTO TÉCNICO ===

SOFTWARE LEGACY:
- Nome: Inergetix Core 5.0
- Arquitetura: 32-bit (x86)
- DLL Antiga: hs3.dll (data: 16/10/2009, tamanho: 503 KB)
- API Antiga: ADC_Start, ADC_Stop, SetMeasureMode, SetSampleFrequency, etc.

HARDWARE:
- Modelo: TiePie HandyScope HS3
- Serial: [INSERIR SERIAL DO TEU HS3]
- USB: VID/PID detecção funcional

PROBLEMA:
Após instalação do driver moderno TiePie, o software Inergetix Core deixou de
funcionar (incompatibilidade API antiga vs driver novo).

=== SOLUÇÃO PROPOSTA ===

Criar DLL wrapper (hs3.dll) que:
1. Exporta API antiga (compatível com Inergetix Core)
2. Internamente chama libtiepie-hw SDK moderno
3. Traduz conceitos antigos → novos (ex: ADC_Start → tiepie_hw_oscilloscope_start)

=== PEDIDO SDK ===

Necessitamos urgentemente:

1. libtiepie-hw SDK COMPLETO para 32-bit (x86):
   - Headers C/C++ (libtiepie-hw.h)
   - Import Library (libtiepie-hw.lib para x86)
   - Runtime DLL (libtiepie-hw.dll 32-bit)
   - Documentação API (referência completa)

2. Informações adicionais:
   - Lista oficial de funções exportadas pela hs3.dll antiga (se disponível)
   - Mapeamento API antiga → API nova (migration guide)
   - Exemplos de código para osciloscópio (básico: init, capture, read data)
   - Notas sobre diferenças arquiteturais (ordinais, calling conventions)

3. Licenciamento:
   - Este wrapper será usado em software médico comercial (BioDeskPro2)
   - Qual o custo de licença SDK para uso comercial?
   - Existem restrições de distribuição do libtiepie-hw.dll?

=== QUESTÕES CRÍTICAS ===

1. O libtiepie-hw SDK tem versão 32-bit (x86) disponível?
   (Se só existir 64-bit, wrapper não será viável)

2. É possível ter driver ANTIGO (Inergetix) e driver NOVO (BioDeskPro2)
   coexistirem na mesma máquina? (não simultâneo, mas instalados)

3. Têm documentação sobre hs3.dll legacy API? (exports, ordinais, assinaturas)

4. Suportam desenvolvimento de wrappers de compatibilidade?
   (ou preferem outra abordagem técnica?)

=== TIMELINE ===

Desenvolvimento wrapper: 2-3 semanas após receção SDK
Testes com Inergetix Core: 1 semana
Deployment produção: Dezembro 2025

=== INFORMAÇÕES ADICIONAIS ===

- País: Portugal
- Sector: Software médico (terapias bioenergéticas)
- Contacto urgente: nfjpc@[INSERIR EMAIL]
- Telefone: [INSERIR TELEFONE]

Agradecemos resposta urgente (pacientes aguardam funcionalidade).

Melhores cumprimentos,
Nuno Correia
BioDeskPro2 Development Team
```

---

## 📨 VERSÃO INGLESA (mais formal)

```
To: support@tiepie.com
Cc: sales@tiepie.com
Subject: SDK Request - HandyScope HS3 Legacy Compatibility Wrapper (32-bit x86)

Dear TiePie Support Team,

We are developing a compatibility wrapper (DLL shim) to enable legacy medical
software (Inergetix Core 5.0) to continue operating with modern TiePie HandyScope
HS3 drivers.

=== TECHNICAL CONTEXT ===

LEGACY SOFTWARE:
- Name: Inergetix Core 5.0
- Architecture: 32-bit (x86) Windows application
- Original DLL: hs3.dll (dated 16/10/2009, 503 KB)
- Legacy API: ADC_Start, ADC_Stop, SetMeasureMode, SetSampleFrequency,
  ADC_GetDataVoltCh, SetTriggerSource, etc.

HARDWARE:
- Model: TiePie HandyScope HS3 USB Oscilloscope
- Serial Number: [INSERT YOUR HS3 SERIAL]
- USB Detection: VID/PID functional

ISSUE:
After installing the modern TiePie driver, Inergetix Core stopped functioning
due to API incompatibility (legacy hs3.dll vs. new libtiepie-hw).

=== PROPOSED SOLUTION ===

Create a wrapper DLL (hs3.dll replacement) that:
1. Exports the original legacy API (Inergetix Core compatible)
2. Internally calls modern libtiepie-hw SDK
3. Translates old concepts → new API calls
   Example: ADC_Start() → tiepie_hw_oscilloscope_start()

Template implementation already prepared (C++ with .def file for ordinals).

=== SDK REQUEST ===

We urgently require:

1. libtiepie-hw SDK COMPLETE for 32-bit (x86):
   - C/C++ headers (libtiepie-hw.h)
   - Import library (libtiepie-hw.lib for x86 architecture)
   - Runtime DLL (libtiepie-hw.dll 32-bit version)
   - API documentation (complete reference)

2. Migration Information:
   - Official list of exported functions from legacy hs3.dll (if available)
   - API mapping guide (old → new function equivalents)
   - Sample code for basic oscilloscope operations (init, capture, data read)
   - Notes on architectural differences (ordinals, calling conventions)

3. Licensing Information:
   - Wrapper will be used in commercial medical software (BioDeskPro2)
   - What is the SDK license cost for commercial use?
   - Are there redistribution restrictions for libtiepie-hw.dll?

=== CRITICAL QUESTIONS ===

1. Does libtiepie-hw SDK have a 32-bit (x86) version available?
   (If only 64-bit exists, wrapper approach is not viable)

2. Can OLD driver (Inergetix) and NEW driver (BioDeskPro2) coexist
   on the same machine? (not simultaneously, but both installed)

3. Do you have documentation for the legacy hs3.dll API?
   (exports, ordinals, function signatures)

4. Do you support compatibility wrapper development?
   (or would you recommend a different technical approach?)

=== DEVELOPMENT TIMELINE ===

Wrapper development: 2-3 weeks after SDK reception
Inergetix Core testing: 1 week
Production deployment: December 2025

=== CONTACT INFORMATION ===

- Country: Portugal
- Sector: Medical software (bioenergetic therapies)
- Urgent contact: nfjpc@[INSERT EMAIL]
- Phone: [INSERT PHONE]
- Alternative: [GitHub/Website if applicable]

We would greatly appreciate an urgent response as patients are awaiting
this functionality.

Best regards,
Nuno Correia
BioDeskPro2 Development Team
Portugal
```

---

## 📋 CHECKLIST PRÉ-ENVIO

Antes de enviar email, completar:

- [ ] Inserir **serial number do HS3** (ver etiqueta no dispositivo)
- [ ] Inserir **teu email de contacto**
- [ ] Inserir **telefone** (opcional mas recomendado)
- [ ] Verificar **anexos** (se quiseres enviar screenshot ou logs)
- [ ] Decidir **idioma** (Inglês = mais profissional, PT = se preferires)

---

## 🎯 O QUE ESPERAR DA RESPOSTA

### ✅ **Resposta POSITIVA** (ideal):
```
- SDK 32-bit disponível para download
- Link para documentação
- Preço de licença comercial (ou grátis)
- Timeline de entrega: 1-5 dias úteis
```

**Próximo passo**: Começar desenvolvimento wrapper (20-40h).

---

### ⚠️ **Resposta NEUTRA** (comum):
```
- SDK só disponível em 64-bit
- Ou: SDK não disponível para distribuição pública
- Ou: Licença comercial muito cara (>€5.000)
```

**Próximo passo**: Avaliar alternativas (Core como backend, terapia por som).

---

### ❌ **Resposta NEGATIVA** (pior caso):
```
- Não suportam wrappers
- API legacy descontinuada
- Sem documentação disponível
```

**Próximo passo**: Abandonar wrapper, focar em Opção C ou D (ver AVALIACAO_REALISTA).

---

## 💡 DICAS DE COMUNICAÇÃO

### ✅ **FAZER**:
- Ser profissional e técnico (demonstras conhecimento)
- Mencionar "medical software" (aumenta prioridade)
- Pedir "urgent response" (justificado - pacientes esperam)
- Oferecer testar beta/RC do SDK (se existir)

### ❌ **NÃO FAZER**:
- Mencionar "reverse engineering" (soa negativo)
- Pedir "free license" logo de início (negociar depois)
- Criticar driver antigo (manter tom neutro)
- Enviar código stub/fake (esperar SDK oficial primeiro)

---

## 📅 FOLLOW-UP

**Se não responderem em 3 dias úteis**:
```
Subject: RE: SDK Request - HandyScope HS3 (Follow-up)

Dear Team,

I am following up on my SDK request sent on [DATA].

Our development timeline is tight and we need to decide this week
whether to:
A) Proceed with wrapper approach (requires SDK)
B) Pursue alternative architecture

Could you please provide initial feedback on SDK availability?

Best regards,
Nuno
```

**Se não responderem em 7 dias**:
- Tentar via LinkedIn (procurar "TiePie Engineering" ou "Support Lead")
- Tentar via formulário website TiePie
- Considerar alternativas (Opção C/D)

---

## 🔗 LINKS ÚTEIS (anexar no email se quiseres)

- Template código wrapper: [anexar ANALISE_SOLUCAO_WRAPPER_HS3_22OUT2025.md]
- Análise técnica completa: [anexar se TiePie pedir detalhes]
- Screenshot erro atual: [capturar log "VID/PID incorreto"]

---

**Data criação**: 22/10/2025
**Status**: ✅ PRONTO PARA ENVIAR
**Próxima ação**: Copiar email, preencher dados pessoais, ENVIAR
