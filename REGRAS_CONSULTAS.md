# 📋 REGRAS DE GESTÃO DE CONSULTAS - BioDeskPro2

**Data:** 12 de outubro de 2025  
**Versão:** 1.0  
**Aplicável a:** Aba 4 - Registo de Consultas/Sessões

---

## 🎯 PRINCÍPIO FUNDAMENTAL

> **As consultas são IMMUTABLE (imutáveis) após criação.**

Esta é uma decisão de arquitetura **intencional e permanente**, não um bug ou limitação técnica.

---

## 🔒 PORQUÊ CONSULTAS IMUTÁVEIS?

### **1. Conformidade Legal (RGPD e Regulamentação Clínica)**
- Registos clínicos devem ser **auditáveis** e **rastreáveis**
- Qualquer alteração deve criar **novo registo** com timestamp
- Histórico médico **não pode ser adulterado** retroativamente
- Exigência de **chain of custody** em caso de auditoria

### **2. Rastreabilidade Completa**
```
Consulta Original (10/10/2025 14:00)
├── Criada por: Dr. Nuno Correia
├── Motivo: "Dor lombar aguda"
└── Prescrição: "Ibuprofeno 400mg"

❌ PROIBIDO: Editar e perder histórico
✅ CORRETO: Criar nova consulta com correções
```

### **3. Integridade de Dados**
- Evita **perda acidental** de informação histórica
- Previne **conflitos de concorrência** (múltiplos utilizadores)
- Garante **backup/restore confiável**

### **4. Auditoria e Responsabilidade**
- Cada consulta tem **timestamp fixo** de criação
- Não é possível "apagar rastros" de diagnósticos
- Facilita **revisão peer-to-peer** e formação

---

## ✅ COMO TRABALHAR COM CONSULTAS IMMUTABLES

### **CENÁRIO 1: Erro de Digitação na Consulta**

❌ **NÃO FAZER:**
- Tentar editar consulta existente
- Apagar e recriar (perde timestamp original)

✅ **FAZER:**
1. Criar **nova consulta** com título: "Correção - [Data Original]"
2. No campo **Observações**, escrever:
   ```
   📝 CORREÇÃO da consulta de 10/10/2025 14:00
   Motivo original: "Dor lombar aguda"
   Correção: "Dor lombar crónica (há 6 meses)"
   ```
3. A consulta original permanece no histórico para auditoria

---

### **CENÁRIO 2: Informação Adicional Após Consulta**

❌ **NÃO FAZER:**
- Editar consulta passada

✅ **FAZER:**
1. Criar **nova entrada** com tipo "Nota Clínica" ou "Follow-up"
2. Referenciar consulta original:
   ```
   📌 Follow-up da consulta de 10/10/2025
   Paciente reportou melhoria de 70% após 3 dias de tratamento.
   Ajuste de dosagem: Ibuprofeno reduzido para 200mg.
   ```

---

### **CENÁRIO 3: Prescrição Errada**

❌ **NÃO FAZER:**
- Alterar prescrição emitida

✅ **FAZER:**
1. Criar **nova prescrição** corrigida
2. No campo **Observações Prescrição**, escrever:
   ```
   ⚠️ ANULA prescrição de 10/10/2025 14:30
   Motivo: Erro de dosagem (prescrito 400mg, correto é 200mg)
   Nova prescrição emitida: 10/10/2025 15:00
   ```
3. Ambas as prescrições ficam no histórico (importante para farmácias)

---

## 🛠️ FUNCIONALIDADES FUTURAS (Roadmap)

### **Em Desenvolvimento (Sprint 2):**
- ✅ **Botão "Duplicar Consulta"** - Criar nova consulta baseada em anterior
- ✅ **Templates de Follow-up** - Agilizar criação de notas complementares
- ✅ **Histórico Visual** - Timeline mostrando consultas relacionadas
- ✅ **Notas Rápidas** - Adicionar observações sem criar consulta completa

### **Planejado (Sprint 3):**
- ✅ **Versioning Explícito** - Consultas mostram "Versão 1.0", "Versão 2.0"
- ✅ **Diff Visual** - Comparar consultas relacionadas lado a lado
- ✅ **Audit Log** - Ver quem criou cada consulta e quando

---

## 📊 WORKAROUND ATUAL (Até Sprint 2)

### **DUPLICAR CONSULTA MANUALMENTE:**

1. **Abrir consulta** que queres "editar"
2. **Copiar informação** relevante (Ctrl+C)
3. Clicar **"Nova Consulta"** (botão verde)
4. **Colar informação** (Ctrl+V) nos campos desejados
5. **Modificar** o que precisa de correção
6. No campo **Observações**, escrever:
   ```
   📝 Baseado na consulta de [DATA ORIGINAL]
   Alterações: [descrever mudanças]
   ```
7. **Guardar** nova consulta

---

## 🔐 EXCEÇÕES (Apenas Administrador)

Em casos **extremamente raros** (ex: dados sensíveis incorretos, RGPD):
- Contactar **administrador do sistema**
- Administrador pode aceder à **base de dados SQLite** diretamente
- Alterações requerem **justificação escrita** e são registadas em log

**Ficheiro BD:** `BioDeskPro2.db` (pasta raiz aplicação)  
**Ferramenta:** DB Browser for SQLite

---

## 📚 REFERÊNCIAS TÉCNICAS

### **Entidades Afetadas:**
- `Sessao.cs` (Domain.Entities) - Representa consulta
- `RegistoConsultasViewModel.cs` - Lógica de criação
- `RegistoConsultasUserControl.xaml` - UI de registo

### **Campos Immutables:**
```csharp
public class Sessao
{
    public int Id { get; set; }                    // PK (auto-increment)
    public int PacienteId { get; set; }            // FK (não editar)
    public DateTime DataSessao { get; set; }       // Timestamp fixo
    public string Motivo { get; set; }             // Imutável após criação
    public string? Observacoes { get; set; }       // Imutável após criação
    public DateTime DataCriacao { get; set; }      // Audit trail
    // ... outros campos
}
```

### **Campos Editáveis (Exceções):**
- ✅ **`Paciente.TerapiaAtual`** - Atualiza automaticamente (campo "vivo")
- ✅ **`Paciente.Notas`** - Permite edição contínua (não é consulta)

---

## ⚠️ AVISOS IMPORTANTES

### **NÃO TENTAR:**
❌ Editar `BioDeskPro2.db` sem backup  
❌ Apagar consultas antigas para "limpar" histórico  
❌ Usar ferramentas externas sem conhecimento técnico  
❌ Alterar timestamps manualmente  

### **SEMPRE FAZER:**
✅ Criar **backup diário** da base de dados  
✅ Usar funcionalidades do sistema (não workarounds externos)  
✅ Documentar **motivo** de cada consulta criada  
✅ Seguir **fluxo de correção** descrito neste documento  

---

## 🆘 SUPORTE

**Dúvidas sobre esta regra?**
- Consultar: `copilot-instructions.md` (secção "Regras de Desenvolvimento")
- Issue Tracker: GitHub BioDeskPRO2.0
- Documentação Técnica: `PLANO_DESENVOLVIMENTO_RESTANTE.md`

**Relatórios de Bug:**
- Se encontrares forma de **editar consulta** sem autorização → reportar como **vulnerabilidade de segurança**

---

## 📝 HISTÓRICO DE MUDANÇAS

| Data | Versão | Alteração | Autor |
|------|--------|-----------|-------|
| 12/10/2025 | 1.0 | Documento inicial criado | GitHub Copilot |

---

**🎯 RESUMO EXECUTIVO:**
> Consultas são imutáveis por design legal e técnico. Para "editar", criar nova consulta referenciando a original. Funcionalidade "Duplicar Consulta" chegará no Sprint 2.

---

*Documento vivo - Atualizar conforme novas funcionalidades são implementadas.*
