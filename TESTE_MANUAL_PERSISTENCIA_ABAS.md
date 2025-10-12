# 🧪 TESTE MANUAL - Persistência Estado Abas
**Data**: 12 de Outubro de 2025  
**Feature**: Sprint 2 - Tarefa 6/6  
**Commit**: `8e4697b`

---

## ✅ VERIFICAÇÕES AUTOMÁTICAS

### 1. Build Status
```bash
dotnet build
# Result: 0 Errors, 24 Warnings (apenas AForge)
# Status: ✅ SUCESSO
```

### 2. Migração Aplicada
```bash
dotnet ef migrations list
# Result: 20251012164743_AddLastActiveTabToPaciente
# Status: ✅ APLICADA
```

### 3. Base de Dados
```
Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db
Size: 348 KB
Status: ✅ EXISTENTE
```

### 4. Coluna Criada
```sql
ALTER TABLE "Pacientes" ADD "LastActiveTab" INTEGER NOT NULL DEFAULT 1;
# Status: ✅ EXECUTADO
```

---

## 📱 TESTE MANUAL - PASSO A PASSO

### Cenário 1: Persistência Básica

**Objetivo**: Verificar se a última aba visitada é restaurada ao reabrir paciente.

#### Passos:
1. ✅ **Aplicação está a executar** (PID: Verificar com Task Manager)
2. 🖱️ **Abrir Dashboard**
3. 🖱️ **Selecionar qualquer paciente** (ex: "Ana Silva")
4. 🖱️ **Navegar para Aba 5 (📊 Irisdiagnóstico)**
5. ⏱️ **Aguardar 2 segundos** (auto-save em background)
6. 🖱️ **Voltar ao Dashboard** (botão "Voltar" ou fechar ficha)
7. 🖱️ **Reabrir o mesmo paciente** ("Ana Silva")

#### Resultado Esperado:
✅ **Paciente deve abrir diretamente na Aba 5 (Irisdiagnóstico)**

#### Se falhar:
❌ Verificar logs no console da aplicação (procurar "💾 Aba 5 salva")

---

### Cenário 2: Múltiplas Navegações

**Objetivo**: Verificar se sempre guarda a última aba, não a primeira.

#### Passos:
1. 🖱️ Abrir paciente "Carlos Mendes"
2. 🖱️ Navegar para **Aba 3 (Consentimentos)** → aguardar 2s
3. 🖱️ Navegar para **Aba 6 (Comunicação)** → aguardar 2s
4. 🖱️ Navegar para **Aba 2 (Saúde)** → aguardar 2s
5. 🖱️ Fechar ficha
6. 🖱️ Reabrir "Carlos Mendes"

#### Resultado Esperado:
✅ **Deve abrir na Aba 2 (Saúde)** - última visitada

---

### Cenário 3: Pacientes Diferentes

**Objetivo**: Verificar se cada paciente guarda sua própria aba.

#### Passos:
1. 🖱️ Abrir "Ana Silva" → Navegar para **Aba 5** → Fechar
2. 🖱️ Abrir "Carlos Mendes" → Navegar para **Aba 3** → Fechar
3. 🖱️ Abrir "Beatriz Costa" → Navegar para **Aba 7** → Fechar
4. 🖱️ **Reabrir "Ana Silva"** → Deve estar na **Aba 5**
5. 🖱️ **Reabrir "Carlos Mendes"** → Deve estar na **Aba 3**
6. 🖱️ **Reabrir "Beatriz Costa"** → Deve estar na **Aba 7**

#### Resultado Esperado:
✅ **Cada paciente mantém sua própria aba independentemente**

---

### Cenário 4: Novo Paciente

**Objetivo**: Verificar default (Aba 1) para pacientes novos.

#### Passos:
1. 🖱️ Criar **novo paciente** (botão "Novo Paciente")
2. 🖱️ Preencher dados mínimos (Nome, Género)
3. 🖱️ Salvar paciente
4. 🖱️ Voltar ao Dashboard
5. 🖱️ Reabrir o paciente recém-criado

#### Resultado Esperado:
✅ **Deve abrir na Aba 1 (Dados)** - default para novos pacientes

---

## 🔍 LOGS ESPERADOS

### Console da Aplicação
Ao mudar de aba, deve aparecer:
```
🔄 ABA MUDOU: Aba ativa agora é 5
💾 Aba 5 salva para paciente 1
```

### Se houver erro:
```
⚠️ Erro ao salvar LastActiveTab: [detalhes do erro]
```

---

## 📊 VERIFICAÇÃO BASE DE DADOS (OPCIONAL)

### Via DB Browser for SQLite:
1. Abrir `biodesk.db`
2. Tabela `Pacientes`
3. Coluna `LastActiveTab` deve existir
4. Valores devem estar entre 1-8

### Query SQL:
```sql
SELECT Id, NomeCompleto, LastActiveTab 
FROM Pacientes 
ORDER BY Id 
LIMIT 5;
```

**Resultado esperado**:
```
1 | Ana Silva          | 1
2 | Carlos Mendes      | 1
3 | Beatriz Costa      | 1
4 | (novo paciente)    | 1-8
```

---

## ✅ CRITÉRIOS DE SUCESSO

- [ ] Cenário 1: Aba 5 restaurada após reabrir
- [ ] Cenário 2: Última aba (não primeira) restaurada
- [ ] Cenário 3: Cada paciente tem sua própria aba
- [ ] Cenário 4: Novos pacientes abrem na Aba 1
- [ ] Zero crashes durante testes
- [ ] Logs de debug aparecem corretamente

---

## 🐛 TROUBLESHOOTING

### Problema: Sempre abre na Aba 1
**Possível causa**: Auto-save não está a executar  
**Solução**: Verificar logs, aguardar 2+ segundos após mudar aba

### Problema: Erro ao salvar
**Possível causa**: Paciente ainda não foi salvo (Id = 0)  
**Solução**: Normal, só salva para pacientes existentes

### Problema: Aplicação não executa
**Solução**: 
```bash
dotnet build
dotnet run --project src/BioDesk.App
```

---

## 📝 RELATÓRIO DE TESTE

**Testador**: _______________________  
**Data**: 12/10/2025  

| Cenário | Status | Observações |
|---------|--------|-------------|
| 1. Persistência Básica | ⬜ PASS / ⬜ FAIL | |
| 2. Múltiplas Navegações | ⬜ PASS / ⬜ FAIL | |
| 3. Pacientes Diferentes | ⬜ PASS / ⬜ FAIL | |
| 4. Novo Paciente | ⬜ PASS / ⬜ FAIL | |

**Bugs encontrados**: _______________________________________________

**Aprovação**: ⬜ SIM / ⬜ NÃO

---

**Assinatura**: __________________ **Data**: __/__/____
