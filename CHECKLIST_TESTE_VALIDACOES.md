# ✅ CHECKLIST DE TESTE - VALIDAÇÕES EM TEMPO REAL

## 🎯 OBJETIVO
Verificar que as 5 validações implementadas funcionam corretamente com feedback visual imediato.

---

## 📋 INSTRUÇÕES DE TESTE

### ⚙️ **PREPARAÇÃO**
1. ✔️ Aplicação a correr (dashboard visível)
2. ✔️ Clicar em **"Novo Paciente"** (Ctrl+N)
3. ✔️ Verificar que aba **"Dados Biográficos"** está ativa

---

## 🧪 TESTE 1: NOME COMPLETO

### **Cenário 1.1: Nome muito curto**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "Jo" no campo **Nome Completo** | ⚠️ Aparece texto vermelho: "Nome deve ter pelo menos 3 caracteres (atual: 2/3)" |
| 2 | Adicionar "ão" → "João" | ✅ Erro desaparece automaticamente |

### **Cenário 1.2: Nome vazio**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Limpar campo **Nome Completo** | ⚠️ Aparece: "Nome obrigatório" |
| 2 | Digitar "Ana Silva" | ✅ Erro desaparece |

✅ **TESTE 1 PASSOU:** [ ]

---

## 🧪 TESTE 2: DATA DE NASCIMENTO

### **Cenário 2.1: Campo inicialmente vazio**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Abrir novo paciente | ✅ Campo **Data Nascimento** deve estar vazio |
| 2 | Não preencher | ✅ Sem erro (campo não é obrigatório inicialmente) |

### **Cenário 2.2: Data futura**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Selecionar data de amanhã | ⚠️ Aparece: "Data de nascimento não pode estar no futuro" |
| 2 | Selecionar data de hoje | ⚠️ Aparece: "Data de nascimento não pode estar no futuro" |
| 3 | Selecionar data de ontem | ✅ Erro desaparece |

### **Cenário 2.3: Data muito antiga**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Selecionar 01/01/1900 | ⚠️ Aparece: "Data de nascimento inválida (idade superior a 120 anos)" |
| 2 | Selecionar 01/01/1990 | ✅ Erro desaparece |

✅ **TESTE 2 PASSOU:** [ ]

---

## 🧪 TESTE 3: NIF (PORTUGAL)

### **Cenário 3.1: NIF com letras**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "12345678A" no campo **NIF** | ⚠️ Aparece: "NIF deve conter apenas números" |

### **Cenário 3.2: NIF com tamanho errado**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "123" | ⚠️ Aparece: "NIF deve ter 9 dígitos (3/9)" |
| 2 | Digitar "12345678" | ⚠️ Aparece: "NIF deve ter 9 dígitos (8/9)" |

### **Cenário 3.3: NIF com dígito de controlo inválido**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "123456789" | ⚠️ Aparece: "NIF inválido (dígito de controlo incorreto)" |

### **Cenário 3.4: NIF válido**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "123456780" | ✅ Erro desaparece (dígito válido) |
| 2 | OU digitar "111111118" | ✅ Erro desaparece |

**NIFs Válidos para Teste:**
- `111111118` (todos 1s + checkdigit 8)
- `123456780` (sequência válida)
- `222222221` (todos 2s + checkdigit 1)

✅ **TESTE 3 PASSOU:** [ ]

---

## 🧪 TESTE 4: TELEFONE PRINCIPAL

### **Cenário 4.1: Telefone com tamanho errado**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "91234" no campo **Telefone Principal** | ⚠️ Aparece: "Telefone deve ter 9 dígitos (5/9)" |

### **Cenário 4.2: Telefone com prefixo inválido**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "812345678" | ⚠️ Aparece: "Telefone deve começar com 2 ou 9" |

### **Cenário 4.3: Telefones válidos**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "912345678" (móvel) | ✅ Erro desaparece |
| 2 | Limpar e digitar "212345678" (fixo) | ✅ Erro desaparece |

**Telefones Válidos para Teste:**
- `912345678` (móvel - inicia com 9)
- `212345678` (fixo - inicia com 2)
- `966666666` (móvel - inicia com 9)

✅ **TESTE 4 PASSOU:** [ ]

---

## 🧪 TESTE 5: EMAIL

### **Cenário 5.1: Email sem @**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "joaosilva" no campo **Email** | ⚠️ Aparece: "Email deve conter @" |

### **Cenário 5.2: Email sem domínio**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "joao@" | ⚠️ Aparece: "Email deve ter formato nome@dominio" |
| 2 | Digitar "joao@gmail" | ⚠️ Aparece: "Email deve ter formato nome@dominio.ext" |

### **Cenário 5.3: Email válido**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Digitar "joao@gmail.com" | ✅ Erro desaparece |

**Emails Válidos para Teste:**
- `joao.silva@gmail.com`
- `teste@outlook.pt`
- `contacto@biodesk.pt`

✅ **TESTE 5 PASSOU:** [ ]

---

## 🔄 TESTE 6: INTEGRAÇÃO COMPLETA

### **Cenário 6.1: Preencher ficha completa com erros**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Novo paciente | ✅ Todos os campos vazios |
| 2 | Nome: "Jo" | ⚠️ Erro nome |
| 3 | NIF: "123" | ⚠️ Erro NIF |
| 4 | Email: "teste@" | ⚠️ Erro email |
| 5 | Telefone: "91234" | ⚠️ Erro telefone |
| 6 | **Verificar 4 erros visíveis simultaneamente** | ⚠️ 4 mensagens vermelhas visíveis |

### **Cenário 6.2: Corrigir todos os erros**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Nome: "João Silva" | ✅ Erro 1 desaparece |
| 2 | NIF: "123456780" | ✅ Erro 2 desaparece |
| 3 | Email: "joao@gmail.com" | ✅ Erro 3 desaparece |
| 4 | Telefone: "912345678" | ✅ Erro 4 desaparece |
| 5 | **Verificar que TODOS os erros desapareceram** | ✅ Sem mensagens vermelhas |

### **Cenário 6.3: Guardar com dados válidos**
| Passo | Ação | Resultado Esperado |
|-------|------|-------------------|
| 1 | Clicar **"Guardar Paciente"** (Ctrl+S) | ✅ Guarda sem erros |
| 2 | Verificar mensagem sucesso | ✅ "Paciente guardado com sucesso" |

✅ **TESTE 6 PASSOU:** [ ]

---

## 📊 RESUMO DE RESULTADOS

| Teste | Status | Observações |
|-------|--------|-------------|
| 1. Nome Completo | [ ] | |
| 2. Data Nascimento | [ ] | |
| 3. NIF | [ ] | |
| 4. Telefone | [ ] | |
| 5. Email | [ ] | |
| 6. Integração | [ ] | |

---

## 🐛 PROBLEMAS ENCONTRADOS

### **Problema 1:**
**Descrição:**
_[Descrever o problema encontrado]_

**Passos para Reproduzir:**
1.
2.
3.

**Comportamento Esperado:**
_[O que deveria acontecer]_

**Comportamento Atual:**
_[O que está a acontecer]_

---

### **Problema 2:**
_(Copiar estrutura acima se necessário)_

---

## ✅ APROVAÇÃO FINAL

**Data do Teste:** ___________
**Testado por:** ___________

**Resultado Global:**
- [ ] ✅ Todos os testes passaram - APROVADO
- [ ] ⚠️ Testes passaram com observações - APROVADO COM RESSALVAS
- [ ] ❌ Alguns testes falharam - NECESSITA CORREÇÕES

**Observações Finais:**
_______________________________________
_______________________________________
_______________________________________

---

**Próximo Passo Sugerido:**
Se todos os testes passarem, implementar **Contador de Pendências no Dashboard** conforme solicitado.
