# 📄 Template Placeholders - Criar PDFs Reais

Este diretório contém **ficheiros placeholder (.md)** que documentam a estrutura sugerida para cada template PDF.

## 🎯 Objetivo

Estes ficheiros `.md` servem como:
1. ✅ **Guia de conteúdo** para criar os PDFs reais
2. ✅ **Documentação** do que cada template deve conter
3. ✅ **Referência rápida** para design e formatação

## 📋 Templates a Criar

### ✅ Já Documentados
- [x] `Exercicios_Escoliose.md` → Criar `Exercicios_Escoliose.pdf`
- [x] `Plano_Alimentar_Cardiaco.md` → Criar `Plano_Alimentar_Cardiaco.pdf`

### 📝 Próximos (Adicionar)
- [ ] `Exercicios_Lombar.pdf` - Exercícios para região lombar
- [ ] `Exercicios_Cervical.pdf` - Exercícios para tensão cervical
- [ ] `Dieta_Anti_Inflamatoria.pdf` - Dieta anti-inflamatória
- [ ] `Plano_Detox_7_Dias.pdf` - Programa detox semanal
- [ ] `Prescricao_Naturopatica.pdf` - Template de prescrição
- [ ] `Prescricao_Fitoterapia.pdf` - Prescrição de plantas medicinais
- [ ] `Consentimento_Naturopatia.pdf` - Termo de consentimento
- [ ] `Consentimento_Osteopatia.pdf` - Consentimento osteopatia
- [ ] `Relatorio_Irisdiagnostico.pdf` - Relatório análise íris
- [ ] `Guia_Primeira_Consulta.pdf` - Info para novos pacientes

## 🔧 Workflow de Criação

### 1. Ler o ficheiro .md
Contém estrutura detalhada do conteúdo

### 2. Criar PDF usando Canva/Word/Google Docs
Seguir design guidelines (ver README.md)

### 3. Guardar como PDF
Nome **exato** (ex: `Exercicios_Escoliose.pdf`)

### 4. Colocar na pasta raiz `Templates/`
```
Templates/
├── README.md
├── Exercicios_Escoliose.pdf  ← PDF real
├── Exercicios_Escoliose.md   ← Documentação (pode manter ou apagar)
├── ...
```

### 5. Testar na aplicação
- Abrir BioDeskPro2
- Ficha paciente → Comunicação
- Carregar Templates
- Verificar que aparece na lista

## ⚠️ Importante

**Ficheiros .md são OPCIONAIS após criar os PDFs.**

Podes:
- ✅ **Manter** os `.md` como documentação
- ✅ **Apagar** os `.md` após criar os PDFs (sistema só lê `.pdf`)

O `TemplateService` apenas procura ficheiros com extensão `.pdf`:

```csharp
var files = Directory.GetFiles(_templatePath, "*.pdf");
```

---

**Boa sorte na criação dos templates!** 🎨
