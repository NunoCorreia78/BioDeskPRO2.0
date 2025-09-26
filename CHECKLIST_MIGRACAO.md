# ✅ CHECKLIST MIGRAÇÃO PC - BioDeskPro2

## 📦 ANTES DE MIGRAR:
- [ ] Fechar aplicação WPF se estiver a correr
- [ ] Verificar que `biodesk.db` existe na pasta do projeto
- [ ] Confirmar que `global.json` está na raiz
- [ ] Verificar `BioDeskPro2.sln` presente

## 🚚 TRANSFERÊNCIA:
- [ ] Copiar TODA a pasta `BioDeskPro2/` 
- [ ] Incluir todas as subpastas `src/`, `obj/`, `bin/`
- [ ] Não esquecer ficheiros ocultos `.gitignore`, `.editorconfig`
- [ ] Transferir via OneDrive/USB/Git

## 💻 NOVO PC SETUP:
- [ ] Instalar .NET 8 SDK
- [ ] Instalar Visual Studio Code
- [ ] Instalar extensão C# Dev Kit
- [ ] (Opcional) SQLite Browser para ver BD

## 🔨 PRIMEIRO BUILD:
```bash
□ cd "[CAMINHO]\BioDeskPro2"
□ dotnet restore
□ dotnet build
□ Verificar: "Build succeeded. 0 Warning(s) 0 Error(s)"
```

## 🧪 TESTE FUNCIONAL:
```bash
□ dotnet run --project src/BioDesk.App
□ Aplicação abre no Dashboard
□ Clicar ➕ Novo Paciente  
□ FichaPaciente carrega
□ Clicar TAB 2: 📋 Declaração & Anamnese
□ Aparecem 11 EXPANDERS coloridos
□ Testar 1-2 chips clicáveis
□ Testar 1 slider (intensidade dor)
□ Verificar botões 📝🔄📄 visíveis
```

## 🚨 SE DER ERRO:
- [ ] **Build Error**: `dotnet clean` → `dotnet restore` → `dotnet build`
- [ ] **BD Error**: Apagar `biodesk.db` (regenera automaticamente)
- [ ] **Permissões**: Executar terminal como Administrador
- [ ] **.NET Missing**: Instalar .NET 8 SDK
- [ ] **Expanders Missing**: Confirmar TAB 2 (não Dashboard!)

## ✅ MIGRAÇÃO COMPLETA:
- [ ] Build 100% clean
- [ ] Aplicação executa
- [ ] 11 Expanders funcionais  
- [ ] Interface médica operacional
- [ ] Pronto para desenvolvimento!

## 📋 DOCUMENTAÇÃO:
- [ ] `MIGRACAO_PC_COMPLETA.md` - Guia detalhado
- [ ] `SETUP_RAPIDO.md` - Comandos rápidos
- [ ] Este checklist guardado

---
**Data**: ___/___/2025  
**PC**: _________________  
**Status**: □ Migração Completa ✅