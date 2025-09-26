# 🚀 COMANDOS PARA CONECTAR AO GITHUB

## ⚠️ PRIMEIRO: CRIAR REPOSITÓRIO NO GITHUB
1. https://github.com → Login
2. New repository → Nome: BioDeskPro2-Medical-System
3. ✅ Private ❌ Add README
4. Create repository
5. **COPIAR A URL** que aparece!

## 🔗 DEPOIS: CONECTAR NO PC ATUAL
```bash
# SUBSTITUIR "SUA_URL" pela URL real do GitHub:
git remote add origin SUA_URL_AQUI

# Exemplo (substituir pelo teu username):  
git remote add origin https://github.com/teu_username/BioDeskPro2-Medical-System.git

# Enviar código para GitHub:
git branch -M main
git push -u origin main
```

## ✅ VERIFICAR SUCESSO:
Ir ao GitHub → ver se apareceram 87+ ficheiros

## 🎯 DEPOIS NO NOVO PC:
```bash
# Substituir pela TUA URL:
git clone https://github.com/teu_username/BioDeskPro2-Medical-System.git
cd BioDeskPro2-Medical-System  
.\SETUP_NOVO_PC.bat
```