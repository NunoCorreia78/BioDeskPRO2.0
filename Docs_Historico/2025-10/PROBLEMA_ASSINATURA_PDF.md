# 🐛 PROBLEMA: Assinatura não aparece no PDF de Consentimentos

**Data**: 01/10/2025 22:00
**Status**: 🔴 EM INVESTIGAÇÃO (Task #5)

## 📋 Contexto

Implementação completa de captura e renderização de assinaturas em PDFs:
- ✅ Captura do canvas como PNG/Base64 implementada
- ✅ Propriedade `AssinaturaDigitalBase64` criada no ViewModel
- ✅ Dados passados ao PDF Service
- ✅ Código de renderização QuestPDF implementado
- ❌ **Assinatura NÃO aparece no PDF final**

## 🖼️ Screenshot do Problema

O PDF mostra apenas:
```
_________________________________
Profissional Responsável
BioDeskPro 2.0
```

Esperado:
- **Lado esquerdo**: Imagem da assinatura do paciente (desenho capturado)
- **Lado direito**: Imagem da assinatura do terapeuta (Assets/Images/assinatura.png)

## 🔍 Pontos a Investigar

### 1. Verificar se Base64 está a ser capturado
**Ficheiro**: `ConsentimentosUserControl.xaml.cs`
**Método**: `CapturarAssinaturaComoImagem()`
- Adicionar log para verificar tamanho da string Base64
- Confirmar que `RenderTargetBitmap` está a funcionar
- Verificar se canvas tem conteúdo no momento da captura

### 2. Verificar se valor chega ao ViewModel
**Ficheiro**: `ConsentimentosUserControl.xaml.cs`
**Linha**: ~540 - `viewModel.AssinaturaDigitalBase64 = assinaturaBase64;`
- Adicionar log antes e depois da atribuição
- Confirmar que ViewModel não é null

### 3. Verificar se valor é passado ao PDF Service
**Ficheiro**: `ConsentimentosViewModel.cs`
**Linha**: ~580 - `AssinaturaDigitalBase64 = AssinaturaDigitalBase64`
- Adicionar log do valor que está a ser passado
- Confirmar que não é null ou vazio

### 4. Verificar renderização QuestPDF
**Ficheiro**: `ConsentimentoPdfService.cs`
**Linha**: ~245 - `if (!string.IsNullOrEmpty(dados.AssinaturaDigitalBase64))`
- Adicionar log para verificar se entra no bloco IF
- Verificar se conversão Base64 → byte[] funciona
- Confirmar que QuestPDF aceita o formato PNG

## 🛠️ Ações Propostas

1. **Debug Pass 1**: Adicionar logs em todos os pontos críticos
2. **Debug Pass 2**: Adicionar MessageBox temporário para ver valor Base64
3. **Debug Pass 3**: Guardar imagem PNG em ficheiro temporário para confirmar captura
4. **Fix**: Corrigir o problema identificado

## 📝 Notas Adicionais

### Outras Melhorias Necessárias (Task #6)
- ❌ Logo errado nos PDFs (usar Assets/Images/Logo.png)
- ❌ Menção "BioDeskPro 2.0" → Mudar para "Nuno Correia - Terapias Naturais"
- ❌ Campo "Duração do Tratamento: 30 dias" aparece sem controlo no modal
- ✅ Código de assinatura do terapeuta funciona (ficheiro estático)

## 🔄 Estado do Repositório

**Commit**: `f4cca2b`
**Branch**: `copilot/vscode1759173130560`
**Push**: ✅ Realizado com sucesso
**Backup BD**: biodesk.db (176KB, 01/10/2025 20:58)

---

**Próximo Passo**: Task #5 - Debug completo do fluxo de assinatura
