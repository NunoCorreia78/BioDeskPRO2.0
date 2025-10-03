# 📸 TestData - Imagens de Teste para Irisdiagnóstico

## Conteúdo

### `pseudo_iris_teste.jpg`
- **Descrição**: Imagem sintética de íris para testes
- **Dimensões**: 800x600px
- **Características**:
  - Pupila preta central (50px raio)
  - Íris castanha com gradiente (150px raio)
  - 5 manchas escuras aleatórias (para testar marcações)
  - 24 fibras radiadas (textura realista)
  - Reflexo de luz (realismo)
  - Fundo preto (esclerótica)

## Como Usar

### 1. Testar na Aplicação
1. Abrir BioDeskPro2
2. Ir para FichaPaciente → Irisdiagnóstico
3. Clicar "📁 Adicionar Imagem"
4. Selecionar `TestData/pseudo_iris_teste.jpg`
5. Testar:
   - Zoom (1.0x - 5.0x)
   - Adicionar marcas coloridas nas manchas
   - Editar observações
   - Exportar relatório

### 2. Gerar Nova Imagem
```powershell
cd TestData
.\GerarPseudoIris.ps1
```

## Próximos Passos

### Captura Via Iridoscópio USB
- [ ] Integrar com câmara USB (DirectShow/MediaFoundation)
- [ ] Botão "📷 Capturar do Iridoscópio"
- [ ] Preview em tempo real
- [ ] Ajuste de brilho/contraste antes de guardar
- [ ] Auto-detecção de dispositivo USB

### Melhorias da Imagem de Teste
- [ ] Adicionar variantes (íris verde, azul, avelã)
- [ ] Diferentes padrões de fibras
- [ ] Simular patologias comuns (heterocromia, anéis, manchas)
- [ ] Dataset com 10-20 imagens variadas

---

**Gerado**: 2 de outubro de 2025
**Script**: `GerarPseudoIris.ps1` (PowerShell + System.Drawing)
