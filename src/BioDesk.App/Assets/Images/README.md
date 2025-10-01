# Assets / Images

## 1. Logo da Clínica

**Ficheiro necessário**: `logo.png`

### Instruções:
1. Prepara o logo da tua clínica em alta resolução
2. Converte para PNG com fundo transparente (recomendado) ou branco
3. Dimensões recomendadas: **200x80 pixels** (horizontal) ou **120x120 pixels** (quadrado)
4. Guarda como: `logo.png` nesta pasta

### Formato:
- **Tipo**: PNG (preferencialmente com transparência)
- **Resolução**: Mínimo 150 DPI
- **Tamanho**: ~20-100 KB

---

## 2. Assinatura Digital

**Ficheiro necessário**: `assinatura.png`

### Instruções:
1. Digitaliza a tua assinatura (scanner ou foto de alta qualidade)
2. Converte para PNG com fundo transparente
3. Dimensões recomendadas: **400x150 pixels** (ou similar proporcional)
4. Guarda como: `assinatura.png` nesta pasta

### Formato:
- **Tipo**: PNG com transparência
- **Resolução**: Mínimo 300 DPI para impressão
- **Tamanho**: ~50-200 KB

### Alternativa temporária:
Enquanto não tiveres a assinatura digitalizada, a aplicação usa um placeholder de texto:
```
_______________________
Dr. [Seu Nome]
Naturopata - Cédula XXXX
```

### Configuração no projeto:
O ficheiro é embedido na aplicação via `BioDesk.App.csproj`:
```xml
<ItemGroup>
  <Resource Include="Assets\Images\assinatura.png" />
</ItemGroup>
```
