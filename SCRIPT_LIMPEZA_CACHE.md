# 🧹 SCRIPT DE LIMPEZA CACHE - PREVENÇÃO AUTOMÁTICA

## Para adicionar ao .vscode/tasks.json

```json
{
    "label": "Limpar Cache WPF Completo",
    "type": "shell",
    "command": "powershell",
    "args": [
        "-Command",
        "Remove-Item -Recurse -Force 'src/*/bin/', 'src/*/obj/' -ErrorAction SilentlyContinue; Write-Host '🧹 Cache WPF limpo!'"
    ],
    "group": "build",
    "presentation": {
        "echo": true,
        "reveal": "always",
        "panel": "new"
    }
}
```

## USAR quando suspeitar de problemas de cache

1. **Comando manual rápido:**

   ```powershell
   Remove-Item -Recurse -Force 'src/*/bin/', 'src/*/obj/'
   ```

2. **Build limpo completo:**

   ```powershell
   dotnet clean
   Remove-Item -Recurse -Force 'src/*/bin/', 'src/*/obj/'
   dotnet restore
   dotnet build
   ```

## 🚨 SINAIS DE PROBLEMAS DE CACHE

- ✅ Binding funciona nos logs
- ✅ Converter retorna valores corretos
- ❌ UI não atualiza visualmente
- ❌ UserControls "misturados"
- ❌ Visibility=Collapsed não funciona

## 🛡️ PREVENÇÃO OBRIGATÓRIA

✅ **SEMPRE** usar Panel.ZIndex em UserControls sobrepostos
✅ **SEMPRE** usar Background="Transparent"
✅ **SEMPRE** testar navegação entre TODAS as abas
✅ **SEMPRE** limpar cache quando houver comportamento estranho

---

**REGRA DE OURO**: Quando o binding funciona mas a UI não corresponde = PROBLEMA DE CACHE!
