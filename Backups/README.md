# 💾 Backups da Base de Dados

Esta pasta contém backups timestamped da base de dados SQLite.

## Política de Backups

- **Automático**: Backup antes de operações críticas (migrations, bulk updates)
- **Manual**: Backup via script ou interface
- **Retenção**: Manter últimos 7 dias

## Formato de Nome

```
biodesk_backup_[descrição]_AAAAMMDD_HHMMSS.db
```

**Exemplo:**
```
biodesk_backup_iris_crop_20251007_194719.db
```

## Restaurar Backup

```powershell
# Parar aplicação
# Substituir biodesk.db pelo backup desejado
Copy-Item "Backups\biodesk_backup_AAAAMMDD_HHMMSS.db" "biodesk.db" -Force
# Reiniciar aplicação
```

## Nota

Backups não fazem parte do repositório Git (excluídos via .gitignore).
