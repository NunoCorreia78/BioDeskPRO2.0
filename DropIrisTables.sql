-- Script para remover tabelas Iris problemáticas
PRAGMA foreign_keys = OFF;

DROP TABLE IF EXISTS IrisMarcas;
DROP TABLE IF EXISTS IrisImagens;

PRAGMA foreign_keys = ON;

-- Verificar tabelas restantes
SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Iris%';
