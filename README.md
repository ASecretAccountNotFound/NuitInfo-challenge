# NuitInfo CTF Challenges

Ce repository contient 5 challenges de sécurité informatique pour le CTF NuitInfo.

## 🚀 Lancement rapide

Pour lancer tous les challenges en une fois :

```bash
docker-compose up --build
```

Pour lancer un challenge spécifique :

```bash
cd challengeX-name/pub  # ou challengeX-name pour challenge5
docker-compose up --build
```

---

## 📋 Liste des challenges

### Challenge 1: SQL Injection

**Port:** `80`  
**Flag:** `FLAG{SQHELL_h0p3_Y0u_d1d_it_a_la_mano_sinon_tocard}`  
**Description:** Un développeur a oublié de faire des requêtes préparées et a directement concaténé les entrées utilisateur dans ses requêtes SQL. Montrez-lui pourquoi c'est une mauvaise idée.

**Fichiers à donner aux joueurs:**
- Accès à l'application web sur le port 6000

**Lancement:**
```bash
cd challenge1-sqli/pub
docker-compose up --build
```

---

### Challenge 2: CVE Exploitation avec Metasploit

**Port:** `21` (FTP)  
**Flag:** `FLAG{3xpl01t_4_CV3_W1th_M3t4sploit_Is_easy_nah?}`  
**Description:** Un serveur FTP qui n'a pas été mis à jour depuis 2011 traîne quelque part. Trouvez-le et montrez-lui pourquoi les backdoors c'est pas cool.

**Fichiers à donner aux joueurs:**
- Accès au serveur FTP sur le port 21
- Indication d'utiliser Metasploit

**Lancement:**
```bash
cd challenge2-cve-metasploit/pub
docker-compose up --build
```

**Note:** Ce challenge utilise `network_mode: host`, le port FTP sera directement accessible sur le port 21 de l'hôte.

---

### Challenge 3: ret2win (64-bit)

**Port:** `1337`  
**Flag:** `FLAG{R3tUrn_To_Th3_W1n}`  
**Description:** Un développeur a créé un programme qui lit 256 caractères dans un buffer de 64. Il y a même une fonction `win()` qui affiche le flag, mais personne ne sait comment l'appeler...

**Fichiers à donner aux joueurs:**
- `vuln.c` (code source)
- Accès au binaire via netcat sur le port 1337

**Code source (`vuln.c`):**
```c
#include <stdio.h>
#include <string.h>

void win() {
    FILE *fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        printf("Error: could not open flag.txt\n");
        return;
    }
    char flag[64];
    fgets(flag, sizeof(flag), fp);
    printf("%s", flag);
    fclose(fp);
}

int main() {
    char buffer[64];
    printf("Enter your name: ");
    fgets(buffer, 256, stdin);
    printf("Hello, %s", buffer);
    return 0;
}
```

**Lancement:**
```bash
cd challenge3-ret2win/pub
docker-compose up --build
```

---

### Challenge 4: ret2libc (32-bit)

**Port:** `1338`  
**Flag:** `FLAG{R3T2L1BC_deadbeef}`  
**Description:** Un tocard de développeur a développé une appli en C pour s'entraîner. Testez son application et obtenez un shell pour lui prouver que c'est qu'un tocard.

**Fichiers à donner aux joueurs:**
- `vuln.c` (code source)
- Accès au binaire via netcat sur le port 1338

**Code source (`vuln.c`):**
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vuln() {
    char buffer[64];
    printf("Enter your input: ");
    fgets(buffer,300,stdin);
    printf("You entered: %s\n", buffer);
}

int main() {
    char *sh_path = "/bin/sh";
    printf("/bin/sh a : %p\n", sh_path);
    printf("La fonction system est à l'addresse: %p\n",&system);
    
    printf("Bof!!\n");
    vuln();
    return 0;
}
```

**Lancement:**
```bash
cd challenge4-ret2libc/pub
docker-compose up --build
```

---

### Challenge 5: Bash Jail

**Port:** `20000`  
**Flag:** `FLAG{Pr1s0n_Br34k}`  
**Description:** Un admin parano a créé un shell ultra-sécurisé qui bloque tout : pas de `/`, pas de `;`, pas de commandes externes. Le flag est quelque part, mais comment le trouver avec seulement les builtins bash ?

**Fichiers à donner aux joueurs:**
- `jail.sh` (code source du jail)
- Accès au shell via netcat sur le port 20000

**Code source (`jail.sh`):**
```bash
#!/bin/bash

unset PATH
enable -n exec
enable -n command
enable -n type
enable -n hash
enable -n cd
enable -n enable
set +x

echo "Only core Bash internals are allowed."
echo "The flag is hidden, and you will need to think creatively to find it!"

while true; do
    echo -n "shell> "
    if ! read user_input; then
        echo "Connection closed."
        break
    fi

    [[ -z "$user_input" ]] && continue

    case "$user_input" in 
	   *">"*|*"<"*|*"/"*|*";"*|*"&"*|*"$"*|*"("*|*"\`"*) echo "❌ Transmission blocked: Unsafe characters detected." && continue;;
    esac

    eval "$user_input"
done
```

**Lancement:**
```bash
cd challenge5-jail-bash
docker-compose up --build
```

---


## 🛠️ Prérequis

- Docker
- Docker Compose

## 📝 Notes

- Les flags sont différents pour chaque challenge
- Les challenges de pwn (3 et 4) nécessitent des outils comme `pwntools`, `gdb`, etc.
- Le challenge 2 nécessite Metasploit Framework
- Tous les challenges sont isolés dans leurs propres conteneurs Docker

