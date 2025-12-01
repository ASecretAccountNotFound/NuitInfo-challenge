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

// gcc -m32 -fno-stack-protector -no-pie -z execstack -o vuln vuln.c -ldl
