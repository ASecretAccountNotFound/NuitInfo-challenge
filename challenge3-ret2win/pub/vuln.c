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
    printf("La fonction win est à l'adresse: %p\n", &win);
    printf("Enter your name: ");
    fgets(buffer, 256, stdin);
    printf("Hello, %s", buffer);
    return 0;
}


