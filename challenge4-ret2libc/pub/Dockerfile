FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    gcc \
    gcc-multilib \
    socat \
    libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copier la libc locale (32-bit) et le linker depuis l'hôte
RUN mkdir -p /lib/i386-linux-gnu /lib32
COPY lib32/libc.so.6 /lib/i386-linux-gnu/libc.so.6
COPY lib32/ld-linux.so.2 /lib32/ld-linux.so.2

# Créer un wrapper gcc pour compiler directement en 32-bit
RUN echo '#!/bin/sh\nexec /usr/bin/gcc -m32 "$@"' > /usr/local/bin/gcc && chmod +x /usr/local/bin/gcc
ENV PATH="/usr/local/bin:$PATH"

COPY vuln.c ./

RUN gcc -fno-stack-protector -no-pie -z execstack -o vuln vuln.c -ldl && chmod +x vuln

RUN echo "FLAG{R3T2L1BC_deadbeef}" > flag.txt

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./vuln,pty,stderr"]
