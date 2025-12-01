FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    gcc \
    make \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY vuln.c ./

RUN gcc -fno-stack-protector -no-pie -z execstack -o vuln vuln.c && \
    chmod +x vuln

RUN echo "FLAG{R3tUrn_To_Th3_W1n}" > flag.txt

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./vuln,pty,stderr"]

