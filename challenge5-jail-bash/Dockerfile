FROM alpine:latest

RUN apk add --no-cache bash socat

WORKDIR /app

COPY flag.txt /opt/flag/flag.txt
COPY src/jail.sh /app/jail.sh
RUN chmod +x /app/jail.sh

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/app/jail.sh,pty,stderr"]
