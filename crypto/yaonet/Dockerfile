FROM python:alpine3.18

RUN apk update && \
    apk add --no-cache \
    openssh-keygen

RUN pip install paramiko

WORKDIR /app
COPY flag.txt server.py id_ecdsa.pub ./

EXPOSE 22
CMD ["python3", "server.py"]
