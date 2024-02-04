FROM node:21-alpine

WORKDIR /app

COPY package* .

RUN npm ci

COPY index.* .
COPY flag.txt /flag.txt

USER node

CMD node index.js
