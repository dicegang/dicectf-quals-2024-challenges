FROM node:21-alpine

WORKDIR /app

COPY package* .

RUN apk add --no-cache --virtual .gyp python3 make g++ \
    && npm ci \
    && apk del .gyp

COPY index.js .

CMD node index.js