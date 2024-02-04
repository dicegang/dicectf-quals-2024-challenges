FROM node:21.6.1-slim
WORKDIR /app
COPY --link package.json package-lock.json ./
RUN npm ci
COPY --link server.js .
ADD public.tar .
CMD ["node", "server.js"]
