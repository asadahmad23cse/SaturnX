FROM node:24-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e

ENV NODE_ENV=production \
    PORT=10000

WORKDIR /app

COPY inspector-demo/package.json inspector-demo/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY inspector-demo/gateway.mjs inspector-demo/policy.mjs inspector-demo/inspector.json ./
COPY inspector-demo/public ./public

USER node
EXPOSE 10000

CMD ["node", "gateway.mjs"]
