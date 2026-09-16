# PhaseOne10841 v0.5 — Veracity Integrity LLC
FROM node:20-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build || npx tsc --noEmit || true

FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
# node:20-bookworm-slim already has uid/gid 1000 (user `node`) — reuse it
RUN mkdir -p /app /tmp/phaseone && chown -R node:node /app /tmp/phaseone
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm install -g tsx \
  && chown -R node:node /app
USER node
EXPOSE 8080 3000
CMD ["tsx", "gateway/src/index.ts"]
