FROM node:20-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build || npx tsc --noEmit || true
# Run via tsx in container for simplicity in v0.1 (no brittle path rewrite)
RUN npm install -g tsx

FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm install -g tsx
EXPOSE 8080 3000
CMD ["tsx", "gateway/src/index.ts"]
