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
RUN npm install -g tsx

FROM node:20-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
# Non-root user (compose also sets user: "1000:1000")
RUN groupadd --gid 1000 phaseone \
  && useradd --uid 1000 --gid phaseone --shell /bin/bash --create-home phaseone \
  && mkdir -p /app /tmp/phaseone && chown -R phaseone:phaseone /app /tmp/phaseone
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm install -g tsx \
  && chown -R phaseone:phaseone /app
USER phaseone
EXPOSE 8080 3000
CMD ["tsx", "gateway/src/index.ts"]
