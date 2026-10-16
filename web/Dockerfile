# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS build
RUN npm install --global pnpm@12.9.1
WORKDIR /src/web
COPY web/pnpm-lock.yaml ./
RUN --mount=type=cache,id=jms233-pnpm,target=/pnpm/store pnpm fetch --store-dir /pnpm/store
COPY web/package.json ./
RUN --mount=type=cache,id=jms233-pnpm,target=/pnpm/store pnpm install --offline --frozen-lockfile --store-dir /pnpm/store
COPY web/ ./
COPY scripts/check-web-bundle.mjs /src/scripts/check-web-bundle.mjs
RUN --mount=type=cache,id=jms233-tsc,target=/src/web/node_modules/.cache pnpm build

FROM nginx:stable-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5
COPY web/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /src/web/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=1s --timeout=2s --start-period=1s --retries=20 CMD wget -q -O /dev/null http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["nginx", "-g", "daemon off;"]
