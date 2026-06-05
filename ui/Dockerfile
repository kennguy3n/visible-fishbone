# syntax=docker/dockerfile:1
# --- Build stage --------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# Install dependencies against the lockfile for reproducible builds.
COPY package.json package-lock.json* ./
RUN npm ci || npm install

# Build the static bundle.
COPY . .
RUN npm run build

# --- Runtime stage ------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# SPA-aware nginx config (history fallback + asset caching).
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf

# Static assets from the build stage.
COPY --from=build /app/dist /usr/share/nginx/html

# Entrypoint regenerates /config.js from environment variables at start so a
# single immutable image can be promoted across environments.
COPY docker/docker-entrypoint.sh /docker-entrypoint.d/40-sng-config.sh
RUN chmod +x /docker-entrypoint.d/40-sng-config.sh

EXPOSE 8080
# nginx:alpine already defines a CMD; the official image runs scripts in
# /docker-entrypoint.d before starting nginx, so our config generator runs
# automatically.
