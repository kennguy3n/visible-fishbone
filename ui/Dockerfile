# syntax=docker/dockerfile:1
# --- Build stage --------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# Install dependencies strictly from the committed lockfile for reproducible
# builds. `npm ci` fails loudly if package.json and package-lock.json are out
# of sync, which is what we want in CI/image builds (no silent `npm install`
# fallback that could resolve different versions).
COPY package.json package-lock.json ./
RUN npm ci

# Build the static bundle.
COPY . .
RUN npm run build

# --- Runtime stage ------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# SPA-aware nginx config (history fallback + asset caching) plus the shared
# hardening-headers snippet that each location block includes.
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/security-headers.conf /etc/nginx/snippets/sng-security-headers.conf

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
