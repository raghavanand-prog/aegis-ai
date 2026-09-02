# --- build ------------------------------------------------------------------
FROM node:22-alpine AS build

WORKDIR /app

# Dependencies first so a source change does not reinstall the world.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Baked in at build time: Vite inlines VITE_* variables into the bundle, so the
# API URL is a build argument rather than a runtime secret. Never put anything
# secret in a VITE_ variable - it ends up in the JavaScript the browser gets.
ARG VITE_API_URL=http://localhost:8000/api/v1
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# --- serve ------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://localhost/ >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
