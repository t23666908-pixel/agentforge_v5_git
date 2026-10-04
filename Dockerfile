# Minimaler Dockerfile für Deploys (Fly.io, Railway, Render-Docker, eigener Server)
FROM node:20-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://localhost:8787/health || exit 1
CMD ["node", "server.js"]
