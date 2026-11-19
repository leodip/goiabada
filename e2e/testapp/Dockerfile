# The test app as a small Node server: Next.js's standalone output. Configuration comes from the
# environment at run time (see .env.example), so one image serves any deployment.

# The bases' registry: Docker Hub's library by default, so anyone's own docker build builds on the
# images it always has. The e2e server passes CI's mirror of them,
# --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, so it pulls nothing from Docker Hub (#867).
ARG baseRegistry=docker.io/library

FROM ${baseRegistry}/node:26.13.1-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM ${baseRegistry}/node:26.13.1-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
USER node
EXPOSE 3000
CMD ["node", "server.js"]
