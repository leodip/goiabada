# The docs image. Built from the repository root, not from site/, because the
# build reads the repository's src/: the shipped-link check reads its code.
#
#   docker build -f site/Dockerfile -t goiabada-docs .
#
# Site/Dockerfile.dockerignore keeps the context to site/ and src/.

# The bases' registry: Docker Hub's library by default, so the Docs workflow's build, or anyone's
# own, builds on the images it always has. Check's docs job passes CI's mirror of them,
# --build-arg baseRegistry=ghcr.io/leodip/goiabada-ci, so it pulls nothing from Docker Hub (#867).
ARG baseRegistry=docker.io/library

# Dependencies and sources, with nothing built yet. CI runs the site checks'
# tests in this stage, so they run on the Node version the site is built with.
FROM ${baseRegistry}/node:26.13.1-alpine AS sources

WORKDIR /repo/site

COPY site/package.json site/package-lock.json ./
RUN npm ci

COPY src/ /repo/src/
COPY site/ ./

# Build the static site, with /llms.txt and /llms-full.txt. The build fails on a
# broken internal link or heading anchor, on a goiabada.dev link in src/ that
# names no built page, and when the llms files disagree with the pages.
FROM sources AS builder

RUN npm run build

# Production stage
FROM ${baseRegistry}/nginx:alpine

COPY site/nginx.conf /etc/nginx/conf.d/default.conf

COPY --from=builder /repo/site/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
