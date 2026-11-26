# The example web app: built with Node, served by Caddy. Both images are pinned
# by digest (OPS-03). Build from this directory: `docker build .`.
FROM node:24.11.1-alpine@sha256:682368d8253e0c3364b803956085c456a612d738bd635926d73fa24db3ce53d7 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY index.html vite.config.js ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM caddy:2.11.9@sha256:9c1b76fb701c1f77383d3124d9f626e38bcf83bc1255ed47475d4f2420701d03
# Serves dist/ on port 5173 over plain http; /callback and any other path
# without a file falls back to index.html (a single-page app).
RUN printf '%s\n' \
    '{' \
    '	auto_https off' \
    '	admin off' \
    '}' \
    ':5173 {' \
    '	root * /srv' \
    '	try_files {path} /index.html' \
    '	header Content-Security-Policy "default-src '"'"'self'"'"'; connect-src '"'"'self'"'"' https:; frame-ancestors '"'"'none'"'"'; base-uri '"'"'none'"'"'; object-src '"'"'none'"'"'"' \
    '	header X-Content-Type-Options nosniff' \
    '	file_server' \
    '}' > /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 5173
