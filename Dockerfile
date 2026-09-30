# Production image for the domain security scanner.
# Build:  docker build -t domain-scanner .
# Run:    docker run -p 3000:3000 --env-file .env domain-scanner

FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

# Install production dependencies first so they cache independently of code.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY src ./src
COPY public ./public

# The mailer's dev fallback writes email previews to ./previews when SMTP is
# not configured; give the non-root user somewhere to put them.
RUN mkdir -p previews && chown -R node:node /app
USER node

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:${PORT:-3000}/healthz || exit 1

CMD ["node", "server.js"]
