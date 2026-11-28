# syntax=docker/dockerfile:1
# -----------------------------------------------------------------------------
# FleetSec Telemetry & Security API - Production Container
# Base image pinned strictly (NO :latest tag) to satisfy DevSecOps Quality Gate
# -----------------------------------------------------------------------------
FROM node:22.12.0-alpine3.20

# Metadata
LABEL maintainer="FleetSec Cybersecurity Engineering <security@fleetsec.internal>"
LABEL description="FleetSec secure vehicle telemetry backend API"
LABEL version="1.0.0"

# Set secure working directory
WORKDIR /usr/src/app

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000

# Install production dependencies only using clean install (npm ci)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && \
    npm cache clean --force

# Copy application source code
COPY src/ ./src/

# Create persistent database storage directory with non-root ownership
RUN mkdir -p /usr/src/app/data && \
    chown -R node:node /usr/src/app

# Enforce least-privilege: switch from root to unprivileged 'node' user
USER node

# Expose backend application port
EXPOSE 3000

# Container healthcheck for automated orchestration / docker-compose monitoring
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:3000/health || exit 1

# Start the Node.js application
CMD ["node", "src/index.js"]
