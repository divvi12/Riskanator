FROM node:20-alpine

# Install git, python/pip for pip-audit, and trivy for container scanning
# Note: semgrep is excluded as it requires glibc (not available on Alpine)
# and is too large for cloud build environments
RUN apk add --no-cache git python3 py3-pip curl \
    && pip3 install --break-system-packages pip-audit \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy image --download-db-only --no-progress

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev for TypeScript build)
RUN npm ci

# Copy source files
COPY src/ ./src/

# Build TypeScript
RUN npm run build

# Remove dev dependencies to reduce image size
RUN npm prune --omit=dev

# Expose port
EXPOSE 3001

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3001

# Start the server
CMD ["node", "dist/index.js"]
