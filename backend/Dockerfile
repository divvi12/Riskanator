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

# Install dependencies
RUN npm ci --only=production

# Copy built files
COPY dist/ ./dist/

# Expose port
EXPOSE 3001

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3001

# Start the server
CMD ["node", "dist/index.js"]
