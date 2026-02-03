FROM node:20-slim

# Install git with HTTPS support, python/pip for pip-audit, and other tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    git-lfs \
    openssh-client \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    bash \
    && git config --global http.sslVerify true \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install pip-audit and checkov (IaC scanner)
RUN pip3 install --break-system-packages pip-audit checkov \
    && echo "pip-audit installed at: $(which pip-audit)" \
    && pip-audit --version \
    && echo "checkov installed at: $(which checkov)" \
    && checkov --version

# Install trivy - download directly from GitHub releases
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ]; then TRIVY_ARCH="ARM64"; else TRIVY_ARCH="64bit"; fi && \
    wget -q https://github.com/aquasecurity/trivy/releases/download/v0.58.0/trivy_0.58.0_Linux-${TRIVY_ARCH}.tar.gz -O /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    chmod +x /usr/local/bin/trivy && \
    echo "trivy installed at: $(which trivy)" && \
    trivy --version

# Add pip binaries to PATH and create symlinks for consistent access
ENV PATH="/usr/local/bin:/usr/bin:$PATH"
RUN ln -sf $(which pip-audit) /usr/local/bin/pip-audit 2>/dev/null || true

# Verify all tools are accessible
RUN echo "=== Verifying tool installations ===" \
    && echo "pip-audit:" && which pip-audit && pip-audit --version \
    && echo "checkov:" && which checkov && checkov --version \
    && echo "trivy:" && which trivy && trivy --version \
    && echo "git:" && which git && git --version \
    && echo "=== All tools verified ==="

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
