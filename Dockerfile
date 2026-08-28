#
# Multi-stage Dockerfile for Pentest Agent
# Uses Chainguard Wolfi for minimal attack surface and supply chain security

# Builder stage - Install tools and dependencies
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

# Install system dependencies available in Wolfi
RUN apk update && apk add --no-cache \
    # Core build tools
    build-base \
    git \
    curl \
    wget \
    ca-certificates \
    # Network libraries for Go tools
    libpcap-dev \
    linux-headers \
    # Language runtimes
    go \
    nodejs-22 \
    npm \
    python3 \
    py3-pip \
    ruby \
    ruby-dev \
    # Security tools available in Wolfi
    nmap \
    # Additional utilities
    bash

# Set environment variables for Go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV CGO_ENABLED=1

# Create directories
RUN mkdir -p $GOPATH/bin

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# Install WhatWeb from GitHub (Ruby-based tool)
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    chmod +x /opt/whatweb/whatweb && \
    gem install addressable && \
    echo '#!/bin/bash' > /usr/local/bin/whatweb && \
    echo 'cd /opt/whatweb && exec ./whatweb "$@"' >> /usr/local/bin/whatweb && \
    chmod +x /usr/local/bin/whatweb

# Install Python-based tools
RUN pip3 install --no-cache-dir schemathesis

# Install deterministic white-box scanners (SAST / SCA / dataflow — capabilities 1.1–1.7).
# Best-effort and GUARDED: each optional install is `|| echo`-ed so a failure can never
# break the image build. When a scanner is absent the white-box pass degrades gracefully.
RUN pip3 install --no-cache-dir semgrep || echo "semgrep install skipped (optional)"
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest || echo "osv-scanner install skipped (optional)"
RUN go install github.com/zricethezav/gitleaks/v8@latest || echo "gitleaks install skipped (optional)"

# Install deterministic DAST scanners (Tier-2 ADD group — nuclei/testssl.sh/retire.js).
# Guarded so a failed optional install never breaks the build. nuclei templates are
# pre-downloaded to a fixed dir the runner points at via NUCLEI_TEMPLATES_DIR.
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "nuclei install skipped (optional)"
# Install nuclei templates by cloning the repo directly. nuclei's own `-update-templates`
# downloader fails silently in a minimal container (writes 0 files); a git clone is reliable
# and world-readable so the non-root runtime user can read them.
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates 2>/dev/null \
    && chmod -R a+rX /opt/nuclei-templates \
    || mkdir -p /opt/nuclei-templates
RUN npm install -g retire || echo "retire install skipped (optional)"
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl 2>/dev/null || mkdir -p /opt/testssl

# Runtime stage - Minimal production image
FROM cgr.dev/chainguard/wolfi-base:latest AS runtime

# Install only runtime dependencies
USER root
RUN apk update && apk add --no-cache \
    # Core utilities
    git \
    bash \
    curl \
    ca-certificates \
    # Network libraries (runtime)
    libpcap \
    # Security tools
    nmap \
    # Language runtimes (minimal)
    nodejs-22 \
    npm \
    python3 \
    py3-pip \
    ruby \
    # Chromium browser and dependencies for Playwright
    chromium \
    # Additional libraries Chromium needs
    nss \
    freetype \
    harfbuzz \
    # X11 libraries for headless browser
    libx11 \
    libxcomposite \
    libxdamage \
    libxext \
    libxfixes \
    libxrandr \
    mesa-gbm \
    # Font rendering
    fontconfig \
    # openssl + coreutils for testssl.sh (deep TLS scanning). testssl rejects busybox's
    # `dd`/utilities, so GNU coreutils must be present or testssl aborts on startup.
    openssl \
    coreutils

# Copy Go binaries from builder (subfinder + optional white-box scanners osv-scanner/gitleaks
# + optional DAST scanner nuclei). Directory copy is resilient: it succeeds even if an
# optional scanner did not build.
COPY --from=builder /go/bin/ /usr/local/bin/

# DAST assets from builder: pre-downloaded nuclei templates + testssl.sh (both dirs always
# exist in the builder, so these copies never fail even if a download/clone was skipped).
COPY --from=builder /opt/nuclei-templates /opt/nuclei-templates
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
COPY --from=builder /opt/testssl /opt/testssl
RUN ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh || true

# Copy WhatWeb from builder
COPY --from=builder /opt/whatweb /opt/whatweb
COPY --from=builder /usr/local/bin/whatweb /usr/local/bin/whatweb

# Install WhatWeb Ruby dependencies in runtime stage
RUN gem install addressable

# Copy Python packages from builder
COPY --from=builder /usr/lib/python3.*/site-packages /usr/lib/python3.12/site-packages
COPY --from=builder /usr/bin/schemathesis /usr/bin/

# retire.js (client-side JS CVE scanner) — Node global in the runtime image.
RUN npm install -g retire || echo "retire runtime install skipped (optional)"

# Pre-install the Playwright MCP so agents don't pay a first-run `npx` download that can
# time out the MCP connection on a cold image. Guarded so a failure can't break the build.
RUN npm install -g @playwright/mcp@latest || echo "@playwright/mcp preinstall skipped (optional)"

# semgrep (SAST / taint) — installed in the runtime stage because the builder's site-packages
# copy does not carry semgrep's native core. Guarded so a failure can never break the build.
RUN pip3 install --no-cache-dir --break-system-packages semgrep || echo "semgrep runtime install skipped (optional)"

# Create non-root user for security
RUN addgroup -g 1001 pentest && \
    adduser -u 1001 -G pentest -s /bin/bash -D pentest

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./
COPY mcp-server/package*.json ./mcp-server/

# Playwright must NOT download its own browser during install — the image ships
# a system Chromium (installed above) that render-pdf.ts targets via
# PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH. Set this before npm ci so the postinstall
# step is skipped.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Install Node.js dependencies (including devDependencies for TypeScript build)
RUN npm ci && \
    cd mcp-server && npm ci && cd .. && \
    npm cache clean --force

# Copy application source code
COPY . .

# Build TypeScript (mcp-server first, then main project)
RUN cd mcp-server && npm run build && cd .. && npm run build

# Remove devDependencies after build to reduce image size
RUN npm prune --omit=dev && \
    npm --prefix mcp-server prune --omit=dev

# Create directories for session data and ensure proper permissions
RUN mkdir -p /app/sessions /app/deliverables /app/repos /app/configs && \
    mkdir -p /tmp/.cache /tmp/.config /tmp/.npm && \
    chmod 777 /app && \
    chmod 777 /tmp/.cache && \
    chmod 777 /tmp/.config && \
    chmod 777 /tmp/.npm && \
    chown -R pentest:pentest /app

# Switch to non-root user
USER pentest

# Set environment variables
ENV NODE_ENV=production
ENV PATH="/usr/local/bin:$PATH"
ENV DAPPER_DOCKER=true
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV npm_config_cache=/tmp/.npm
ENV HOME=/tmp
ENV XDG_CACHE_HOME=/tmp/.cache
ENV XDG_CONFIG_HOME=/tmp/.config

# Configure Git identity and trust all directories
RUN git config --global user.email "agent@localhost" && \
    git config --global user.name "Pentest Agent" && \
    git config --global --add safe.directory '*'

# Set entrypoint
ENTRYPOINT ["node", "dist/dapper.js"]
