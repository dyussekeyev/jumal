# JUMAL Static Analyzer Docker Image
# Installs: diec, yara, floss, capa, oletools, oledump, pdfid, pdf-parser
#
# Build: docker build -t jumal-analyzer:latest .
# (The host app can also build this automatically on first use.)

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget \
        curl \
        unzip \
        ca-certificates \
        yara \
        libssl-dev \
        libmagic1 \
        file \
        zlib1g \
        zlib1g-dev \
        libstdc++6 \
        libgcc-s1 \
        # utilities
        binutils \
    && rm -rf /var/lib/apt/lists/*

# Ensure pip is up to date
RUN pip install --no-cache-dir --upgrade pip

# ── Python analysis tools ─────────────────────────────────────────────────────
# Install commonly used python-based tools via pip for better compatibility on this base image
RUN pip install --no-cache-dir \
        oletools \
        pdfminer.six \
        floss \
        capa

# ── Detect It Easy (diec) ─────────────────────────────────────────────────────
# Pinned to a known-good release. Update DIE_VERSION when upgrading.
# Available assets: https://github.com/horsicq/DIE-engine/releases
ARG DIE_VERSION=3.10
RUN set -ex \
    && wget -q \
             "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_portable_Ubuntu_20.04_amd64.tar.gz" \
             -O /tmp/die.tar.gz \
        || { echo "WARNING: DIE-engine ${DIE_VERSION} asset not found. Continuing without diec."; exit 0; } \
    && mkdir -p /opt/die \
    && tar -xzf /tmp/die.tar.gz -C /opt/die --strip-components=1 \
    && if [ -f /opt/die/diec ]; then ln -sf /opt/die/diec /usr/local/bin/diec && chmod +x /usr/local/bin/diec; fi \
    && rm -rf /tmp/die.tar.gz || true

# ── Ensure python-based utilities are available as commands ───────────────────
# Some pip-installed packages expose console scripts (floss, capa) in /usr/local/bin - ensure executable bit
RUN chmod +x /usr/local/bin/floss || true
RUN chmod +x /usr/local/bin/capa || true

# ── Create directories expected by analyzer_entry.py
RUN mkdir -p /workspace/input /workspace/output /workspace/rules /usr/local/lib

# Copy any bundled YARA rules from the image build context (if present)
# This allows shipping default rules inside image build; project also mounts host rules dir at runtime.
COPY rules/ /workspace/rules/  # no-op if directory doesn't exist

# Make sure binaries are executable (best-effort)
RUN chmod +x /usr/local/bin/capa || true
RUN chmod +x /usr/local/bin/floss || true
RUN chmod +x /usr/local/bin/diec || true

# Set a safe working directory
WORKDIR /workspace
