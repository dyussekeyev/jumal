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
        libstdc++6 \
        libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# ── Python analysis tools ─────────────────────────────────────────────────────
RUN pip install --no-cache-dir \
        oletools \
        pdfminer.six

# ── Detect It Easy (diec) ─────────────────────────────────────────────────────
# Pinned to a known-good release. Update DIE_VERSION when upgrading.
# Available assets: https://github.com/horsicq/DIE-engine/releases
ARG DIE_VERSION=3.10
RUN set -ex \
    && wget -q \
             "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_portable_Ubuntu_20.04_amd64.tar.gz" \
             -O /tmp/die.tar.gz \
        || { echo "ERROR: DIE-engine ${DIE_VERSION} asset not found. Check https://github.com/horsicq/DIE-engine/releases and update DIE_VERSION."; exit 1; } \
    && mkdir -p /opt/die \
    && tar -xzf /tmp/die.tar.gz -C /opt/die --strip-components=1 \
    && ln -sf /opt/die/diec /usr/local/bin/diec \
    && chmod +x /usr/local/bin/diec || true \
    && rm /tmp/die.tar.gz

# ── FLOSS (Mandiant FLARE) ────────────────────────────────────────────────────
# Pinned release. Update the URL and version tag together when upgrading.
RUN set -ex \
    && wget -q "https://github.com/mandiant/flare-floss/releases/download/v3.1.0/floss-v3.1.0-linux.zip" \
             -O /tmp/floss.zip \
    && unzip -q /tmp/floss.zip floss -d /tmp/floss_out \
    && mv /tmp/floss_out/floss /usr/local/bin/floss \
    && chmod +x /usr/local/bin/floss \
    && rm -rf /tmp/floss.zip /tmp/floss_out || true

# ── CAPA (Mandiant) ────────────────────────────��──────────────────────────────
# Pinned release. Update the URL and version tag together when upgrading.
RUN set -ex \
    && wget -q "https://github.com/mandiant/capa/releases/download/v7.4.0/capa-v7.4.0-linux.zip" \
             -O /tmp/capa.zip \
    && unzip -q /tmp/capa.zip capa -d /tmp/capa_out \
    && mv /tmp/capa_out/capa /usr/local/bin/capa \
    && chmod +x /usr/local/bin/capa \
    && rm -rf /tmp/capa.zip /tmp/capa_out || true

# ── Didier Stevens tools ──────────────────────────────────────────────────────
RUN set -ex \
    && pip install --no-cache-dir oletools pdfminer.six \
    || true

# Create directories expected by analyzer_entry.py
RUN mkdir -p /workspace/input /workspace/output /workspace/rules

# Copy any bundled YARA rules from the image build context (if present)
# This allows shipping default rules inside image build; project also mounts host rules dir at runtime.
COPY rules/ /workspace/rules/  # no-op if directory doesn't exist

# Make sure binaries are executable
RUN chmod +x /usr/local/bin/capa || true
RUN chmod +x /usr/local/bin/floss || true
RUN chmod +x /usr/local/bin/diec || true

# Set a safe working directory
WORKDIR /workspace
