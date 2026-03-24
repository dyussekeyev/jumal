# JUMAL Static Analyzer Docker Image
# Installs: diec, yara, floss, capa, oletools, oledump, pdfid, pdf-parser
#
# Build: docker build -t jumal-analyzer:latest .
# (The host app can also build this automatically on first use.)

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        python3-dev \
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
        binutils \
    && rm -rf /var/lib/apt/lists/*

# Ensure pip is up to date
RUN pip install --no-cache-dir --upgrade pip

# ── Python analysis tools ─────────────────────────────────────────────────────
# Install commonly used python-based tools via pip for better compatibility on this base image
RUN pip install --no-cache-dir \
        oletools \
        pdfminer.six \
        flare-floss \
        flare-capa

# ── Detect It Easy (diec) ─────────────────────────────────────────────────────
# Install Qt5 runtime libraries required by DIE, then install the Debian 12 deb.
# Pinned to a known-good release. Update DIE_VERSION when upgrading.
# Available assets: https://github.com/horsicq/DIE-engine/releases
ARG DIE_VERSION=3.10
# NOTE: apt lists are kept alive until AFTER dpkg-i so that
# "apt-get install -f" can resolve any unmet dependencies automatically.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libqt5core5a \
        libqt5gui5 \
        libqt5widgets5 \
        libqt5script5 \
        libqt5network5 \
        libqt5xml5 \
        libglib2.0-0 \
    && ( \
        wget -q \
            "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Debian_12_amd64.deb" \
            -O /tmp/die.deb \
        || wget -q \
            "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_22.04_amd64.deb" \
            -O /tmp/die.deb \
    ) \
    && (dpkg -i /tmp/die.deb || apt-get install -f -y --no-install-recommends) \
    && rm -f /tmp/die.deb \
    && rm -rf /var/lib/apt/lists/* \
    && (which diec || ln -sf /usr/bin/diec /usr/local/bin/diec || true) \
    || { echo "WARNING: DIE installation failed; diec will not be available"; rm -f /tmp/die.deb; rm -rf /var/lib/apt/lists/*; }

# ── Didier Stevens standalone tools ───────────────────────────────────────────
# oledump, pdfid, and pdf-parser are standalone scripts not available via pip.
RUN mkdir -p /usr/local/lib \
    && wget -q "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py" \
         -O /usr/local/lib/oledump.py \
    && wget -q "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py" \
         -O /usr/local/lib/pdfid.py \
    && wget -q "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py" \
         -O /usr/local/lib/pdf-parser.py \
    && chmod +x /usr/local/lib/oledump.py /usr/local/lib/pdfid.py /usr/local/lib/pdf-parser.py

# ── Create directories expected by analyzer_entry.py
# /workspace/tmp is used as TMPDIR so PyInstaller-based tools (floss, capa)
# can extract their bundled libraries to an exec-capable filesystem instead of
# the noexec /tmp tmpfs that the host mounts inside the container.
RUN mkdir -p /workspace/input /workspace/output /workspace/rules /workspace/tmp

# Copy any bundled YARA rules from the image build context (if present)
# This allows shipping default rules inside image build; project also mounts host rules dir at runtime.
COPY rules/ /workspace/rules/

# Copy the analyzer entrypoint script
COPY analyzer_entry.py /workspace/analyzer_entry.py

# Make sure binaries are executable (best-effort)
RUN chmod +x /usr/local/bin/capa || true \
    && chmod +x /usr/local/bin/floss || true \
    && chmod +x /usr/local/bin/diec || true

# Set a safe working directory
WORKDIR /workspace

ENTRYPOINT ["python3", "/workspace/analyzer_entry.py"]
