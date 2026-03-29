# ============================================================
# Jerry The Customer Service Bot Backend — Dockerfile
# ============================================================
# Uses PyTorch CPU-only to keep image under Railway's 4 GB limit.
# Full CUDA PyTorch is ~2.5 GB; CPU-only is ~200 MB.
# ============================================================
# NOTE: Build context is the repo root (set by railway.toml),
# so all COPY paths are relative to the repo root.
# ============================================================

FROM python:3.11-slim

# System dependencies for building Python packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install PyTorch CPU-only FIRST (before requirements.txt)
# This avoids pulling in the ~2.5 GB CUDA version
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install remaining Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY backend/ .

# Port (Railway injects $PORT, default 8000)
EXPOSE 8000

# Run the server
CMD ["python", "main.py"]
