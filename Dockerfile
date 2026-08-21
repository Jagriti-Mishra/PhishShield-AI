# 🛡️ PhishShield AI — Production Multi-Stage Dockerfile
FROM python:3.12-slim AS builder

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final Runtime Image
FROM python:3.12-slim AS runner

WORKDIR /app

# Install runtime dependencies for PIL, Network, and SSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg62-turbo \
    zlib1g \
    libfreetype6 \
    liblcms2-2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Copy project files
COPY backend /app/backend
COPY frontend /app/frontend
COPY run_server.py /app/run_server.py

WORKDIR /app

# Initialize reference brand signatures
RUN python backend/seed_brand_data.py

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["python", "run_server.py"]
