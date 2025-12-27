# Use Python 3.13 slim image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install uv and git
RUN apt-get update && apt-get install -y --no-install-recommends git curl \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Add uv to PATH
ENV PATH="/root/.local/bin:$PATH"

# Copy dependency files first for better caching
COPY pyproject.toml uv.lock ./

# Install dependencies using uv (uses uv.lock for reproducible builds)
RUN uv sync --frozen --no-dev

# Copy application code
COPY . .

# Expose ports
EXPOSE 8001 9000

# Default command (can be overridden in docker-compose)
CMD ["uv", "run", "python", "-m", "taskmanager_mcp.server"]
