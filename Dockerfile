# Use Python 3.13 slim image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Copy dependency files
COPY requirements.txt ./

# Install git (needed for git-based pip dependencies) and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y git && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY . .

# Expose ports
EXPOSE 8001 9000

# Default command (can be overridden in docker-compose)
CMD ["python", "-m", "taskmanager_mcp.server"]
