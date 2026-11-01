# NSFW Firewall Engine - Production Docker Image
FROM python:3.12-slim

# Install system dependencies (libmagic for MIME detection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy only requirements first for caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create logs directory
RUN mkdir -p /var/log/nsfw-firewall

# Expose port (internal only, accessible via Nginx)
EXPOSE 8080

# Define default command
CMD ["python", "-m", "app.main"]
