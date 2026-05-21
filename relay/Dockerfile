# NoiseBox relay — minimal Python container.
#
# Builds: ~70 MB image with aiohttp and nothing else. The container runs
# the relay on :8081 inside; Caddy in the next-door container terminates
# TLS and forwards.

FROM python:3.12-slim

WORKDIR /app

# Install only the runtime deps. requirements.txt is intentionally tiny
# (aiohttp) so the image stays small.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the bot code.
COPY bot.py .

# Persist state (peer mappings, device tokens) into a volume so restarts
# don't lose user bindings. Mount /data from the host or a named volume.
ENV STATE_FILE=/data/state.json
ENV HTTP_HOST=0.0.0.0
ENV HTTP_PORT=8081

EXPOSE 8081

# Run as a non-root user. State dir is owned by this user (uid 1000).
RUN useradd --create-home --uid 1000 cardputer && mkdir /data && chown cardputer:cardputer /data
USER cardputer

CMD ["python", "bot.py"]
