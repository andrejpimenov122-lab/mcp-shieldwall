FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY mcp_shieldwall ./mcp_shieldwall
RUN pip install --no-cache-dir .
USER 65534:65534
ENTRYPOINT ["mcp-shieldwall", "serve-mcp"]
