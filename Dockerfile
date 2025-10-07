FROM python:3.13

WORKDIR /auth-service
COPY main.py pyproject.toml /auth-service

RUN python --version
RUN pip install --upgrade pip
RUN pip install uv
RUN uv sync

EXPOSE 8000
ENV PORT=8000
RUN uv pip list

# Can not use $PORT in JSON array syntax below
CMD  ["uv", "run", "fastapi", "dev", "main.py", "--host", "0.0.0.0", "--port", "8000"]
