FROM alpine:latest

RUN apk add uv ffmpeg
RUN uv tool install spotdl

WORKDIR /app

COPY . .

RUN uv sync

CMD ["uv", "run", "main.py"]
