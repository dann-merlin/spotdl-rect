# Default output directory (can be overridden from command line)
OUTPUTDIR ?= ./out
PORT ?= 8584

IMAGE_NAME = spotdl-rect

build_podman:
	podman build -t $(IMAGE_NAME) .

run_podman:
	podman run --rm -it \
		-p $(PORT):8080 \
		-v ./config.toml:/app/config.toml \
		-v "$(OUTPUTDIR):/app/out" \
		$(IMAGE_NAME)

