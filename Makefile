.PHONY: build test demo lab-down

build:
	go build -o wgx .

test:
	go test ./...

demo:
	@flock .wgx-demo.lock sh -c 'docker compose up -d --build && docker compose exec wgx wgx'

lab-down:
	docker compose down
