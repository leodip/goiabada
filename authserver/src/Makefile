air:
	tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
	ls -l --block-size=M ./web/static
	rm ./tmp/goiabada
	go build -o ./tmp/goiabada ./cmd/goiabada/main.go
