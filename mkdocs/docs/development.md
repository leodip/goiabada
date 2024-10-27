# Development

Goibada was developed in [Go](https://go.dev/) using Linux (❤️). The [github repository](https://github.com/leodip/goiabada) has a vscode dev container with all the dependencies pre-configured to run Goiabada locally. 

To get started, simply clone the repository, install [Microsoft's Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) and open it in the dev container. You can `make serve` the authserver and `make serve` the adminconsole, from their respective folders. That will give you a running Goiabada.

For integration tests, first `make serve` the authserver to start it, then in another terminal use the `make test-local` script from the authserver folder, to run the tests.

Goiabada uses [go-sqlbuilder](https://github.com/huandu/go-sqlbuilder) for SQL generation, [Tailwind CSS](https://tailwindcss.com/) with [DaisyUI](https://daisyui.com/) for UI & styling, and the [chi router](https://github.com/go-chi/chi) to manage the incoming HTTP requests.

Bug reports and pull requests are encouraged. You can reach out to me at [contact@leodip.com](mailto:contact@leodip.com). Your involvement is welcome and appreciated.