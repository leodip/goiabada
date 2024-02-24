# Development

Goibada was developed in [Go](https://go.dev/) using [Fedora Linux](https://fedoraproject.org/) (❤️). The [github repository](https://github.com/leodip/goiabada) has a vscode `devcontainer` with all the dependencies configured to run Goiabada locally. 

To get started, simply clone the repository, open it in the `devcontainer`, start it by using the `make serve` command.

For running integration tests, first use the `make serve` command to start the web server, then in another terminal use the `make test` script. Test coverage will be progressively improved over time.

Goiabada uses [go-sqlbuilder](https://github.com/huandu/go-sqlbuilder) for SQL generation, [Tailwind CSS](https://tailwindcss.com/) with [DaisyUI](https://daisyui.com/) for UI & styling, and the [chi router](https://github.com/go-chi/chi) to manage the incoming HTTP requests.

Pull requests are encouraged. You can reach out to me at [contact@leodip.com](mailto:contact@leodip.com). Your involvement is welcome and appreciated.