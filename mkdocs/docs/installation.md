# Installation

## Docker compose

The most convenient way to use Goiabada is via a container. 

Container images are available in [docker hub](https://hub.docker.com/repository/docker/leodip/goiabada).

To get started, feel free to use and customize the following docker compose file. You can download it by right clicking [this link](https://github.com/leodip/goiabada/raw/main/authserver/docker/docker-compose.yml) and 'save as'.

```{.py3 title="docker-compose.yml"}
--8<-- "docker-compose.yml"
```

If you have Docker working in your environment, save the above file and execute the following command:

`docker compose up -d`

Once the container is ready, you can access the application using the following URL:

[https://localhost:8100](https://localhost:8100)

The default admin credentials are:

```text
Email: admin@example.com
Password: changeme
```

## SSL certs

Goiabada requires SSL to work. When you have the SSL certs for your domain, remember to make them available to the container, using a volume. Then, please amend the environment variables `GOIABADA_CERTFILE` and `GOIABADA_KEYFILE` to point to your certification and key files, accordingly.

You can have a look at [Customizations - HTML templates](customizations.md#html-templates) to see an example of docker volume mapping.
