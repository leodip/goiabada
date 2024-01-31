# Installation

## Docker compose

The recommended and most convenient way to use Goiabada is via a container. Container images are available in [docker hub](https://hub.docker.com/repository/docker/leodip/goiabada).

To get started, feel free to use and customize the following [docker compose file](https://github.com/leodip/goiabada/raw/main/authserver/docker/docker-compose.yml). You can read more about the environment variables [here](envvars.md).

```{.py3 title="docker-compose.yml"}
--8<-- "docker-compose.yml"
```

If you have Docker working in your environment, save the above file and execute the following command:

`docker compose up -d`

Once the container is ready, you can access the application using the URL:

[http://localhost:8100](http://localhost:8100)

The default admin credentials are:

```text
Email: admin@example.com
Password: changeme
```

**Important**: the docker compose file given above is set up with HTTP (non-TLS), making it insecure. HTTP should only be used for testing or development purposes.

## SSL certs

HTTPS/TLS is essential for Goiabada to function securely. When you have the SSL cert for your domain, remember to make it available to the container, using a volume. Then, amend the environment variables `GOIABADA_CERTFILE` and `GOIABADA_KEYFILE` to point to your certification and key files, accordingly. Don't forget to use the correct port in your docker compose file.

You can have a look at the documentation of Docker [https://docs.docker.com/compose/compose-file/07-volumes/](https://docs.docker.com/compose/compose-file/07-volumes/) for details on how to map a volume.
