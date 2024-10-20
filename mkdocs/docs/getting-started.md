# Getting started

## Overview of Goiabada architecture

Goiabada is made up of three main parts:

- the auth server, which manages key endpoints for things like authorization, token exchange, and authentication forms; 
- the admin console, where you can adjust settings and manage user accounts and profiles;
- and lastly, a shared database that's used by both.

![Screenshot](img/screenshot4.png)

## How to run it?

The easiest and recommended way to use Goiabada is through containers, with images available on [docker hub](https://hub.docker.com/repository/docker/leodip/goiabada).

To get started, you can use and customize the docker compose files below. For more details on environment variables, check [here](envvars.md).

### Docker compose (mysql)

```{.py3 title="docker-compose-mysql.yml"}
--8<-- "docker-compose-mysql.yml"
```

### Docker compose (sqlite)

```{.py3 title="docker-compose-sqlite.yml"}
--8<-- "docker-compose-sqlite.yml"
```

If you’ve got Docker running in your environment, just save the docker compose file and run this command:

`docker compose -f docker-compose.yml up -d`

Once the container is up and running, you can access the admin console at:

[http://localhost:8081](http://localhost:8081)

The admin credentials are either what you’ve set in the environment variables, or by default:

```text
Email: admin@example.com
Password: changeme
```

⚠️ Important: the docker compose files provided above are configured with HTTP (non-TLS), making it **not secure**. HTTP should only be used for testing or development purposes.

## SSL certs

HTTPS/TLS is essential for Goiabada to function securely. When you have the SSL cert for your domain, remember to make it available to the container, using a volume. Then, amend the environment variables `GOIABADA_AUTHSERVER_CERTFILE`, `GOIABADA_AUTHSERVER_KEYFILE`, `GOIABADA_ADMINCONSOLE_CERTFILE` and `GOIABADA_ADMINCONSOLE_KEYFILE` to point to your certification and key files, accordingly. Don't forget to assign the correct port in your docker compose file.

You can have a look at the documentation of Docker [https://docs.docker.com/compose/compose-file/07-volumes/](https://docs.docker.com/compose/compose-file/07-volumes/) for details on how to map a volume.
