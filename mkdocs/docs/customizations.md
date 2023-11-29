# Customize

## App name, issuer and UI theme

The most basic level of customization is to set the app name, issuer (the same as the public deployment URL) and also choosing a UI theme. Those things should be customized in the **admin area**, using the web interface.

## HTML templates

You can also modify any HTML template of Goiabada, if you wish, provided you don't break the existing UI code (the javascript sections, element ids, etc.). You need to be careful and know what you're doing.

The overall strategy is:

1. copy the `web` folder from container to host
2. make your modifications in the HTML/CSS files
2. relaunch the Goiabada container with a volume, mapping from host folder to container folder.

Example:

```bash
docker ps -a
```

This will list all containers - make a note of the Goiabada container ID. For example: `39ae6e1b54aa`. Then:

```bash
docker cp 39ae6e1b54aa:/app/web ./web
```

Now you have the `web` folder on your host, with all the HTML resources. You can change the HTML/CSS files as you want.

Now you need to relaunch the containers with a volume. You can add this to your `docker-compose.yml` (example):

```{.py3 title="Add the volume"}
(...)
depends_on: 
  mysql-server:
    condition: service_healthy  
volumes:
  - ./web:/app/web
command: sleep infinity
(...)
```

### Tailwind CSS

Goiabada uses [Tailwind CSS](https://tailwindcss.com/). When customizing the templates you can add/change Tailwind CSS classes if you wish. However, if you do that, it's necessary that you run the **Tailwind CLI tool**, after you finish editing the files. The Tailwind CLI tool will regenerate the file `main.css` that is used by the application.

You can download the Tailwind CLI tool here: [https://tailwindcss.com/blog/standalone-cli](https://tailwindcss.com/blog/standalone-cli).

Here's how you can regenerate the `main.css` file:

```
(the current folder here is one level up the web folder)

tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
```

