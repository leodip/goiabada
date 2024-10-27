# Customize

## App name, issuer and UI theme

The most basic level of customization is to set the app name, issuer (the same as the public deployment URL) and also choosing a UI theme. Those things should be customized in the **admin area**, using the web interface.

## HTML templates

You can also modify any HTML template of Goiabada, if you wish, provided you don't break the existing UI code (the javascript sections, element ids, etc.). You need to be careful and know what you're doing.

The overall strategy is:

1. copy the `web` folder from container to host
2. make your modifications in the HTML/CSS files
3. relaunch the Goiabada container with a volume, mapping from host folder to container folder.
4. set `GOIABADA_AUTHSERVER_TEMPLATEDIR` and/or `GOIABADA_ADMINCONSOLE_TEMPLATEDIR` to mapped folder. You can also set `GOIABADA_AUTHSERVER_STATICDIR` and/or `GOIABADA_ADMINCONSOLE_STATICDIR` to a mapped folder, if you want to serve static files from the filesystem.

### Tailwind CSS

Goiabada uses [Tailwind CSS](https://tailwindcss.com/). When customizing the templates you can add/change Tailwind CSS classes if you wish. If you do that, it's necessary that you run the **Tailwind CLI tool**, after you finish editing the files. The Tailwind CLI tool will regenerate the file `main.css` that is used by the application.

You can download the Tailwind CLI tool here: [https://tailwindcss.com/blog/standalone-cli](https://tailwindcss.com/blog/standalone-cli).

Here's how you can regenerate the `main.css` file:

```
(the current folder here is one level up the web folder)

tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
```

