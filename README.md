# Goiabada

**Self-hosted sign-in, single sign-on, and permissions for your apps.**

Goiabada is a standards-based, open-source authentication server built on **OAuth 2.0** and **OpenID Connect**. Your apps can use standard libraries to sign users in and obtain tokens; you choose where the auth server and database run.

**[Try it locally](https://goiabada.dev/get-started/quickstart/)** · **[Add sign-in to a web app](https://goiabada.dev/guides/add-sign-in-to-a-web-app/)** · **[Explore the docs](https://goiabada.dev/)**

## What you get

- **One account across your apps.** Single sign-on, authorization code flow with PKCE, and optional two-factor authentication with step-up for sensitive apps.
- **Control over access.** Give users, groups, and clients permissions; include groups and custom attributes in tokens when your apps need them.
- **An admin console and API.** Manage users, clients, settings, and signing keys through the web UI or automate them through the API. Review changes in the audit log.
- **Account self-service.** Users can manage their profile and security settings, recover a password, and review their sessions. You can enable self-registration and email verification.
- **A choice of deployment.** The setup wizard prepares Docker Compose, Kubernetes, or native binary deployments. Use SQLite, PostgreSQL, MySQL, or SQL Server. Docker images support x86_64 and ARM64.

You can also enable [dynamic client registration](https://goiabada.dev/guides/let-clients-register-themselves-dcr/) for apps such as MCP clients.

## Get started

The [quickstart](https://goiabada.dev/get-started/quickstart/) runs Goiabada locally with Docker Compose and SQLite in a few minutes. When you're ready to run it for others, [choose a deployment method](https://goiabada.dev/deploy/choose-a-method/).

[Documentation](https://goiabada.dev/) · [Contributing](https://goiabada.dev/about/contributing/) · [MIT license](LICENSE)

[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge-flat.svg)](https://github.com/avelino/awesome-go)
