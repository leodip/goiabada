---
title: Architecture overview
description: Overview of Goiabada's architecture and components.
---

Goiabada is made up of three main parts:

- The **auth server**, which manages key endpoints for authorization, token exchange, and authentication forms
- The **admin console**, where you can change settings and manage user accounts and profiles
- A **database** that stores all the data

Starting with version 1.2, the admin console now communicates with the auth server through HTTP calls, and only the auth server accesses the database. This new design provides better separation of concerns and improved security.

![Goiabada architecture diagram](../../../assets/screenshot4.png)
