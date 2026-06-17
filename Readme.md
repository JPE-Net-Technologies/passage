# Intro

An open-source, composable authentication framework project providing secure OAuth/OIDC integrations,
designed as a reusable backbone for enterprise-grade applications.

> ⚠️ **WARNING**: This project is currently a prototype under construction and is not fit for production, or
> general usage, yet.

Passage is distributed **package-first**: you depend on `@passage/core` and start from a runnable preset, rather
than forking and diverging. That keeps upgrades non-intrusive to your configuration and code.

**Why would you want to use Passage?**

- Organizations have **identity sprawl**: Auth0 for customers, Okta for employees, custom solutions for partners
- No clean way to present a unified identity interface to internal applications
- Each identity provider has different APIs, token formats, user schemas
- Applications end up with brittle multi-provider integration logic
- Migration between providers is organizationally traumatic

> 📑 **Conceptual / Vision Diagram of Passage**
> ![img.png](readme/media/conceptual-architectural-diagram.png)

## How it's distributed

Passage is a **bun-workspace monorepo**:

```
packages/
  core/                 # @passage/core — the installable identity-broker core
examples/
  keycloak-basic/       # a runnable preset that federates a local Keycloak upstream
```

- **`@passage/core`** is the package you consume. Config is *injected* (it never reads your
  working directory), so you build an `AppConfig` and mount the app:

  ```ts
  import { createApp } from '@passage/core';
  import { loadAppConfig } from '@passage/core/config';

  const app = await createApp(loadAppConfig('./config'));
  app.listen(3000);
  ```

- **Presets** under `examples/` are full, runnable deployments. Copy one as your starting
  point — it owns its `config/`, its KMS keystore, and its process lifecycle.

Get the example running:

```bash
bun install
task launch          # start the preset's Keycloak + datastore (docker-compose)
task server:dev      # boot examples/keycloak-basic on :3000
task test            # run the core suite (enforces 100% line/statement coverage)
```

## Readme Directory

This readme is only an introductory overview of what Passage does.
Setup, technical docs, and diagrams can be found in the [readme](./readme) directory.

## Superpower your development!
Uses the Bun as a package manager and runtime for blazing fast speeds, especially for Express.js (https://bun.com/).

> We aim to make this project as easy to use as possible, loading-up on secure and powerful developer tools:
> - Git
> - Docker
> - Bun
> - Taskfile (a modernized GNU-make; check out [Taskfile.dist.yml](./Taskfile.dist.yml)!)

> **Timeline of Development**
> ![img.png](readme/media/timeline.png)
