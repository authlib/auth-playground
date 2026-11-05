# Auth Playground

[![Tests](https://github.com/authlib/auth-playground/actions/workflows/tests.yaml/badge.svg)](https://github.com/authlib/auth-playground/actions/workflows/tests.yaml)
[![Docker](https://github.com/authlib/auth-playground/actions/workflows/publish-docker.yaml/badge.svg)](https://github.com/authlib/auth-playground/actions/workflows/publish-docker.yaml)
[![Docker Image](https://ghcr-badge.egpl.dev/authlib/auth-playground/latest_tag?trim=major&label=latest)](https://github.com/authlib/auth-playground/pkgs/container/auth-playground)

A demonstration OAuth2 / OpenID Connect (OIDC) client application built with [Authlib](https://authlib.org).
This project illustrates how to integrate with an identity provider for user authentication, registration, and consent management.
It can be used to play with the different interactions between clients and server, or debug a server implementation.

## Installation

### Using pip

```bash
pip install auth-playground
```

### Using uv

```bash
uv add auth-playground
```

### Using uvx

```bash
uvx auth-playground
```

### Using Docker

Run the pre-built image from GitHub Container Registry:

```bash
docker run -p 4000:4000 -e SECRET_KEY="your-secret-key" ghcr.io/authlib/auth-playground:latest
```

Or build locally:

```bash
docker build -t auth-playground .
docker run -p 4000:4000 -e SECRET_KEY="your-secret-key" auth-playground
```

## Configuration

The application is configured using environment variables. Copy the example configuration file:

```bash
cp example.env .env
```

Edit `.env` and set the required values:

```bash
# Required
export SECRET_KEY="your-secret-key"

# Optional
export OAUTH_CLIENT_ID="your-client-id"
export OAUTH_CLIENT_SECRET="your-client-secret"
export OAUTH_AUTH_SERVER="https://your-identity-provider.example.com"
```

### Running behind a reverse proxy

If the application runs behind a reverse proxy or a load balancer, enable the proxy support:

```bash
export PROXY_FIX=true
```

The application then trusts the `X-Forwarded-Proto` and `X-Forwarded-Prefix` headers set by the closest proxy.
For example, the redirect URIs use `https` when the proxy handles TLS.
They also start with the path prefix when the application is served under a sub-path.
It also trusts `X-Forwarded-For`, which only changes the client address shown in the logs.
Only enable it when a proxy is present.
Without a proxy, clients could forge these headers.

The proxy must set `X-Forwarded-Proto` and forward the original `Host` header.
It must also set `X-Forwarded-Prefix`, or clear it when the application is served at the root.
Otherwise clients could send their own prefix.
With nginx, at the root of the domain:

```nginx
location / {
    proxy_pass http://127.0.0.1:4000;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix "";
}
```

Under a sub-path, the proxy removes the prefix from the request path and sends it in `X-Forwarded-Prefix`:

```nginx
location /playground/ {
    proxy_pass http://127.0.0.1:4000/;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /playground;
}
```

With several proxies, the inner proxies must pass on the `X-Forwarded-Proto` and `X-Forwarded-Prefix` headers they receive.

### Registering with your Identity Provider

When registering this application with your identity provider, configure the following redirect URIs:

```
http://localhost:4000/authorize_callback
http://localhost:4000/logout_callback
```

## Usage

```bash
uv run auth-playground
```

The application will be available at `http://localhost:4000`

## Development

### Running Tests

```bash
uv run pytest
```

### Code Style

```bash
uv run prek run --all-files
```

### Git Hooks

Install the hooks once per clone:

```bash
uv run prek install
```

They check the code style before each commit.
They also check that commit messages follow [Conventional Commits](https://www.conventionalcommits.org).

### Front-end dependencies

The front-end dependencies are listed in `package.json` and pinned in `package-lock.json`.
Their files are copied in `src/auth_playground/static/vendor` and committed, so Node is not needed to run or build the application.
To update a dependency, install the new version and copy its files:

```bash
npm install @anyblades/blades@3.1.1
npm run vendor
```

Renovate only updates `package.json` and `package-lock.json`.
On its pull requests, run `npm ci && npm run vendor` and commit the result.

### Translations

After you add or change a translatable string, update the catalog:

```bash
uv run prek run pybabel-extract --all-files
```
