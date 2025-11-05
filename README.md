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

### Registering with your Identity Provider

When registering this application with your identity provider, configure the following redirect URIs:

```
http://localhost:4000/authorize_callback
http://localhost:4000/logout_callback
```

## Usage

```bash
auth-playground
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
