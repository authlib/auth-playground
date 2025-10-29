# Auth Playground

A demonstration OAuth2 / OpenID Connect (OIDC) client application built with Flask.
This project illustrates how to integrate with an identity provider for user authentication, registration, and consent management.

## Installation


```bash
uv add auth-playground
```

or

```bash
docker run -p 4000:4000 auth-playground
pip install auth-playground
```

or

```bash
docker build -t auth-playground .
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
http://localhost:4000/login_callback
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
