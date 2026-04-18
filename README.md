# Go Auth Portfolio

This project is a portfolio-ready example of authorization in Go using Gin.

It demonstrates:

- JWT-based authentication
- Access and refresh token flow
- Password hashing with bcrypt
- Role-based authorization middleware
- Layered structure: config, repository, service, handler, middleware
- A runnable service with no external database dependency

## Features

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /me`
- `GET /admin/overview`

## Architecture

The code is split into small layers:

- `internal/config`: environment loading
- `internal/model`: domain models
- `internal/repository/memory`: in-memory persistence for users and refresh sessions
- `internal/service`: authentication and token issuance
- `internal/httpapi/handler`: Gin request handlers
- `internal/httpapi/middleware`: auth and role checks
- `cmd/api`: application bootstrap

## Auth Flow

### 1. Register

1. Client sends name, email, and password.
2. The password is hashed with bcrypt.
3. The user is stored in the repository.
4. The service returns an access token and refresh token.

### 2. Login

1. Client sends email and password.
2. Password is verified against the stored bcrypt hash.
3. A new access token and refresh token are issued.

### 3. Access Protected Routes

1. Client sends `Authorization: Bearer <access_token>`.
2. Middleware validates the JWT signature, type, and expiry.
3. The request reaches the handler only if the token is valid.

### 4. Refresh

1. Client sends the refresh token.
2. The refresh token is validated and checked against the active session store.
3. The old refresh token is consumed.
4. A new access token and refresh token are issued.

### 5. Logout

1. Client sends the refresh token.
2. The active refresh session is revoked.
3. The token cannot be used again.

## Authorization Model

- Regular users can call `/me`
- Admin users can call `/admin/overview`
- Authorization is handled by middleware, not by the handler itself

## Configuration

The service reads these environment variables:

- `PORT` - server port, default `8080`
- `APP_ENV` - `development` or `production`
- `JWT_SECRET` - signing key, default `change-me-in-production`
- `ACCESS_TOKEN_TTL` - access token lifetime, default `15m`
- `REFRESH_TOKEN_TTL` - refresh token lifetime, default `168h`
- `ADMIN_EMAIL` - seeded admin email, default `admin@example.com`
- `ADMIN_PASSWORD` - seeded admin password, default `Admin123!`

## Run

### 1. Install dependencies

```bash
go mod tidy
```

### 2. Configure env

```bash
cp .env.example .env
```

### 3. Start the service

```bash
go run ./cmd/api
```

### 4. Optional environment example

```bash
export JWT_SECRET="a-long-random-secret"
export PORT=8080
export ADMIN_EMAIL="admin@example.com"
export ADMIN_PASSWORD="Admin123!"
go run ./cmd/api
```

## Example Requests

### Register

```bash
curl -s -X POST http://localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "Password123!"
  }'
```

### Login

```bash
curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "jane@example.com",
    "password": "Password123!"
  }'
```

### Me

```bash
curl -s http://localhost:8080/me \
  -H "Authorization: Bearer <access_token>"
```

### Admin Overview

```bash
curl -s http://localhost:8080/admin/overview \
  -H "Authorization: Bearer <admin_access_token>"
```

## Notes

- This implementation uses in-memory storage so it is easy to run locally and present in a portfolio.
- For production, replace the repository with a persistent database and store refresh sessions in a durable table or cache.
- The refresh token flow already follows a rotation pattern, which is the important security piece to keep.
