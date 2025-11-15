# Goiabada - Authentication & Authorization Server

## Project Overview
Goiabada is an open-source authentication and authorization server built with Go, designed to simplify user management for application developers. It provides comprehensive identity management with OAuth2/OpenID Connect support.

## Key Features
- **Authentication & Authorization**: Complete user identity management
- **Single Sign-On (SSO)**: Seamless authentication across applications
- **Two-Factor Authentication**: OTP-based 2FA support
- **OAuth2 & OpenID Connect**: Standards-compliant implementation
- **Dynamic Client Registration**: RFC 7591 support for self-registering OAuth clients (MCP, native apps)
- **Multi-Database Support**: MySQL, PostgreSQL, SQL Server, SQLite
- **Self-Service Account Management**: Users can manage their own profiles
- **Fine-Grained Permissions**: Resource and permission-based access control
- **Server-to-Server Auth**: Client credentials flow for API authentication

## Architecture

### Core Components
The project is organized into three main Go modules:

#### 1. **Core Module** (`src/core/`)
- **Location**: `src/core/go.mod`
- **Purpose**: Shared business logic, data models, and database operations
- **Key Dependencies**:
  - Database drivers: MySQL, PostgreSQL, SQL Server, SQLite
  - JWT handling (`golang-jwt/jwt/v5`)
  - Database migrations (`golang-migrate/migrate/v4`)
  - Email functionality (`xhit/go-simple-mail/v2`)
  - OTP generation (`pquerna/otp`)

#### 2. **Auth Server** (`src/authserver/`)
- **Location**: `src/authserver/go.mod`
- **Main Binary**: `src/authserver/cmd/goiabada-authserver/main.go`
- **Purpose**: Handles authentication flows, token generation, and user-facing auth pages
- **Key Features**:
  - OAuth2/OpenID Connect endpoints
  - Dynamic Client Registration endpoint (`/connect/register` - RFC 7591)
  - User login/registration flows
  - 2FA/OTP enrollment and validation
  - Session management
  - Rate limiting for security-sensitive endpoints
  - HTML templates for auth UI (`src/authserver/web/template/`)

#### 3. **Admin Console** (`src/adminconsole/`)
- **Location**: `src/adminconsole/go.mod`
- **Main Binary**: `src/adminconsole/cmd/goiabada-adminconsole/main.go`
- **Purpose**: Administrative interface for managing users, clients, permissions
- **Key Features**:
  - User and group management
  - Client application configuration
  - Resource and permission management
  - System configuration

## Development Environment

### Building the Project
Each module has its own Makefile with standard targets:

```bash
# Auth Server
cd src/authserver
make build          # Build with Tailwind CSS compilation
make serve          # Development server with hot reload (requires Air)
make test-ci        # Run integration tests
make test-local     # Run tests against running server
make check          # Static analysis and linting

# Admin Console
cd src/adminconsole
make build
make serve
make test-local
make check
```

### Development Tools
- **Air**: Hot reload for development (`make serve`)
- **Tailwind CSS**: Frontend styling compilation
- **Static Analysis**: `staticcheck`, `golangci-lint`, `unparam`

### Testing
- **Integration Tests**: `src/authserver/tests/integration/`
- **Data Layer Tests**: `src/authserver/tests/data/`
- **Test Script**: `run-tests.sh` for CI environments

## Database Schema
The core module handles database migrations and supports:
- **MySQL**: Production-ready setup
- **PostgreSQL**: Full feature support
- **SQL Server**: Enterprise environments
- **SQLite**: Development/testing (see `/tmp/goiabada.db`)

## Docker Deployment
Multiple deployment configurations available in `src/build/`:
- `docker-compose-mysql.yml`: MySQL backend
- `docker-compose-sqlite.yml`: SQLite backend
- `docker-compose-direct.yml`: Direct access setup
- `docker-compose-reverse-proxy.yml`: Behind reverse proxy
- `Dockerfile-authserver` & `Dockerfile-adminconsole`: Service images

## Technology Stack
- **Backend**: Go 1.25.4
- **Web Framework**: Chi router (`go-chi/chi/v5`)
- **Authentication**: JWT tokens, session management
- **Frontend**: Server-rendered HTML with Tailwind CSS
- **Security**: CSRF protection, rate limiting, CORS handling
- **Databases**: Multiple SQL database support
- **Email**: SMTP with DKIM support
- **Testing**: Extensive integration and unit test coverage

## Key Dependencies
- **Chi Router**: HTTP routing and middleware
- **JWT**: Token generation and validation
- **CSRF Protection**: Gorilla CSRF middleware  
- **Session Management**: Gorilla sessions
- **Database Migrations**: golang-migrate
- **OTP/2FA**: TOTP implementation
- **Email**: Simple mail library with DKIM
- **Countries**: Internationalization support

## Development Workflow
1. **Local Development**: Use `make serve` for hot reload
2. **Frontend Changes**: Tailwind CSS auto-compilation
3. **Testing**: Run integration tests with `make test-local`
4. **Static Analysis**: `make check` for code quality
5. **Docker Testing**: Use docker-compose files for environment testing

## Integration Testing
The project includes comprehensive integration tests covering:
- OAuth2 authorization flows
- Dynamic Client Registration (RFC 7591)
- Token endpoint functionality
- User authentication workflows
- Database operations
- API endpoints

## Common Commands
```bash
# Start development server
make serve

# Build and test
make build && make test-ci

# Run static analysis
make check

# Generate SSL certificates for development  
make cert

# Run specific test suites
go test -v ./tests/integration/...
go test -v ./tests/data/...
```

## Documentation
- **Official Docs**: https://goiabada.dev
- **Docker Images**: https://hub.docker.com/r/leodip/goiabada/tags
- **GitHub**: https://github.com/leodip/goiabada

## Important
Do not make any changes, until you have 95% confidence that you know what to build ask me follow up questions until you have that confidence.

