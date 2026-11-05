# Auth Service

Auth Service is a Spring Boot microservice responsible for user authentication, credential management, and JWT-based authorization in the Marketplace application.

It provides secure registration and login, issues access and refresh tokens, validates JWTs, and exposes a JSON Web Key Set (JWKS) endpoint so other services can verify issued tokens.

## Features

- User registration with profile creation through User Service.
- Secure password storage using BCrypt.
- JWT access and refresh token generation.
- RSA-based RS256 token signing.
- Refresh token validation and rotation.
- User and role information stored in JWT claims.
- Public JWKS endpoint for token verification by other services.
- Bootstrap administrator configuration.
- Global exception handling with consistent API error responses.
- Database schema management using Liquibase.
- Docker-based deployment.

## Technology Stack

- Java 21
- Spring Boot 3.4
- Spring Security
- Spring Data JPA
- PostgreSQL
- Liquibase
- JSON Web Tokens (JWT)
- RSA / RS256
- BCrypt
- Maven
- Docker and Docker Compose
- JUnit and Mockito

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Registers a new user and creates authentication credentials |
| POST | `/api/auth/login` | Authenticates a user and returns access and refresh tokens |
| POST | `/api/auth/refresh` | Issues new tokens using a valid refresh token |
| GET | `/.well-known/jwks.json` | Returns public RSA key information for JWT verification |

## Architecture

Auth Service communicates with User Service during registration to create a user profile and obtain the generated user ID.

Authentication credentials are stored locally in the Auth Service database. Passwords are hashed using BCrypt.

After successful authentication, the service issues:
- **Access token** — used to authorize API requests.
- **Refresh token** — used to obtain a new token pair.

Tokens are signed using the RS256 algorithm. Other services can retrieve the public key through the JWKS endpoint and independently verify token signatures.

## Configuration

Application configuration is provided through Spring profiles and environment variables.

Important configuration properties:

| Variable | Description |
|---|---|
| `DB_URL` | PostgreSQL JDBC connection URL |
| `DB_USERNAME` | Database username |
| `DB_PASSWORD` | Database password |
| `USER_SERVICE_URL` | Base URL of User Service |
| `JWT_PRIVATE_KEY_PATH` | Path to the RSA private key |
| `JWT_PUBLIC_KEY_PATH` | Path to the RSA public key |
| `ADMIN_USERNAME` | Bootstrap administrator username |
| `ADMIN_PASSWORD` | Bootstrap administrator password |
| `ADMIN_USER_ID` | Bootstrap administrator user ID |

## JWT RSA Key Configuration

Auth Service uses a 2048-bit RSA key pair to sign and verify JWTs using RS256.

The key files are stored in the project-level `secrets/` directory:

```text
secrets/
├── private_key.pem
└── public_key.pem
```

The private key uses PKCS#8 PEM encoding, while the public key uses X.509 SubjectPublicKeyInfo PEM encoding. These formats are required by the RSA key-loading implementation in `JwtService`.

### Generating a key pair

OpenSSL is used to generate the RSA keys. Run the following commands from the project root:

```bash
mkdir -p secrets

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out secrets/private_key.pem

openssl pkey \
  -in secrets/private_key.pem \
  -pubout \
  -out secrets/public_key.pem
```

The generated files have the following PEM headers:

- Private key: `-----BEGIN PRIVATE KEY-----`
- Public key: `-----BEGIN PUBLIC KEY-----`

### Local execution

When running the application locally, the default key paths are:

```text
./secrets/private_key.pem
./secrets/public_key.pem
```

These paths can be overridden using the `JWT_PRIVATE_KEY_PATH` and `JWT_PUBLIC_KEY_PATH` environment variables.

### Docker execution

Docker Compose mounts the same key files as Docker secrets. Inside the container, they are available at:

```text
/run/secrets/jwt_private_key
/run/secrets/jwt_public_key
```

This allows the application to use the same RSA key pair in both local and containerized environments.

## Database

PostgreSQL is used to store authentication credentials.

Liquibase manages database schema changes and applies migrations during application startup.

The credentials table stores user references, usernames, BCrypt password hashes, roles, and audit timestamps.

## Running the Application

### Prerequisites

- Java 21
- Maven 3.9+
- PostgreSQL 16 (for local execution)
- OpenSSL (for RSA key generation)
- Docker and Docker Compose (for containerized execution)

### Build and test

```bash
mvn clean test
```

### Run locally

Configure the required environment variables, prepare the RSA key pair, and start the application:

```bash
mvn spring-boot:run
```

The service runs on port `8082` by default.

### Run with Docker Compose

After configuring the required environment variables and preparing the RSA key files, run:

```bash
docker compose up --build
```

To stop the containers:

```bash
docker compose down
```

## Project Structure

```text
src/
├── main/
│   ├── java/com/marketplace/authservice/
│   │   ├── config/
│   │   ├── controller/
│   │   ├── dto/
│   │   ├── entity/
│   │   ├── exception/
│   │   ├── mapper/
│   │   ├── repository/
│   │   └── service/
│   └── resources/
│       ├── db/changelog/
│       └── application.yml
└── test/
    └── java/com/marketplace/authservice/
```

## Security

- Passwords are stored as BCrypt hashes.
- JWTs are signed using RSA with RS256.
- Private keys are used only by Auth Service for token signing.
- Public keys are exposed through the JWKS endpoint.
- The application verifies that the configured public and private keys form a matching pair during startup.
- Secret files and environment-specific credentials are excluded from version control.