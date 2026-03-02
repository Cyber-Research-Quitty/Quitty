# Web App Microservices Demo

This folder now contains a small shopping application with separate services for:

- `auth`: login, JWT validation, and authenticated profile data
- `product`: product catalog for the storefront home page
- `cart`: JWT-protected cart API
- `db`: cart persistence with SQLite
- `frontend`: Next.js storefront with Home, Cart, and Profile views

## User Flow

1. Visitors land on a storefront home page with products.
2. They log in through `auth`.
3. The frontend stores the JWT and loads the profile from `auth /me`.
4. Products are fetched from `product`.
5. Cart actions go through `cart`, which validates the JWT.
6. `db` stores cart items.

## Run with Docker

```bash
docker compose -f web-app/docker-compose.yml up --build -d
```

Services:

- Frontend: `http://localhost:3000`
- Auth API: `http://localhost:8001`
- DB API: `http://localhost:8002`
- Cart API: `http://localhost:8003`
- Product API: `http://localhost:8004`

## Demo Login

- Email: `alice@example.com`
- Password: `password123`

## Stop the stack

```bash
docker compose -f web-app/docker-compose.yml down
```
