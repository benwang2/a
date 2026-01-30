# URL Shortener

A URL shortener built with Go, Pebble database, Preact, and Pico CSS.

## Features

### Public Access
- **GET /{code}**: Redirects to the target URL (302), tracks uses and last access time
  - Returns 404 if the code doesn't exist
  - Returns 410 (Gone) if the link has expired
- **POST /api/public/routes**: Create short links with 1d or 7d expiry (default: 1d)

### Admin Access
- OAuth authentication via Google or GitHub
- Access control via email domain allowlist (Google) or username allowlist (GitHub)
- Admin dashboard to:
  - List all routes with statistics
  - Create routes with 1d, 7d, 30d, or permanent expiry
  - Edit existing routes
  - Delete routes

### Code Generation
- Custom vanity codes supported
- Auto-generated codes use short, memorable words
- Reserved codes blocked: `auth`, `api`, `admin`

## Setup

1. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   ```

2. Set up OAuth applications:
   - **Google OAuth**: https://console.cloud.google.com/apis/credentials
   - **GitHub OAuth**: https://github.com/settings/developers

3. Update `.env` with your OAuth credentials and allowlists

4. Install dependencies:
   ```bash
   go mod download
   ```

5. Run the server:
   ```bash
   go run main.go
   ```

6. Access the application:
   - Public interface: http://localhost:8080
   - Admin dashboard: http://localhost:8080/admin

## API Endpoints

### Public
- `POST /api/public/routes` - Create a short link
  ```json
  {
    "url": "https://example.com",
    "code": "optional-custom-code",
    "expiry": "1d"  // "1d" or "7d"
  }
  ```

### Admin (Requires Authentication)
- `GET /api/admin/routes` - List all routes
- `POST /api/admin/routes` - Create a route
  ```json
  {
    "url": "https://example.com",
    "code": "optional-custom-code",
    "expiry": "1d"  // "1d", "7d", "30d", or "perma"
  }
  ```
- `PUT /api/admin/routes/{code}` - Update a route
- `DELETE /api/admin/routes/{code}` - Delete a route

## Technology Stack

- **Backend**: Go with Gorilla Mux for routing
- **Database**: Pebble (embedded key-value store)
- **Frontend**: Preact with HTM
- **Styling**: Pico CSS
- **Authentication**: OAuth 2.0 (Google & GitHub)