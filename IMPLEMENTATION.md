# URL Shortener Implementation Summary

## Project Overview
A complete URL shortener service built with Go, Pebble database, Preact, and Pico CSS.

## Features Implemented

### Public Features
- **GET /{code}**: 302 redirects to target URL
  - Tracks usage count and last access timestamp
  - Returns 404 for missing codes
  - Returns 410 (Gone) for expired links
- **POST /api/public/routes**: Create short links
  - Supports 1d or 7d expiry (default: 1d)
  - Auto-generated codes using memorable words
  - Custom vanity codes supported
  - Reserved codes blocked: `auth`, `api`, `admin`

### Admin Features
- **OAuth Authentication**: Google (email domain allowlist) or GitHub (username allowlist)
- **Admin API Endpoints**:
  - GET /api/admin/routes - List all routes with statistics
  - POST /api/admin/routes - Create routes with 1d/7d/30d/permanent expiry
  - PUT /api/admin/routes/{code} - Edit existing routes
  - DELETE /api/admin/routes/{code} - Delete routes
- **Admin Dashboard**: Interactive UI for route management built with Preact

### Security Features
1. **URL Validation**: Only http and https URLs allowed
   - Prevents XSS via javascript: URLs
   - Prevents data: URL attacks
2. **Code Validation**: Alphanumeric characters and hyphens only (1-50 chars)
   - Prevents path traversal attacks
   - Prevents special character injection
3. **OAuth CSRF Protection**: Cryptographically secure random state parameters
4. **Secure Random Generation**: Using crypto/rand for code generation
5. **Session Security**: 
   - Proper error handling on session operations
   - Warning when using default SESSION_KEY
6. **Access Control**:
   - Empty allowlist filtering to prevent bypass
   - Email domain or GitHub username validation

## Technology Stack
- **Backend**: Go 1.x
- **Database**: Pebble (embedded key-value store)
- **Routing**: Gorilla Mux
- **Session Management**: Gorilla Sessions
- **Authentication**: OAuth 2.0 (Google & GitHub)
- **Frontend**: Preact with HTM (no build step required)
- **Styling**: Pico CSS (lightweight, semantic)

## File Structure
```
├── main.go              # Main application with all handlers
├── go.mod               # Go module definition
├── go.sum               # Go dependencies checksums
├── .env.example         # Environment variables template
├── .gitignore           # Git ignore patterns
├── README.md            # Project documentation
└── static/
    ├── index.html       # Public homepage
    └── admin/
        └── index.html   # Admin dashboard
```

## Setup Instructions

1. **Clone and Install**:
   ```bash
   git clone https://github.com/benwang2/a
   cd a
   go mod download
   ```

2. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your OAuth credentials and allowlists
   ```

3. **Run the Server**:
   ```bash
   go run main.go
   ```

4. **Access**:
   - Public interface: http://localhost:8080
   - Admin dashboard: http://localhost:8080/admin

## API Examples

### Create Public Route
```bash
curl -X POST http://localhost:8080/api/public/routes \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "expiry": "7d"}'
```

### Create Admin Route (requires authentication)
```bash
curl -X POST http://localhost:8080/api/admin/routes \
  -H "Content-Type: application/json" \
  -H "Cookie: auth-session=..." \
  -d '{"url": "https://example.com", "code": "custom", "expiry": "30d"}'
```

## Security Testing Results
- ✅ CodeQL Security Scan: 0 vulnerabilities
- ✅ JavaScript URL rejection test passed
- ✅ Data URL rejection test passed
- ✅ Path traversal rejection test passed
- ✅ Code validation test passed
- ✅ OAuth state parameter CSRF protection implemented

## Known Limitations & Future Enhancements
1. **Rate Limiting**: Currently no rate limiting on public route creation
   - Recommendation: Add IP-based rate limiting or CAPTCHA
2. **CORS**: No CORS headers configured
   - Currently same-origin only
   - Add CORS if cross-origin access needed
3. **Accessibility**: Some UI improvements suggested in code review
   - Use inline messages instead of alert()
   - Add ARIA labels for screen readers
4. **Permanent Links**: Using 100-year expiry as "permanent"
   - Could use explicit permanent flag instead

## Environment Variables
- `PORT`: Server port (default: 8080)
- `SESSION_KEY`: Secret key for session cookies
- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `GOOGLE_REDIRECT_URL`: Google OAuth callback URL
- `GITHUB_CLIENT_ID`: GitHub OAuth client ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth client secret
- `GITHUB_REDIRECT_URL`: GitHub OAuth callback URL
- `ALLOWED_DOMAINS`: Comma-separated email domains (e.g., "example.com,company.com")
- `ALLOWED_GITHUB_USERS`: Comma-separated GitHub usernames

## License
[Add license information]

## Contributors
- Implementation by GitHub Copilot
- Repository owner: benwang2
