# SVA OAuth Backend

Django REST API backend with Google OAuth, GitHub OAuth, and custom email authentication with email verification.

## Features

- ✅ Custom user authentication (email/password)
- ✅ Email verification for custom signups
- ✅ Google OAuth integration
- ✅ GitHub OAuth integration
- ✅ JWT token authentication
- ✅ RESTful API endpoints
- ✅ CORS support for frontend integration

## Setup Instructions

### 1. Install Dependencies

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Environment Configuration

Create environment-specific configuration files:

**For Local Development:**
```bash
cp .env.local .env
```

**For Production:**
```bash
cp .env.production .env
```

The application automatically loads `.env.local` for development or `.env.production` for production based on the `ENVIRONMENT` variable.

Edit the appropriate `.env` file and configure the following:

#### Required for Development:
- **DJANGO_SECRET_KEY**: Generate a Django secret key (or use default for dev)
- **ENVIRONMENT**: Set to `development` for local development

#### Required for Production:
- **DJANGO_SECRET_KEY**: Generate a secure Django secret key
- **ENVIRONMENT**: Set to `production`
- **ALLOWED_HOSTS**: Comma-separated list of allowed hosts
- **DATABASE_URL**: PostgreSQL connection string
- **CORS_ALLOWED_ORIGINS**: Comma-separated list of allowed frontend origins
- **EMAIL settings**: SMTP configuration for email verification
- **INTERNAL_SERVICE_TOKEN**: Token for service-to-service communication
- **DATA_TOKEN_SECRET**: Secret key for data tokens (must match sva_server)

#### Optional Configuration:
- **JWT_ACCESS_TOKEN_LIFETIME_HOURS**: Access token lifetime (default: 1 hour)
- **JWT_REFRESH_TOKEN_LIFETIME_DAYS**: Refresh token lifetime (default: 7 days)
- **FRONTEND_URL**: Frontend URL for email links and OAuth redirects
- **CORE_CONSENT_URL**: URL for OAuth consent screen

#### OAuth Provider Settings:
OAuth credentials are configured via Django Admin or the `setup_oauth` management command:
- **GOOGLE_CLIENT_ID** and **GOOGLE_CLIENT_SECRET**: From Google Cloud Console
- **GITHUB_CLIENT_ID** and **GITHUB_CLIENT_SECRET**: From GitHub Developer Settings

See `.env.local` or `.env.production` for a complete list of all available environment variables.

### 3. Database Migration

```bash
python manage.py makemigrations
python manage.py migrate
```

### 4. Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

### 5. Setup OAuth Applications

After configuring your OAuth credentials in `.env`, run:

```bash
python manage.py setup_oauth
```

Alternatively, you can configure them manually in Django Admin:
1. Go to `http://localhost:8001/admin/`
2. Navigate to "Social Applications"
3. Add Google and GitHub OAuth apps with your credentials

### 6. Run Development Server

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8001`

## API Endpoints

### Authentication

- `POST /api/auth/register/` - Register new user
- `POST /api/auth/login/` - Login user
- `POST /api/auth/verify-email/` - Verify email with token
- `POST /api/auth/resend-verification/` - Resend verification email

### User Profile

- `GET /api/auth/profile/` - Get current user profile (requires authentication)
- `PUT /api/auth/profile/update/` - Update user profile (requires authentication)

### OAuth

- `POST /api/auth/google/` - Google OAuth login
- `POST /api/auth/github/` - GitHub OAuth login
- `GET /api/auth/oauth-urls/` - Get OAuth login URLs

## OAuth Setup

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API and Google Identity API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Set Application type to "Web application"
6. Add authorized redirect URIs (include both if you use backend and frontend flows):
   - Backend callback: `http://localhost:8001/accounts/google/login/callback/`, `http://127.0.0.1:8001/accounts/google/login/callback/`
   - Frontend callback (e.g. sva_oauth_client): `http://localhost:8081/auth/callback/google`, `http://127.0.0.1:8081/auth/callback/google`
7. Copy Client ID and Client Secret to `.env.local` or `.env`:
   ```
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   ```
8. Run `python manage.py setup_oauth` to configure the app

### GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: SVA OAuth (or your app name)
   - **Homepage URL**: `http://localhost:5173`
   - **Authorization callback URL**: `http://localhost:8001/accounts/github/login/callback/`
4. Copy Client ID and Client Secret to `.env`:
   ```
   GITHUB_CLIENT_ID=your-client-id
   GITHUB_CLIENT_SECRET=your-client-secret
   ```
5. Run `python manage.py setup_oauth` to configure the app

## Email Verification

Email verification tokens are sent via email when users register. Tokens expire after 24 hours.

For development, emails are printed to console by default. For production, configure SMTP settings in `.env`.

## Frontend Integration

The backend is configured to accept requests from:
- `http://localhost:5173` (Vite default)
- `http://localhost:3000` (React default)

Update `CORS_ALLOWED_ORIGINS` in `config/settings.py` for additional origins.

## JWT Tokens

The API uses JWT tokens for authentication:

- **Access Token**: Valid for 1 hour (configurable via `JWT_ACCESS_TOKEN_LIFETIME_HOURS`)
- **Refresh Token**: Valid for 7 days (configurable via `JWT_REFRESH_TOKEN_LIFETIME_DAYS`)

Include tokens in requests:
```
Authorization: Bearer <access_token>
```

Token lifetimes can be configured via environment variables in `.env`.

## Project Structure

```
backend/
├── config/
│   ├── settings.py      # Django settings
│   ├── urls.py          # Main URL configuration
│   └── wsgi.py          # WSGI configuration
├── accounts/
│   ├── models.py        # User and EmailVerificationToken models
│   ├── serializers.py   # API serializers
│   ├── views.py         # API views
│   ├── urls.py          # Account URLs
│   └── admin.py         # Admin configuration
├── manage.py
├── requirements.txt
└── .env                 # Environment variables (not in git)
```

## Development

### Running Tests

```bash
python manage.py test
```

### Creating Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### Accessing Admin Panel

```bash
python manage.py runserver
# Visit http://localhost:8001/admin/
```

## Production Deployment

Before deploying to production:

1. Set `ENVIRONMENT=production` in `.env` (DEBUG will automatically be False)
2. Generate a secure `DJANGO_SECRET_KEY`:
   ```bash
   python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
   ```
3. Configure `ALLOWED_HOSTS` (comma-separated list):
   ```
   ALLOWED_HOSTS=oauth-api.azurewebsites.net,oauth-api.getsva.com
   ```
4. Set up PostgreSQL database and configure `DATABASE_URL`
5. Configure production email backend (SMTP settings)
6. Set `CORS_ALLOWED_ORIGINS` to your production frontend URLs
7. Configure `INTERNAL_SERVICE_TOKEN` and `DATA_TOKEN_SECRET` (must match sva_server)
8. Set `FRONTEND_URL` and `CORE_CONSENT_URL` to production URLs
9. Use HTTPS for OAuth callbacks
10. Run `python manage.py collectstatic` to collect static files

### Environment File Structure

The application supports environment-specific configuration files:
- **Development**: Copy `.env.local` to `.env` (or set `ENVIRONMENT=development`)
- **Production**: Copy `.env.production` to `.env` (or set `ENVIRONMENT=production`)

The system automatically loads:
- `.env.local` when `ENVIRONMENT=development` (or defaults to development)
- `.env.production` when `ENVIRONMENT=production`
- Falls back to `.env` if the environment-specific file doesn't exist

**Note**: The `ENVIRONMENT` variable can be set in the file itself or as a system environment variable (useful for deployment platforms like Azure App Service).

## License

This project is part of the SVA OAuth application.

