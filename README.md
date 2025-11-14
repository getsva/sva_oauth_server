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

Create a `.env` file in the backend directory (copy from `.env.example`):

```bash
cp .env.example .env
```

Edit `.env` and add your configuration:

- **SECRET_KEY**: Generate a Django secret key
- **EMAIL settings**: Configure for email verification
- **GOOGLE_CLIENT_ID** and **GOOGLE_CLIENT_SECRET**: From Google Cloud Console
- **GITHUB_CLIENT_ID** and **GITHUB_CLIENT_SECRET**: From GitHub Developer Settings

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
6. Add authorized redirect URIs:
   - `http://localhost:8001/accounts/google/login/callback/`
   - `http://127.0.0.1:8001/accounts/google/login/callback/`
7. Copy Client ID and Client Secret to `.env`:
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

- **Access Token**: Valid for 1 hour
- **Refresh Token**: Valid for 7 days

Include tokens in requests:
```
Authorization: Bearer <access_token>
```

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

1. Set `DEBUG=False` in `.env`
2. Generate a secure `SECRET_KEY`
3. Configure proper `ALLOWED_HOSTS`
4. Set up proper database (PostgreSQL recommended)
5. Configure production email backend
6. Set up static file serving
7. Use HTTPS for OAuth callbacks

## License

This project is part of the SVA OAuth application.

