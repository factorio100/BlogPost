# BlogPost
BlogPost is a Django-powered blog application created as a learning project to deepen understanding of web development using the Django framework.

# Features
- User authentication (custom user model).
- Create, edit, and delete blog posts.
- Comment system for posts.
-	reCAPTCHA integration for enhanced security.
-	Email verification for user signups.
-	Fully responsive design using Bootstrap.
-	Environment-specific settings for development and production.

# Tech Stack
-	Language: Python
-	Framework: Django
-	Database: SQLite (development), PostgreSQL (production)
-	Frontend: Bootstrap
-	Hosting: Render
-	Other Tools: WhiteNoise for static file management, Django reCAPTCHA

# Installation Instructions
- Clone the repository:
git clone <repository-url>
cd blogpost

- Create a virtual environment:
python -m venv venv
source venv/bin/activate  

- Install dependencies:
pip install -r requirements.txt

# Environment Variables
Ensure the following environment variables are set:
-	SECRET_KEY: Django's secret key.
-	DEBUG: Set to True for development, False for production.
-	DATABASE_URL: Connection string for the PostgreSQL database in production.
-	EMAIL_HOST_USER and EMAIL_HOST_PASSWORD: Credentials for the email backend.
-	RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET_KEY: reCAPTCHA credentials.
