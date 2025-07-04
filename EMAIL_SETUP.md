# Email Configuration Setup

To enable the forgot password functionality, you need to configure email settings in your backend.

## Step 1: Create .env file

Create a `.env` file in the `backend` directory with the following content:

```env
# Server Configuration
PORT=5000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/portfolio_db

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# CORS Configuration
CORS_ORIGIN=http://localhost:3000

# Frontend URL (for password reset links)
FRONTEND_URL=http://localhost:3000

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
EMAIL_FROM=your-email@gmail.com
```

## Step 2: Configure Gmail (Recommended)

1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate an App Password**:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate a new app password for "Mail"
   - Use this password as `EMAIL_PASS`

## Step 3: Alternative Email Providers

You can use other email providers by changing the `EMAIL_HOST`:

- **Outlook/Hotmail**: `smtp-mail.outlook.com`
- **Yahoo**: `smtp.mail.yahoo.com`
- **Custom SMTP**: Use your provider's SMTP settings

## Step 4: Test Configuration

After setting up the `.env` file, restart your backend server and try the forgot password functionality.

## Troubleshooting

If you get email errors:
1. Check that all email environment variables are set
2. Verify your email credentials
3. Make sure 2FA is enabled and app password is generated (for Gmail)
4. Check that the email provider allows SMTP access

## Security Notes

- Never commit your `.env` file to version control
- Use strong, unique passwords for email accounts
- Consider using environment-specific configurations for production 