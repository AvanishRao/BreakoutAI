# AI Email Campaign Dashboard

A Streamlit-based dashboard for managing intelligent email campaigns with LLM-enhanced content generation and analytics.

## Features

- Multiple data source integrations (CSV, Google Sheets)
- Multiple email provider support (SendGrid, Gmail, SMTP)
- LLM-powered email content enhancement
- Email scheduling and batch sending
- Real-time analytics and visualizations
- Export capabilities (CSV, Excel)
- Rate limiting and throttling

## Prerequisites

- Python 3.9+
- Docker and Docker Compose
- SendGrid API Key (optional)
- Google Cloud Console Account (for Gmail and Sheets API)
- Groq API Key (for LLM processing)

## Setup Instructions

### 1. Clone the Repository
```bash
git clone <repository-url>
cd <repository-name>
```

### 2. Configure API Keys and Credentials

Create a `.env` file in the root directory with the following:
```env
# API Keys
SENDGRID_API_KEY=your_sendgrid_api_key
GROQ_API_KEY=your_groq_api_key
SEARCH_API_KEY=your_serp_api_key

# Email Configuration
SENDER_EMAIL=your_verified_sender_email@domain.com
EMAIL_RATE_LIMIT=50

# Google API Credentials
SHEETS_CREDS_FILE=credentials.json
GMAIL_CREDS_FILE=gmail_credentials.json

# Redis Configuration
REDIS_URL=redis://redis:6379/0

# Other Settings
MAX_REQUESTS=100
```

### 3. Set Up Google Cloud Console

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Enable required APIs:
   - Google Sheets API
   - Gmail API

4. Create credentials:
   - For Sheets API:
     - Create Service Account
     - Download JSON key as `credentials.json`
   
   - For Gmail API:
     - Create OAuth 2.0 Client ID
     - Add authorized redirect URIs:
       ```
       http://localhost:8501
       http://localhost:8501/
       http://127.0.0.1:8501
       http://127.0.0.1:8501/
       ```
     - Download JSON as `gmail_credentials.json`

5. Place both credential files in the project root directory

### 4. SendGrid Setup (Optional)

1. Create a [SendGrid account](https://sendgrid.com)
2. Create and verify a sender identity
3. Create an API key with email sending permissions
4. Add the API key to your .env file

### 5. Docker Setup

1. Install [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

2. Build and run the containers:
```bash
docker-compose up --build
```

The application will be available at `http://localhost:8501`

## Project Structure
```
project/
├── .env                    # Environment variables
├── config.py              # Configuration management
├── data_handlers.py       # Data source handlers
├── docker-compose.yaml    # Docker compose configuration
├── Dockerfile            # Docker build instructions
├── email_handler.py      # Email service handlers
├── llm.py               # LLM processing logic
├── main.py              # Main application
├── models.py            # Data models
├── requirements.txt     # Python dependencies
├── search_engine.py     # Search functionality
├── credentials.json     # Google Sheets credentials
└── gmail_credentials.json # Gmail OAuth credentials
```

## Usage

1. Start the application:
```bash
docker-compose up
```

2. Open your browser and navigate to `http://localhost:8501`

3. Follow the UI steps:
   - Choose data source (CSV or Google Sheets)
   - Configure email provider
   - Set up email template
   - Configure sending schedule
   - Start campaign

4. Monitor progress in the Analytics tab

## Development

### Adding New Features

1. Create a new branch:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes
3. Update requirements.txt if needed:
```bash
pip freeze > requirements.txt
```

4. Test locally:
```bash
docker-compose up --build
```

### Running Tests
```bash
docker-compose run web pytest
```

## Troubleshooting

### Common Issues

1. Redis Connection Error:
```bash
docker-compose down
docker-compose up --build
```

2. Gmail Authentication Issues:
   - Verify redirect URIs in Google Console
   - Check gmail_credentials.json is present
   - Clear browser cookies and try again

3. SendGrid Errors:
   - Verify sender email is verified
   - Check API key permissions
   - Verify email content follows guidelines

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

For support, please create an issue in the repository or contact raoavanish99@gmail.com
