from dataclasses import dataclass
from typing import Optional
import os
from dotenv import load_dotenv

@dataclass
class Config:
    SERP_API_KEY: str
    GROQ_API_KEY: str
    SHEETS_CREDS_FILE: str  # For Google Sheets
    GMAIL_CREDS_FILE: str   # For Gmail
    SENDGRID_API_KEY: str
    REDIS_URL: str
    SENDER_EMAIL: str
    MAX_REQUESTS: int = 100
    EMAIL_RATE_LIMIT: int = 50

    @classmethod
    def from_env(cls):
        load_dotenv()
        return cls(
            SERP_API_KEY=os.getenv('SEARCH_API_KEY', ''),
            GROQ_API_KEY=os.getenv('GROQ_API_KEY', ''),
            SHEETS_CREDS_FILE=os.getenv('SHEETS_CREDS_FILE', 'credentials.json'),
            GMAIL_CREDS_FILE=os.getenv('GMAIL_CREDS_FILE', 'gmail_credentials.json'),
            SENDGRID_API_KEY=os.getenv('SENDGRID_API_KEY', ''),
            REDIS_URL=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
            SENDER_EMAIL=os.getenv('SENDER_EMAIL', ''),
            MAX_REQUESTS=int(os.getenv('MAX_REQUESTS', '100')),
            EMAIL_RATE_LIMIT=int(os.getenv('EMAIL_RATE_LIMIT', '50'))
        )