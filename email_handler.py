import base64
from email.mime.text import MIMEText
import pickle
import redis
import logging
import base64
from email.mime.text import MIMEText
import pickle
import redis
import logging
import os
import time
import streamlit as st
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import pandas as pd
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
import json
from sendgrid.helpers.mail import (
    Mail,
    Email,
    To,
    Content
)
from sendgrid import SendGridAPIClient

class EmailHandler:
    def __init__(self, config):
        """Initialize EmailHandler with configuration."""
        self.config = config
        self.sendgrid_client = None
        self.redis_client = None
        self.gmail_creds = None
        self.smtp_settings = None
        
        if self._initialize_redis():
            self._initialize_sendgrid()
            self._setup_gmail_oauth()

    def _initialize_redis(self) -> bool:
        """Initialize Redis connection with retry logic."""
        max_retries = 5
        retry_delay = 2  
        
        for attempt in range(max_retries):
            try:
                redis_url = os.getenv('REDIS_URL', self.config.REDIS_URL)
                
                if 'redis://redis:' in redis_url and attempt == 0:
                    redis_url = redis_url.replace('redis://redis:', 'redis://localhost:')
                
                st.write(f"Connecting to Redis at: {redis_url}")  # Debug info
                
                self.redis_client = redis.Redis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                

                self.redis_client.ping()
                st.success("Successfully connected to Redis")
                logging.info("Successfully connected to Redis")
                return True
                
            except redis.ConnectionError as e:
                st.warning(f"Attempt {attempt + 1}/{max_retries} to connect to Redis...")
                logging.warning(f"Redis connection attempt {attempt + 1} failed: {str(e)}")
                
                if attempt == max_retries - 1:
                    st.error(f"""
                    Failed to connect to Redis after {max_retries} attempts.
                    Please check:
                    1. Redis service is running (docker-compose ps)
                    2. Redis URL is correct: {redis_url}
                    3. Redis container logs: docker-compose logs redis
                    """)
                    return False
                    
                time.sleep(retry_delay)
                
            except Exception as e:
                st.error(f"Unexpected Redis error: {str(e)}")
                logging.error(f"Redis initialization error: {str(e)}")
                return False
        
        return False

    def _initialize_sendgrid(self):
        """Initialize SendGrid client if API key is available."""
        if hasattr(self.config, 'SENDGRID_API_KEY') and self.config.SENDGRID_API_KEY:
            try:
                self.sendgrid_client = SendGridAPIClient(api_key=self.config.SENDGRID_API_KEY)
                logging.info("Successfully initialized SendGrid client")
            except Exception as e:
                st.warning("SendGrid initialization failed. Email sending will be simulated.")
                logging.warning(f"SendGrid initialization error: {str(e)}")

    def _send_via_sendgrid(self, to_email: str, subject: str, content: str) -> bool:
        """Send email using SendGrid."""
        try:
            if not self.sendgrid_client:
                raise Exception("SendGrid client not initialized")
                
            if not self.config.SENDER_EMAIL:
                raise Exception("Sender email not configured")
            
            st.write("Creating SendGrid mail object...")    
            message = Mail(
                from_email=Email(self.config.SENDER_EMAIL),
                to_emails=To(to_email),
                subject=subject,
                html_content=Content("text/html", content)
            )
            
            st.write("Attempting to send via SendGrid...")
            try:
                response = self.sendgrid_client.send(message)
                if response.status_code not in [200, 202]:
                    st.error(f"SendGrid API error: Status code {response.status_code}")
                    return False
                st.success("Email sent successfully via SendGrid!")
                return True
                
            except Exception as send_error:
                st.error(f"SendGrid sending error: {str(send_error)}")
                return False
                
        except Exception as e:
            st.error(f"SendGrid setup error: {str(e)}")
            return False

    def _initialize_sendgrid(self):
        """Initialize SendGrid client if API key is available."""
        if hasattr(self.config, 'SENDGRID_API_KEY') and self.config.SENDGRID_API_KEY:
            try:
                self.sendgrid_client = SendGridAPIClient(api_key=self.config.SENDGRID_API_KEY)
                logging.info("Successfully initialized SendGrid client")
            except Exception as e:
                st.warning("SendGrid initialization failed. Email sending will be simulated.")
                logging.warning(f"SendGrid initialization error: {str(e)}")
                self.sendgrid_client = None
        else:
            st.warning("SendGrid API key not configured. Email sending will be simulated.")
            self.sendgrid_client = None

    def send_email(self, to_email: str, subject: str, content: str) -> bool:
        """Send an email using the configured provider."""
        try:
            st.write(f"Attempting to send email to: {to_email}")
            st.write(f"Current provider setup:")
            st.write(f"- SendGrid configured: {bool(self.sendgrid_client)}")
            st.write(f"- Gmail configured: {bool(self.gmail_creds)}")
            st.write(f"- SMTP configured: {bool(self.smtp_settings)}")
            
            if self.sendgrid_client:
                st.write("Attempting to send via SendGrid...")
                success = self._send_via_sendgrid(to_email, subject, content)
                st.write(f"SendGrid result: {'Success' if success else 'Failed'}")
                return success
            elif self.gmail_creds:
                st.write("Attempting to send via Gmail...")
                success = self._send_via_gmail(to_email, subject, content)
                st.write(f"Gmail result: {'Success' if success else 'Failed'}")
                return success
            elif self.smtp_settings:
                st.write("Attempting to send via SMTP...")
                success = self._send_via_smtp(to_email, subject, content)
                st.write(f"SMTP result: {'Success' if success else 'Failed'}")
                return success
            else:
                st.warning("No email provider configured. Simulating email send.")
                return self._simulate_email_send(to_email, subject, content)
                
        except Exception as e:
            st.error(f"Error sending email: {str(e)}")
            st.exception(e)  # This will show the full traceback
            logging.error(f"Error sending email: {str(e)}")
            return False

    def _send_via_gmail(self, to_email: str, subject: str, content: str) -> bool:
        """Send email using Gmail API."""
        try:
            st.write("Checking Gmail credentials...")
            if not self.gmail_creds:
                st.write("No credentials in memory, checking Redis...")
                creds_data_str = self.redis_client.get('gmail_credentials')
                if not creds_data_str:
                    raise Exception("Gmail not authenticated - No credentials found in Redis")
                
                st.write("Found credentials in Redis, loading...")
                creds_data = json.loads(creds_data_str)
                expiry = datetime.fromisoformat(creds_data['expiry']) if creds_data.get('expiry') else None
                
                self.gmail_creds = Credentials(
                    token=creds_data['token'],
                    refresh_token=creds_data['refresh_token'],
                    token_uri=creds_data['token_uri'],
                    client_id=creds_data['client_id'],
                    client_secret=creds_data['client_secret'],
                    scopes=creds_data['scopes'].split(','),
                    expiry=expiry
                )

            # Check if credentials need refresh
            st.write("Checking if credentials need refresh...")
            if self.gmail_creds.expired and self.gmail_creds.refresh_token:
                st.write("Credentials expired, refreshing...")
                self.gmail_creds.refresh(Request())
                st.write("Credentials refreshed successfully")
                # Update stored credentials
                creds_data = {
                    'token': self.gmail_creds.token,
                    'refresh_token': self.gmail_creds.refresh_token,
                    'token_uri': self.gmail_creds.token_uri,
                    'client_id': self.gmail_creds.client_id,
                    'client_secret': self.gmail_creds.client_secret,
                    'scopes': ','.join(self.gmail_creds.scopes),
                    'expiry': self.gmail_creds.expiry.isoformat() if self.gmail_creds.expiry else None
                }
                self.redis_client.set('gmail_credentials', json.dumps(creds_data))
            
            st.write("Building Gmail service...")
            service = build('gmail', 'v1', credentials=self.gmail_creds)
            
            st.write("Creating email message...")
            message = MIMEText(content, 'html')
            message['to'] = to_email
            message['subject'] = subject
            message['from'] = self.config.SENDER_EMAIL
            
            st.write("Encoding email message...")
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            
            st.write("Sending email via Gmail API...")
            service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            st.success("Email sent successfully via Gmail!")
            return True
            
        except Exception as e:
            st.error(f"Gmail sending error: {str(e)}")
            st.exception(e)  # This will show the full traceback
            logging.error(f"Gmail sending error: {str(e)}")
            return False

    def _simulate_email_send(self, to_email: str, subject: str, content: str) -> bool:
        """Simulate email sending for testing."""
        st.info(f"""
        Simulating email send:
        To: {to_email}
        Subject: {subject}
        Content length: {len(content)} characters
        Content preview: {content[:100]}...
        """)
        return True

    def get_batch_list(self) -> List[str]:
        """Get list of all email batches with error handling."""
        try:
            if not self.redis_client:
                return []
                
            batch_keys = self.redis_client.keys('batch:*')
            return [key.split(':')[1] for key in batch_keys] if batch_keys else []
            
        except redis.ConnectionError as e:
            st.error("Lost connection to Redis. Attempting to reconnect...")
            self._initialize_redis()
            return []
        except Exception as e:
            st.error(f"Error retrieving batch list: {str(e)}")
            return []

 

    def get_batch_analytics(self, batch_id: str) -> Dict:
        """Get analytics for a batch of emails with error handling."""
        try:
            if not self.redis_client:
                raise Exception("Redis client not initialized")
                
            # Get all email IDs for batch
            email_ids = self.redis_client.smembers(f"batch:{batch_id}")
            if not email_ids:
                return {
                    'total': 0,
                    'sent': 0,
                    'failed': 0,
                    'scheduled': 0,
                    'opened': 0
                }
            
            analytics = {
                'total': len(email_ids),
                'sent': 0,
                'failed': 0,
                'scheduled': 0,
                'opened': 0
            }
            
            # Process each email
            for email_id in email_ids:
                status_data = self.get_email_status(email_id)
                
                if status_data:
                    status = status_data.get('status', '')
                    if status == 'sent':
                        analytics['sent'] += 1
                        if status_data.get('opened') == 'true':
                            analytics['opened'] += 1
                    elif status == 'failed':
                        analytics['failed'] += 1
                    elif status == 'scheduled':
                        analytics['scheduled'] += 1
                        
            return analytics
            
        except redis.ConnectionError as e:
            st.error("Lost connection to Redis. Please check if Redis server is running.")
            logging.error(f"Redis connection error in get_batch_analytics: {str(e)}")
            return {'error': 'Redis connection failed'}
        except Exception as e:
            st.error(f"Error retrieving batch analytics: {str(e)}")
            logging.error(f"Error in get_batch_analytics: {str(e)}")
            return {'error': str(e)}

    def get_email_status(self, email_id: str) -> Optional[Dict]:
        """Get the current status of an email."""
        try:
            if not self.redis_client:
                raise Exception("Redis client not initialized")
                
            status_data = self.redis_client.hgetall(f"email_status:{email_id}")
            return status_data if status_data else None
            
        except redis.ConnectionError as e:
            logging.error(f"Redis connection error in get_email_status: {str(e)}")
            return None
        except Exception as e:
            logging.error(f"Error in get_email_status: {str(e)}")
            return None

    def get_detailed_status(self, batch_id: str) -> Optional[pd.DataFrame]:
        """Get detailed status for all emails in a batch."""
        try:
            if not self.redis_client:
                raise Exception("Redis client not initialized")
                
            email_ids = self.redis_client.smembers(f"batch:{batch_id}")
            detailed_status = []
            
            for email_id in email_ids:
                email_data = self.redis_client.hgetall(f"email:{email_id}")
                status_data = self.redis_client.hgetall(f"email_status:{email_id}")
                
                if email_data and status_data:
                    status_dict = {
                        'Email': email_data.get('to_email', ''),
                        'Status': status_data.get('status', ''),
                        'Scheduled Time': status_data.get('scheduled_time', ''),
                        'Sent Time': status_data.get('sent_time', ''),
                        'Delivery Status': status_data.get('delivery_status', ''),
                        'Error': status_data.get('error', '')
                    }
                    detailed_status.append(status_dict)
            
            if detailed_status:
                import pandas as pd
                return pd.DataFrame(detailed_status)
            
            return None
            
        except redis.ConnectionError as e:
            st.error("Lost connection to Redis. Please check if Redis server is running.")
            logging.error(f"Redis connection error in get_detailed_status: {str(e)}")
            return None
        except Exception as e:
            st.error(f"Error retrieving detailed status: {str(e)}")
            logging.error(f"Error in get_detailed_status: {str(e)}")
            return None
        
    def create_batch(self, df: pd.DataFrame, template_config: Dict) -> str:
        """Create a new email batch from DataFrame."""
        try:
            batch_id = f"batch_{datetime.now().timestamp()}"
            
            # Store batch metadata - convert None to empty string
            batch_meta = {
                'created_at': datetime.now().isoformat(),
                'total_emails': str(len(df)),  # Convert to string
                'template_subject': template_config.get('subject', ''),
                'template_content': template_config.get('content', ''),
                'status': 'created'
            }
            
            # Convert all values to strings
            batch_meta = {k: str(v) if v is not None else '' for k, v in batch_meta.items()}
            self.redis_client.hmset(f"batch_meta:{batch_id}", batch_meta)
            
            # Process each row and create email entries
            for _, row in df.iterrows():
                email_id = f"email_{datetime.now().timestamp()}_{row.name}"
                
                # Replace template variables
                subject = template_config['subject']
                content = template_config['content']
                
                for col in df.columns:
                    placeholder = f"{{{col}}}"
                    if placeholder in subject:
                        subject = subject.replace(placeholder, str(row[col]))
                    if placeholder in content:
                        content = content.replace(placeholder, str(row[col]))
                
                # Store email data - convert all values to strings
                email_data = {
                    'batch_id': batch_id,
                    'to_email': str(row[template_config['email_column']]),
                    'subject': subject,
                    'content': content,
                    'created_at': datetime.now().isoformat()
                }
                
                # Convert any None values to empty strings
                email_data = {k: str(v) if v is not None else '' for k, v in email_data.items()}
                self.redis_client.hmset(f"email:{email_id}", email_data)
                self.redis_client.sadd(f"batch:{batch_id}", email_id)
                
                # Initialize status
                status_data = {
                    'status': 'pending',
                    'created_at': datetime.now().isoformat(),
                    'scheduled_time': '',
                    'sent_time': '',
                    'delivery_status': '',
                    'error': ''
                }
                self.redis_client.hmset(f"email_status:{email_id}", status_data)
            
            return batch_id
            
        except Exception as e:
            logging.error(f"Error creating batch: {str(e)}")
            raise

    def process_batch(self, batch_id: str, schedule_config: Optional[Dict] = None) -> bool:
        """Process a batch of emails with optional scheduling."""
        try:
            # Get all email IDs in batch
            email_ids = self.redis_client.smembers(f"batch:{batch_id}")
            
            if not email_ids:
                raise ValueError(f"No emails found in batch {batch_id}")
            
            # Update batch status
            self.redis_client.hset(f"batch_meta:{batch_id}", 'status', 'processing')
            
            for email_id in email_ids:
                try:
                    email_data = self.redis_client.hgetall(f"email:{email_id}")
                    
                    if schedule_config:
                        # Handle scheduling
                        if schedule_config.get('type') == 'batch':
                            # Calculate send time based on batch position
                            batch_size = schedule_config.get('batch_size', 20)
                            interval_hours = schedule_config.get('interval_hours', 1)
                            position = list(email_ids).index(email_id)
                            batch_number = position // batch_size
                            send_time = datetime.fromisoformat(schedule_config['start_time']) + \
                                      timedelta(hours=batch_number * interval_hours)
                        else:
                            # Single scheduled time for all emails
                            send_time = datetime.fromisoformat(schedule_config['start_time'])
                            
                        # Schedule the email
                        self.schedule_email(
                            email_data['to_email'],
                            email_data['subject'],
                            email_data['content'],
                            send_time
                        )
                        
                        status_update = {
                            'status': 'scheduled',
                            'scheduled_time': send_time.isoformat(),
                            'sent_time': '',
                            'error': ''
                        }
                        
                    else:
                        # Send immediately
                        success = self.send_email(
                            email_data['to_email'],
                            email_data['subject'],
                            email_data['content']
                        )
                        
                        status_update = {
                            'status': 'sent' if success else 'failed',
                            'sent_time': datetime.now().isoformat() if success else '',
                            'error': '' if success else 'Failed to send email',
                            'scheduled_time': ''
                        }
                    
                    # Convert all values to strings and replace None with empty string
                    status_update = {k: str(v) if v is not None else '' for k, v in status_update.items()}
                    self.redis_client.hmset(f"email_status:{email_id}", status_update)
                    
                except Exception as e:
                    error_msg = str(e)
                    logging.error(f"Error processing email {email_id}: {error_msg}")
                    self.redis_client.hmset(f"email_status:{email_id}", {
                        'status': 'failed',
                        'error': error_msg,
                        'sent_time': '',
                        'scheduled_time': ''
                    })
            
            # Update batch status
            self.redis_client.hset(f"batch_meta:{batch_id}", 'status', 'completed')
            return True
            
        except Exception as e:
            error_msg = str(e)
            logging.error(f"Error processing batch: {error_msg}")
            self.redis_client.hset(f"batch_meta:{batch_id}", 'status', 'failed')
            raise

    def update_delivery_status(self, batch_id: str):
        """Update delivery status for all emails in a batch."""
        try:
            email_ids = self.redis_client.smembers(f"batch:{batch_id}")
            
            for email_id in email_ids:
                status_data = self.redis_client.hgetall(f"email_status:{email_id}")
                
                if status_data.get('status') == 'sent':
                    try:
                        # Check delivery status from email provider
                        if self.sendgrid_client:
                            # Implement SendGrid delivery status check
                            pass
                        elif self.gmail_creds:
                            # Implement Gmail delivery status check
                            pass
                        elif self.smtp_settings:
                            # SMTP doesn't provide delivery status
                            pass
                            
                    except Exception as e:
                        logging.error(f"Error checking delivery status for {email_id}: {str(e)}")
                        
        except Exception as e:
            logging.error(f"Error updating delivery status for batch {batch_id}: {str(e)}")

    def get_rate_limits(self) -> Dict:
        """Get current rate limit status."""
        try:
            now = datetime.now()
            hour_key = f"email_count:{now.strftime('%Y-%m-%d:%H')}"
            
            # Get current hour's count
            hour_count = int(self.redis_client.get(hour_key) or 0)
            
            return {
                'hourly_limit': self.config.EMAIL_RATE_LIMIT,
                'hourly_used': hour_count,
                'hourly_remaining': max(0, self.config.EMAIL_RATE_LIMIT - hour_count)
            }
            
        except Exception as e:
            logging.error(f"Error getting rate limits: {str(e)}")
            return {
                'hourly_limit': 0,
                'hourly_used': 0,
                'hourly_remaining': 0
            }

    def cleanup_old_data(self, days: int = 30):
        """Clean up old email and batch data."""
        try:
            cutoff = datetime.now() - timedelta(days=days)
            
            # Get all batch IDs
            batch_keys = self.redis_client.keys('batch:*')
            
            for batch_key in batch_keys:
                batch_id = batch_key.split(':')[1]
                batch_meta = self.redis_client.hgetall(f"batch_meta:{batch_id}")
                
                if batch_meta and 'created_at' in batch_meta:
                    created_at = datetime.fromisoformat(batch_meta['created_at'])
                    
                    if created_at < cutoff:
                        # Delete batch data
                        email_ids = self.redis_client.smembers(f"batch:{batch_id}")
                        
                        for email_id in email_ids:
                            self.redis_client.delete(f"email:{email_id}")
                            self.redis_client.delete(f"email_status:{email_id}")
                            
                        self.redis_client.delete(f"batch:{batch_id}")
                        self.redis_client.delete(f"batch_meta:{batch_id}")
                        
            logging.info(f"Cleaned up data older than {days} days")
            
        except Exception as e:
            logging.error(f"Error cleaning up old data: {str(e)}")

    def get_system_status(self) -> Dict:
        """Get overall system status."""
        try:
            return {
                'redis_connected': bool(self.redis_client and self.redis_client.ping()),
                'sendgrid_configured': bool(self.sendgrid_client),
                'gmail_configured': bool(self.gmail_creds),
                'smtp_configured': bool(self.smtp_settings),
                'rate_limits': self.get_rate_limits()
            }
        except Exception as e:
            logging.error(f"Error getting system status: {str(e)}")
            return {
                'redis_connected': False,
                'sendgrid_configured': False,
                'gmail_configured': False,
                'smtp_configured': False,
                'rate_limits': {'error': str(e)}
            }
    
    def _setup_gmail_oauth(self):
        """Set up Gmail OAuth configuration."""
        try:
            # Define Gmail API scopes
            self.GMAIL_SCOPES = [
                'https://www.googleapis.com/auth/gmail.send',
                'https://www.googleapis.com/auth/gmail.readonly'
            ]
            self.gmail_creds = None
            self.credentials_path = self.config.GMAIL_CREDS_FILE  # Changed from GOOGLE_CREDS_FILE
                
            if not os.path.exists(self.credentials_path):
                raise FileNotFoundError(f"Google Gmail credentials file not found at {self.credentials_path}")
                    
        except Exception as e:
                st.error(f"Gmail OAuth setup error: {str(e)}")
                raise

    def get_gmail_auth_url(self) -> str:
        """Generate Gmail OAuth authorization URL."""
        try:
            self._setup_gmail_oauth()
            
            flow = InstalledAppFlow.from_client_secrets_file(
                self.credentials_path,
                self.GMAIL_SCOPES,
                redirect_uri='http://localhost:8501'
            )
            
            # Generate authorization URL first
            auth_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true'
            )
            
            # Now store necessary flow information
            auth_config = {
                'client_id': flow.client_config['client_id'],
                'client_secret': flow.client_config['client_secret'],
                'scopes': ','.join(self.GMAIL_SCOPES),
                'redirect_uri': 'http://localhost:8501',
                'state': state  # Store the generated state
            }
            
            # Store auth config in Redis as a JSON string
            self.redis_client.set('gmail_auth_config', json.dumps(auth_config))
            
            return auth_url
                
        except Exception as e:
            st.error(f"Failed to generate Gmail auth URL: {str(e)}")
            raise

    def handle_gmail_callback(self, auth_code: str) -> bool:
        """Handle Gmail OAuth callback."""
        try:
            # Retrieve auth config from Redis
            auth_config_str = self.redis_client.get('gmail_auth_config')
            if not auth_config_str:
                raise Exception("Authentication configuration not found. Please try again.")
            
            auth_config = json.loads(auth_config_str)
            
            # Create a new flow instance
            flow = InstalledAppFlow.from_client_secrets_file(
                self.credentials_path,
                scopes=auth_config['scopes'].split(','),
                redirect_uri=auth_config['redirect_uri'],
                state=auth_config['state']  # Use the stored state
            )
            
            # Exchange auth code for credentials
            try:
                credentials = flow.fetch_token(
                    code=auth_code,
                    state=auth_config['state']
                )
            except Exception as token_error:
                st.error(f"Error exchanging code for token: {str(token_error)}")
                return False

            # Store credentials data
            creds_data = {
                'token': flow.credentials.token,
                'refresh_token': flow.credentials.refresh_token,
                'token_uri': flow.credentials.token_uri,
                'client_id': flow.credentials.client_id,
                'client_secret': flow.credentials.client_secret,
                'scopes': ','.join(flow.credentials.scopes),
                'expiry': flow.credentials.expiry.isoformat() if flow.credentials.expiry else None
            }
            
            # Store as JSON string
            self.redis_client.set('gmail_credentials', json.dumps(creds_data))
            self.gmail_creds = flow.credentials
            
            # Clean up auth config
            self.redis_client.delete('gmail_auth_config')
            
            return True
            
        except Exception as e:
            st.error(f"Gmail authentication failed: {str(e)}")
            return False

    def _send_via_gmail(self, to_email: str, subject: str, content: str) -> bool:
        """Send email using Gmail API."""
        try:
            if not self.gmail_creds:
                creds_data_str = self.redis_client.get('gmail_credentials')
                if not creds_data_str:
                    raise Exception("Gmail not authenticated")
                
                creds_data = json.loads(creds_data_str)
                expiry = datetime.fromisoformat(creds_data['expiry']) if creds_data.get('expiry') else None
                
                self.gmail_creds = Credentials(
                    token=creds_data['token'],
                    refresh_token=creds_data['refresh_token'],
                    token_uri=creds_data['token_uri'],
                    client_id=creds_data['client_id'],
                    client_secret=creds_data['client_secret'],
                    scopes=creds_data['scopes'].split(','),
                    expiry=expiry
                )

            # Check if credentials need refresh
            if self.gmail_creds.expired and self.gmail_creds.refresh_token:
                self.gmail_creds.refresh(Request())
                # Update stored credentials
                creds_data = {
                    'token': self.gmail_creds.token,
                    'refresh_token': self.gmail_creds.refresh_token,
                    'token_uri': self.gmail_creds.token_uri,
                    'client_id': self.gmail_creds.client_id,
                    'client_secret': self.gmail_creds.client_secret,
                    'scopes': ','.join(self.gmail_creds.scopes),
                    'expiry': self.gmail_creds.expiry.isoformat() if self.gmail_creds.expiry else None
                }
                self.redis_client.set('gmail_credentials', json.dumps(creds_data))
            
            service = build('gmail', 'v1', credentials=self.gmail_creds)
            
            message = MIMEText(content, 'html')
            message['to'] = to_email
            message['subject'] = subject
            
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            return True
            
        except Exception as e:
            logging.error(f"Gmail sending error: {str(e)}")
            return False

