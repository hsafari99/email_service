import os
import base64
import requests
import logging
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from config.config_validator import load_config
from .base_email_service import BaseEmailService

# Setting up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

class GmailService(BaseEmailService):
    def __init__(self, client_id=None, client_secret=None, refresh_token=None):
        # Load credentials from environment variables validated by config_validator
        logger.debug("Initializing GmailService...")
        config = load_config()

        self.client_id = client_id or config.GMAIL_CLIENT_ID
        self.client_secret = client_secret or config.GMAIL_CLIENT_SECRET
        self.refresh_token = refresh_token or config.GMAIL_REFRESH_TOKEN

        # Initialize Gmail API credentials
        try:
            self.credentials = self._get_credentials()
            logger.info("Credentials successfully retrieved.")
        except Exception as e:
            logger.error(f"Error retrieving credentials: {e}")
            raise

        self.api_url = "https://www.googleapis.com/upload/gmail/v1/users/me/messages/send"

    def _get_credentials(self):
        """Retrieve credentials using OAuth2 refresh token."""
        logger.debug("Retrieving credentials with OAuth2 refresh token...")
        credentials = Credentials.from_authorized_user_info(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token
            }
        )
        if credentials and credentials.expired and credentials.refresh_token:
            logger.debug("Credentials expired, refreshing...")
            credentials.refresh(Request())
        return credentials

    def send_email(self, to_email, subject, body):
        """Send an email using the Gmail API."""
        logger.debug(f"Preparing to send email to {to_email} with subject: {subject}")
        
        # Sanitize subject and body
        subject = self._sanitize_input(subject)
        body = self._sanitize_input(body)

        # Prepare the email data in the format Gmail API expects
        message = self._create_message(to_email, subject, body)

        headers = {
            "Authorization": f"Bearer {self.credentials.token}",
            "Content-Type": "application/json"
        }

        logger.debug("Sending email...")
        response = requests.post(self.api_url, json=message, headers=headers)

        if response.status_code == 200:
            logger.info(f"Email sent successfully to {to_email}. Response: {response.json()}")
            return {"status": "success", "message": "Email sent successfully"}
        else:
            logger.error(f"Error sending email: {response.json().get('error', {}).get('message', 'Unknown error')}")
            raise Exception(f"Error sending email: {response.json().get('error', {}).get('message', 'Unknown error')}")

    def _create_message(self, to_email, subject, body):
        """Create a message in the Gmail API format."""
        message = {
            "raw": base64.urlsafe_b64encode(
                f"To: {to_email}\nSubject: {subject}\n\n{body}".encode("utf-8")
            ).decode("utf-8")
        }
        return message

    def _sanitize_input(self, input_data: str) -> str:
        """
        A utility method to sanitize the input (e.g., subject or body) to prevent XSS or other malicious injections.
        """
        if input_data:
            # Basic sanitation: Replace harmful characters (e.g., '<', '>', etc.)
            input_data = input_data.replace("<", "&lt;").replace(">", "&gt;")
            input_data = input_data.replace("&", "&amp;").replace('"', "&quot;")
            input_data = input_data.replace("'", "&#39;")
            logger.debug(f"Sanitized input: {input_data}")
        return input_data
