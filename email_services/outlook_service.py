import requests
import logging
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

class OutlookService(BaseEmailService):
    def __init__(self, client_id=None, client_secret=None, refresh_token=None):
        # Load credentials from environment variables validated by config_validator
        logger.debug("Initializing OutlookService...")
        config = load_config()

        self.client_id = client_id or config.OUTLOOK_CLIENT_ID
        self.client_secret = client_secret or config.OUTLOOK_CLIENT_SECRET
        self.refresh_token = refresh_token or config.OUTLOOK_REFRESH_TOKEN

        # Initialize the OAuth2 token endpoint for Outlook API
        self.token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        self.api_url = "https://graph.microsoft.com/v1.0/me/sendMail"

        try:
            self.access_token = self._get_access_token()
            logger.info("Access token successfully obtained.")
        except Exception as e:
            logger.error(f"Error obtaining access token: {e}")
            raise

    def _get_access_token(self):
        """Fetch access token using the refresh token."""
        logger.debug("Fetching access token using refresh token...")
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'scope': 'Mail.Send'
        }
        response = requests.post(self.token_url, data=data)
        response_data = response.json()

        if response.status_code == 200:
            logger.debug("Access token obtained successfully.")
            return response_data['access_token']
        else:
            logger.error(f"Error fetching access token: {response_data.get('error_description', 'Unknown error')}")
            raise Exception(f"Error fetching access token: {response_data.get('error_description', 'Unknown error')}")

    def send_email(self, to_email, subject, body):
        """Send an email using the Outlook API."""
        logger.debug(f"Preparing to send email to {to_email} with subject: {subject}")
        
        # Sanitize subject and body
        subject = self._sanitize_input(subject)
        body = self._sanitize_input(body)

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

        email_data = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "Text",
                    "content": body
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": to_email
                        }
                    }
                ]
            }
        }

        logger.debug("Sending email...")
        response = requests.post(self.api_url, json=email_data, headers=headers)

        if response.status_code == 202:
            logger.info(f"Email sent successfully to {to_email}. Response: {response.json()}")
            return {"status": "success", "message": "Email sent successfully"}
        else:
            logger.error(f"Error sending email: {response.json().get('error', {}).get('message', 'Unknown error')}")
            raise Exception(f"Error sending email: {response.json().get('error', {}).get('message', 'Unknown error')}")

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
