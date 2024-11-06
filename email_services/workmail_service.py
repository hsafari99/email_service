import boto3
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

class WorkMailService(BaseEmailService):
    def __init__(self, region_name, access_key, secret_key, workmail_domain):
        # Load credentials from environment variables validated by config_validator
        logger.debug("Initializing WorkMailService...")
        config = load_config()

        self.client = boto3.client(
            'workmail',
            region_name=region_name,
            aws_access_key_id=access_key or config.WORKMAIL_ACCESS_KEY,
            aws_secret_access_key=secret_key or config.WORKMAIL_SECRET_KEY
        )
        self.workmail_domain = workmail_domain or config.WORKMAIL_DOMAIN
        logger.info(f"WorkMailService initialized for domain: {self.workmail_domain}")

    def send_email(self, to_email, subject, body):
        """
        Send an email through AWS WorkMail.
        
        Args:
        - to_email (str): Recipient email address.
        - subject (str): Subject of the email.
        - body (str): Body of the email.
        
        Returns:
        - response (dict): The response from the WorkMail API.
        """
        logger.debug("Preparing to send email...")
        
        # Email source will be from the WorkMail domain
        from_email = f"noreply@{self.workmail_domain}"
        
        # Ensure that subject and body are sanitized for safety (e.g., no harmful content)
        subject = self._sanitize_input(subject)
        body = self._sanitize_input(body)
        
        logger.debug(f"Sending email to {to_email} with subject: {subject}")

        try:
            # Send email using AWS WorkMail
            response = self.client.send_raw_email(
                Source=from_email,
                Destinations=[to_email],
                RawMessage={
                    'Data': f"Subject: {subject}\n\n{body}"
                }
            )
            logger.info(f"Email sent successfully to {to_email}. Response: {response}")
            return response
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}. Error: {e}")
            raise

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