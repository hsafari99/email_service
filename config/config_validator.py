# config/config_validator.py

from pydantic import BaseSettings, validator, ValidationError, Field
from typing import Optional

class EmailConfig(BaseSettings):
    # Common credentials
    TO_EMAIL: str = Field(..., env="TO_EMAIL")  # Email address to receive messages

    # WorkMail credentials
    WORKMAIL_REGION: str = Field(..., env="WORKMAIL_REGION")
    WORKMAIL_ACCESS_KEY: str = Field(..., env="WORKMAIL_ACCESS_KEY")
    WORKMAIL_SECRET_KEY: str = Field(..., env="WORKMAIL_SECRET_KEY")
    WORKMAIL_DOMAIN: str = Field(..., env="WORKMAIL_DOMAIN")

    # Gmail credentials
    GMAIL_CLIENT_ID: str = Field(..., env="GMAIL_CLIENT_ID")
    GMAIL_CLIENT_SECRET: str = Field(..., env="GMAIL_CLIENT_SECRET")
    GMAIL_REFRESH_TOKEN: str = Field(..., env="GMAIL_REFRESH_TOKEN")

    # Outlook credentials
    OUTLOOK_CLIENT_ID: str = Field(..., env="OUTLOOK_CLIENT_ID")
    OUTLOOK_CLIENT_SECRET: str = Field(..., env="OUTLOOK_CLIENT_SECRET")
    OUTLOOK_REFRESH_TOKEN: str = Field(..., env="OUTLOOK_REFRESH_TOKEN")

    # Yahoo credentials
    YAHOO_APP_PASSWORD: str = Field(..., env="YAHOO_APP_PASSWORD")
    YAHOO_USERNAME: str = Field(..., env="YAHOO_USERNAME")

    # Zoho credentials
    ZOHO_CLIENT_ID: str = Field(..., env="ZOHO_CLIENT_ID")
    ZOHO_CLIENT_SECRET: str = Field(..., env="ZOHO_CLIENT_SECRET")
    ZOHO_REFRESH_TOKEN: str = Field(..., env="ZOHO_REFRESH_TOKEN")

    class Config:
        env_file = ".env"  # Ensure the .env file is loaded
        env_file_encoding = "utf-8"  # Set the encoding for the .env file

    @validator('WORKMAIL_DOMAIN')
    def validate_workmail_domain(cls, v):
        if v and not v.endswith('.awsapps.com'):
            raise ValueError('Invalid WorkMail domain format, should end with ".awsapps.com"')
        return v

    @validator('YAHOO_APP_PASSWORD')
    def validate_yahoo_password(cls, v, values):
        # Validate that the Yahoo password is provided when a username is present
        if 'YAHOO_USERNAME' in values and not v:
            raise ValueError('App password is required for Yahoo if username is provided')
        return v

    @validator('GMAIL_REFRESH_TOKEN', 'OUTLOOK_REFRESH_TOKEN', 'ZOHO_REFRESH_TOKEN')
    def validate_refresh_token(cls, v, values, field):
        # Validate that refresh token exists for Gmail, Outlook, and Zoho
        if not v:
            raise ValueError(f'Refresh token is required for {field.name}')
        return v

def load_config():
    try:
        # Load and validate the environment variables based on the EmailConfig class
        config = EmailConfig()
        return config
    except ValidationError as e:
        print(f"Validation error: {e}")
        exit(1)  # Stop execution if validation fails

