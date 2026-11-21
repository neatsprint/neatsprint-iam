from neatsprint_lib.settings import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "iam"
    api_prefix: str = "iam"

    jwt_private_key_path: str = "./.keys/jwt-private.pem"
    jwt_public_key_path: str = "./.keys/jwt-public.pem"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    password_min_length: int = 10

    bootstrap_token: str | None = None
    core_internal_url: str = "http://neatsprint-core:8000"
    service_token: str | None = None
    outbox_enabled: bool = True
    outbox_stream: str = "neatsprint.events"
    web_base_url: str = "http://localhost:3000"

    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_from: str = "NeatSprint <no-reply@neatsprint.local>"
    email_enabled: bool = True


settings = Settings()
