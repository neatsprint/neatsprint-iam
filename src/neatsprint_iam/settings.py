from neatsprint_lib.settings import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "iam"
    api_prefix: str = "iam"


settings = Settings()
