from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "QWitty P1 – PQC JWT Sign & Verify"
    environment: str = "dev"

    default_alg: str = "ml-dsa-44"
    keystore_path: str = "data/p1-keystore.json"

    # P1 -> P2 integration
    p2_export_url: str | None = None
    p2_delete_url: str | None = None
    p2_timeout_seconds: float = 3.0

    # P1 -> P4 integration
    p4_revoke_url: str | None = None
    p4_token_sync_url: str | None = None
    p4_timeout_seconds: float = 3.0

    class Config:
        env_file = ".env"


settings = Settings()
