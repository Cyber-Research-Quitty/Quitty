from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Central configuration for the P1 service.
    Values can be overridden via environment variables or a .env file.
    """

    app_name: str = "QWitty P1 – PQC JWT Sign & Verify"
    environment: str = "dev"

    # For now we still use a dev algorithm; later we'll switch this to "ml-dsa-44".
    default_alg: str = "ed25519-dev"

    # Where private keys will be stored (we'll implement this keystore later).
    keystore_path: str = "data/p1-keystore.json"

    # URL of P2 JWKS service for future key export (we'll wire this later).
    p2_export_url: str | None = None

    class Config:
        env_file = ".env"  # if a .env file exists, it will be read automatically


# create a single settings instance we can import everywhere
settings = Settings()
