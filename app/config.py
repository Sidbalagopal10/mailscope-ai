import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv(
        "APP_NAME",
        "MailScope AI",
    )

    app_env: str = os.getenv(
        "APP_ENV",
        "development",
    )

    database_url: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./phishing_detector.db",
    )

    google_credentials_file: str = os.getenv(
        "GOOGLE_CREDENTIALS_FILE",
        "credentials.json",
    )

    model_path: str = os.getenv(
        "MODEL_PATH",
        "training/models/phishing_model.joblib",
    )


settings = Settings()
