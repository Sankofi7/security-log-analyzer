import json


DEFAULT_CONFIG = {
    "repeated_login_threshold": 3,
    "account_targeting_threshold": 3,
    "login_burst_threshold": 3,
    "login_burst_window_seconds": 60
}


def validate_config(config):
    """
    Validate configuration values.
    """

    for setting, value in config.items():

        if setting not in DEFAULT_CONFIG:
            raise ValueError(
                f"Unknown configuration setting: {setting}"
            )

        if not isinstance(value, int):
            raise ValueError(
                f"{setting} must be an integer."
            )

        if value <= 0:
            raise ValueError(
                f"{setting} must be greater than 0."
            )


def load_config(config_file="config/config.json"):
    """
    Load and validate analyzer configuration.
    Missing settings use default values.
    """

    try:
        with open(config_file, "r") as file:
            user_config = json.load(file)

    except FileNotFoundError:
        print(
            "Warning: Configuration file not found."
        )
        print(
            "Using default configuration."
        )

        return DEFAULT_CONFIG.copy()

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON configuration: {error}"
        )

    if not isinstance(user_config, dict):
        raise ValueError(
            "Configuration must be a JSON object."
        )

    validate_config(user_config)

    config = DEFAULT_CONFIG.copy()

    config.update(user_config)

    return config