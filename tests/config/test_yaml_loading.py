from pathlib import Path

import yaml

CONFIG_FILE = Path("config") / "detections.yaml"


def test_yaml_loading():

    with open(CONFIG_FILE, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    assert config["linux"]["brute_force"]["enabled"] is True

    assert config["linux"]["brute_force"]["max_failed_logins"] == 5

    assert config["windows"]["account_lockout"]["severity"] == "HIGH"

    assert config["aws"]["root_login"]["severity"] == "CRITICAL"