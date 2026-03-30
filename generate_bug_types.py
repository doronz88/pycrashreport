import plistlib
from pathlib import Path

import typer

SUBMISSION_CONFIG = Path(
    "/System/Library/PrivateFrameworks/OSAnalytics.framework/Versions/A/Resources/submissionConfig.plist"
)


def main() -> None:
    submission_config = plistlib.loads(SUBMISSION_CONFIG.read_bytes())
    log_types = submission_config["log_types"]

    for k, v in log_types.items():
        print(f"{v['name']} = '{k}'")


def cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    cli()
