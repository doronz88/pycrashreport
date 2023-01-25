import plistlib
from pathlib import Path

import click

SUBMISSION_CONFIG = Path(
    '/System/Library/PrivateFrameworks/OSAnalytics.framework/Versions/A/Resources/submissionConfig.plist')


@click.command()
def cli():
    submission_config = plistlib.loads(SUBMISSION_CONFIG.read_bytes())
    log_types = submission_config['log_types']

    for k, v in log_types.items():
        print(f'{v["name"]} = \'{k}\'')


if __name__ == '__main__':
    cli()
