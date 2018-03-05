import click
import cloud_authentication
import cloud_providers


@click.group()
def cli():
    pass


@cli.command('aws')
@click.option(
    '--region',
    help='AWS Region to check your security groups'
)
@click.option(
    '--profile',
    default='default',
    help='AWS CLI profile to check'
)
@click.option(
    '--whitelist',
    help='Whitelist to declare safe IPs'
)
def aws_command(region, profile, whitelist=None):
    if whitelist is None:
        whitelist_file = None
    else:
        whitelist_file = read_whitelist_file(whitelist)

    aws_authentication = cloud_authentication.aws.get_client(
        region=region,
        profile=profile,
    )

    if aws_authentication["Error"] is not None:
        print(aws_authetication["Error"])
    else:
        aws_client = aws_authentication["Client"]
        cloud_providers.aws.aws_panoptes.analyze_security_groups(
            aws_client,
            whitelist_file,
        )
    return None


def read_whitelist_file(whitelist):
    with open(whitelist, 'r') as whitelist_file:
        whitelist = [line.replace('\n', '') for line in whitelist_file]
    return whitelist


if __name__ == "__main__":
    cli()
    exit()
