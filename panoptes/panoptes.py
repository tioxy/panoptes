import click
import cloud_authentication
import cloud_providers


@click.group()
def cli():
    pass


@cli.group('aws')
def aws():
    pass


@aws.command('analyze')
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
@click.option(
    '--output',
    default='json',
    help='Which kind of output you want the analysis'
)
def aws_analyze_command(region, profile, output, whitelist=None):
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


@aws.command('remove-anywhere')
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
    '--analysis-file',
    help='File created from the analyze command'
)
def aws_remove_anywhere_command(region, profile, analysis_file):
    aws_authentication = cloud_authentication.aws.get_client(
        region=region,
        profile=profile,
    )

    if aws_authentication["Error"] is not None:
        print(aws_authetication["Error"])
    else:
        aws_client = aws_authentication["Client"]
        print("Still being developed")
    return None


@aws.command('remove-unsafe')
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
    '--analysis-file',
    help='File created from the analyze command'
)
def aws_remove_unsafe_command(region, profile, analysis_file):
    aws_authentication = cloud_authentication.aws.get_client(
        region=region,
        profile=profile,
    )

    if aws_authentication["Error"] is not None:
        print(aws_authetication["Error"])
    else:
        aws_client = aws_authentication["Client"]
        print("Still being developed")
    return None


@aws.command('remove-unused')
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
    '--analysis-file',
    help='File created from the analyze command'
)
def aws_remove_unsafe_command(region, profile, analysis_file):
    aws_authentication = cloud_authentication.aws.get_client(
        region=region,
        profile=profile,
    )

    if aws_authentication["Error"] is not None:
        print(aws_authetication["Error"])
    else:
        aws_client = aws_authentication["Client"]
        print("Still being developed")
    return None
   


def read_whitelist_file(whitelist):
    with open(whitelist, 'r') as whitelist_file:
        whitelist = [line.replace('\n', '') for line in whitelist_file]
    return whitelist


if __name__ == "__main__":
    cli()
    exit()
