import click
import cloud_authentication
import cloud_providers


@click.group()
def cli():
    """Welcome to Panoptes - The multi cloud security group analyzer

    This project is stored at GitHub and open sourced under the Apache 2.0 License.

    To start using it, read the docs at:
    https://github.com/tioxy/panoptes
    """
    pass


@cli.group(
    'aws',
    help='Amazon Web Services'
)
def aws():
    pass


@cli.group(
    'gcp',
    help='Google Cloud Plataform'
)
def gcp():
    pass


@aws.command(
    'analyze',
    help="Generate the analysis file"
)
@click.option(
    '--region',
    required=True,
    help='AWS Region to list the security groups',
    metavar='<region_id>'
)
@click.option(
    '--profile',
    default='default',
    help='AWS CLI configured profile which will be used',
    metavar='<profile_name>'
)
@click.option(
    '--output',
    default='json',
    help='Which kind of output you want the analysis',
    metavar='<json/yml>'
)
@click.option(
    '--whitelist',
    help='Whitelist with declared safe IPs and CIDR',
    metavar='<path>'
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


def read_whitelist_file(whitelist):
    with open(whitelist, 'r') as whitelist_file:
        whitelist = [line.replace('\n', '') for line in whitelist_file]
    return whitelist


if __name__ == "__main__":
    cli()
    exit()
