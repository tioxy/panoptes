#!/usr/bin/env python
import click
import panoptes.aws


def generate_analysis_output(output, analysis):
    output_options = {
        "json": panoptes.aws.output.output_json,
        "yml": panoptes.aws.output.output_yml,
        "human": panoptes.aws.output.output_human,
    }
    output_options[output](analysis=analysis)
    return None


@click.group()
def cli():
    """Welcome to Panoptes - The multi cloud security group analyzer

    This project is stored on GitHub and open sourced under Apache 2.0

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
    'region',
    required=True,
    help='AWS Region to list the security groups',
    metavar='<region_id>',
)
@click.option(
    '--profile',
    'profile',
    default='default',
    help='AWS CLI configured profile which will be used',
    metavar='<profile_name>',
)
@click.option(
    '--output',
    'output',
    default='human',
    help='Which kind of output you want the analysis',
    type=click.Choice(['human', 'json', 'yml']),
)
@click.option(
    '--whitelist',
    'whitelist_path',
    help='Whitelist with declared safe IPs and CIDR',
    metavar='<path>',
)
def aws_analyze_command(region, profile, output, whitelist_path=None):
    whitelist = []
    if whitelist_path:
        whitelist = read_whitelist_file(
            whitelist_path=whitelist_path
        )

    aws_authentication = panoptes.aws.authentication.get_client(
        region=region,
        profile=profile,
    )

    if aws_authentication:
        aws_client = aws_authentication
        analysis = panoptes.aws.analysis.analyze_security_groups(
            aws_client=aws_authentication,
            whitelist=whitelist,
        )
        generate_analysis_output(
            output=output,
            analysis=analysis,
        )
    return None


def read_whitelist_file(whitelist_path):
    with open(whitelist_path, 'r') as whitelist_file:
        whitelist = whitelist_file.read().splitlines()
    return whitelist


if __name__ == "__main__":
    cli()
    exit()
