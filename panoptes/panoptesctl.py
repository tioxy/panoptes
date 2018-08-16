#!/usr/bin/env python
import click
import panoptes.aws
import panoptes.generic


AVAILABLE_OUTPUT_OPTIONS = [
    'human',
    'json',
    'yml',
]
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
    help="Generate the analysis output"
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
    type=click.Choice(AVAILABLE_OUTPUT_OPTIONS),
)
@click.option(
    '--whitelist',
    'whitelist_path',
    default=None,
    help='Path to whitelist with declared safe IPs and CIDR',
    metavar='<path>',
)
def aws_analyze_command(region, profile, output, whitelist_path):
    aws_output_options = {
        "human": panoptes.aws.output.print_human,
        "json": panoptes.generic.output.print_json,
        "yml": panoptes.generic.output.print_yml,
    }

    whitelist = []
    if whitelist_path:
        whitelist = panoptes.generic.parser.parse_whitelist_file(
            whitelist_path=whitelist_path
        )

    aws_client = panoptes.aws.authentication.get_client(
        region=region,
        profile=profile,
    )

    if aws_client:
        analysis = panoptes.aws.analysis.analyze_security_groups(
            aws_client=aws_client,
            whitelist=whitelist,
        )
        aws_output_options.get(output)(analysis=analysis)
    return None


if __name__ == "__main__":
    cli()
    exit()
