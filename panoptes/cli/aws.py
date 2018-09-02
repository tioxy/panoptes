""" Panoptes - CLI - AWS
Responsible for organizing commands from Panoptes AWS CLI
"""

import click
import panoptes.cli
import panoptes.generic
import panoptes.aws

AVAILABLE_OUTPUT_OPTIONS = [
    'human',
    'json',
    'yml',
]


@click.command(
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
    pass
