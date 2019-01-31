""" Panoptes - CLI - AWS

Responsible for organizing commands from Panoptes AWS CLI
"""

import click
import panoptes


AWS_AVAILABLE_OUTPUT_OPTIONS = [
    'human',
    'json',
    'yml',
]


@click.command(
    'analyze',
    help="Generate the analysis output"
)
@click.option(
    '-r', '--region',
    'region',
    required=True,
    help='AWS Region to list the security groups',
    metavar='<region_id>',
)
@click.option(
    '-p', '--profile',
    'profile',
    help='AWS CLI configured profile which will be used',
    metavar='<profile_name>',
)
@click.option(
    '-o', '--output',
    'output',
    default='human',
    help='Which kind of output you want the analysis',
    type=click.Choice(AWS_AVAILABLE_OUTPUT_OPTIONS),
)
@click.option(
    '--whitelist',
    'whitelist_path',
    help='Path to whitelist with declared safe IPs and CIDR',
    metavar='<path>',
)
@click.option(
    '-f', '--file',
    'analysis_path',
    help='Path to save the analysis file from Panoptes',
    metavar='<path>',
)
def aws_analyze_command(region, profile, output, whitelist_path, analysis_path):
    """
    This function is called when the user types
    "panoptes aws analyze"
    """
    aws_output_options = {
        "human": panoptes.aws.output.print_human,
        "json": panoptes.generic.output.print_json,
        "yml": panoptes.generic.output.print_yml,
    }

    if whitelist_path:
        whitelist = panoptes.generic.helpers.parse_whitelist_file(
            whitelist_path=whitelist_path
        )
    else:
        whitelist = []

    session = panoptes.aws.authentication.create_session(
        region=region,
        profile=profile,
    )

    if session:
        analysis = panoptes.aws.analysis.analyze_security_groups(
            session=session,
            whitelist=whitelist,
        )
        print(aws_output_options.get(output)(analysis=analysis))

    if analysis_path:
        unsupported_file_outputs = [
            "human",
        ]
        if output in unsupported_file_outputs:
            print(
                panoptes.generic.output.generate_warning_message(
                    f"Your analysis file will not be created as '{output}' output is not supported."
                )
            )
        else:
            panoptes.generic.helpers.write_analysis_file(
                analysis=analysis,
                analysis_path=analysis_path,
                analysis_output=output,
            )


if __name__ == "__main__":
    pass
