""" Panoptes - CLI - Analysis
Responsible for organizing commands from Panoptes Analysis CLI
"""

import click
import panoptes


@click.command(
    'view',
    help="Generate the analysis output"
)
@click.option(
    '-f', '--file',
    'file',
    help='Path to analysis file generated from Panoptes',
    metavar='<path>',
)
def analysis_view_command(file):
    """
    This function is called when the user types
    "panoptes analysis view"
    """
    human_outputs = {
        "aws": panoptes.aws.output.print_human,
    }
    analysis = panoptes.generic.helpers.parse_analysis_file(file)
    print(human_outputs[analysis['Metadata']['CloudProvider']['Name']](analysis))


if __name__ == "__main__":
    pass
