import click
import panoptes.cli
import panoptes.generic


GCP_AVAILABLE_OUTPUT_OPTIONS = [
    'human',
    'json',
    'yml',
]


@click.command(
    'analyze',
    help="Generate the analysis output"
)
def gcp_analyze_command():
    print("Nothing here")
    return None


if __name__ == "__main__":

    pass
