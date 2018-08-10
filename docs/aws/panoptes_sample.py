import panoptes
from pprint import pprint


def main():
    MY_REGION = "us-east-1"
    MY_PROFILE = "default"
    # PATH_TO_WHITELIST = "/path/to/whitelist.txt"

    """
    REQUIRED: Generate Panoptes AWS auth
    """
    aws_client = panoptes.aws.authentication.get_client(
        region=MY_REGION,
        profile=MY_PROFILE,
    )

    """
    OPTIONAL: You can read the whitelist from a file
    """
    #whitelist = panoptes.panoptesctl.read_whitelist_file(
    #    whitelist_path=PATH_TO_WHITELIST
    #)

    """
    OPTIONAL: You can declare the whitelist manually
    """
    #whitelist = [
    #    '123.123.123.123/32',
    #    '10.0.0.0/24',
    #    '0.0.0.0/0',
    #]

    """
    REQUIRED: Generate the analysis
    """
    generated_analysis = panoptes.aws.analysis.analyze_security_groups(
        aws_client=aws_client,
        # whitelist=whitelist,
    )

    """
    CONGRATULATIONS!!!
    You can do whatever you want with it.
    """
    pprint(generated_analysis)


if __name__ == "__main__":
    main()
    exit()
