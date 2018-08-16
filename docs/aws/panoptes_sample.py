import panoptes


def main():
    MY_REGION = "us-east-1"
    MY_PROFILE = "default"
    # PATH_TO_WHITELIST = "/path/to/whitelist.txt"

    """
    Generate Panoptes AWS auth
    """
    aws_client = panoptes.aws.authentication.get_client(
        region=MY_REGION,
        profile=MY_PROFILE,
    )

    """
    OPTIONAL:
    1- Read the whitelist from a file
    2- Declare the whitelist manually through a list
    """
    #
    # First Way
    #
    #whitelist = panoptes.generic.parser.parse_whitelist_file(
    #    whitelist_path=PATH_TO_WHITELIST
    #)
    #
    # Second Way
    #
    #whitelist = [
    #    '123.123.123.123/32',
    #    '10.0.0.0/24',
    #    '0.0.0.0/0',
    #]

    """
    Generate the analysis
    """
    generated_analysis = panoptes.aws.analysis.analyze_security_groups(
        aws_client=aws_client,
        # Uncomment below if you declared the whitelist
        # whitelist=whitelist,
    )

    """
    CONGRATULATIONS!!!
    You can do whatever you want with it.
    """
    print(generated_analysis)


if __name__ == "__main__":
    main()
    exit()
