from pprint import pprint
import panoptes


def main():
    MY_REGION = "us-east-1"

    # Creating auth
    aws_session = panoptes.aws.authentication.create_session(
        region=MY_REGION,
    )

    # Generating analysis from auth
    generated_analysis = panoptes.aws.analysis.analyze_security_groups(
        session=aws_session,
    )

    # Prettified print of the output dictionary
    pprint(generated_analysis)


if __name__ == "__main__":
    main()
    exit()
