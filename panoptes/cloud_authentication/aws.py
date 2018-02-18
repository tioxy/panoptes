import boto3


def get_client(
    region,
    profile,
):
    error = None
    client = None
    try:
        client = boto3.Session(
            profile_name=profile,
            region_name=region,
        )
    except Exception as e:
        error = (
            "ERROR - Was not possible authenticating at AWS, "
            "check if your credentials exist and work."
        )
    response = {
        "Client": client,
        "Error": error
    }
    return response


if __name__ == "__main__":
    None
