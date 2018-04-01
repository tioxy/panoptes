""" Panoptes - Cloud Authentication

Responsible to standarize the cloud authentication client object.
Every authentication method should not require DIRECT CREDENTIALS input, very
like AWS Named Profiles

Every authentication module must be created like the following one:
<CLOUD_PROVIDER_NAME>.py

Functions naming must have a only necessary parameters and should be name like:
get_client(param1, param2, param3)
"""

from panoptes.cloud_authentication import aws


if __name__ == "__main__":
    pass
