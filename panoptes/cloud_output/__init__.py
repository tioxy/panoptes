""" Panoptes - Cloud Output

Responsible to import output functions from cloud providers.

Every module must be created like the following one:
<CLOUD_PROVIDER_NAME>_output.py

Inside the respective cloud output module, the amount of functions must be
equal to the amount of possible outputs.

Functions naming must be:
output_<OUTPUT_KIND>(analysis)
"""

from panoptes.cloud_output import aws_output


if __name__ == "__main__":
    pass
