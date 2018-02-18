import click
import cloud_authentication
import cloud_providers


@click.group()
def cli():
    pass


@cli.command('aws')
@click.option(
    '--region',
    help='AWS Region to check your security groups'
)
@click.option(
    '--profile',
    default='default',
    help='AWS CLI profile to check'
)
def aws_command(region, profile):
    aws_authentication = cloud_authentication.aws.get_client(
        region=region,
        profile=profile,
    )
    print(aws_authentication)


if __name__ == "__main__":
    cli()
    exit()
