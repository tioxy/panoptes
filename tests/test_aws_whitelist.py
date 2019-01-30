import boto3
import unittest
import pytest
import panoptes
from pprint import pprint
from moto import mock_ec2


VPC = {
    'default': '172.31.0.0/16',
    'created': '99.0.0.0/16',
}

SUBNET = {
    "default": [
        '172.31.0.0/20',
        '172.31.16.0/20',
        '172.31.32.0/20',        
    ],
    "created": [
        '99.0.0.0/24',
        '99.0.1.0/24',
    ],
}


def create_vpc(session: boto3.session.Session, cidr: str, name: str):
    vpc = session.resource('ec2').create_vpc(CidrBlock=cidr)
    vpc.create_tags(
        Tags=[
            {'Key': 'Name', 'Value': name},
        ],
    )
    vpc.wait_until_exists()
    vpc.wait_until_available()
    return vpc


def create_subnet(vpc, cidr: str, az: str, name: str):
    subnet = vpc.create_subnet(
        AvailabilityZone=az,
        CidrBlock=cidr,
    )
    subnet.create_tags(
        Tags=[
            {'Key': 'Name', 'Value': name},
        ],
    )
    return subnet


class PanoptesInfra(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.mock_ec2 = mock_ec2()
        self.mock_ec2.start()

        self.session = boto3.Session(
            region_name="us-east-1",
            aws_access_key_id="fakeaccess",
            aws_secret_access_key="fakesecret"
        )

        # Available clients
        self.clients = panoptes.aws.authentication.get_boto_clients(self.session)

        # Creating VPC
        self.vpc = create_vpc(self.session, VPC['created'], 'vpc-panoptes')

        # Creating Subnets
        self.subnet_pub = create_subnet(self.vpc, SUBNET['created'][0], 'us-east-1a', 'subnet-1a-pub')
        self.subnet_prv = create_subnet(self.vpc, SUBNET['created'][1], 'us-east-1a', 'subnet-1a-prv')

    def test_get_vpc_ranges(self):
        ec2 = self.clients['ec2']
        all_vpc_ranges = panoptes.aws.whitelist.get_vpc_ranges(ec2)

        self.assertIn(VPC['default'], all_vpc_ranges)
        self.assertIn(VPC['created'], all_vpc_ranges)
        self.assertNotIn("0.0.0.0/0", all_vpc_ranges)
        self.assertNotIn("10.0.0.0/16", all_vpc_ranges)

    def test_get_subnet_ranges(self):
        ec2 = self.clients['ec2']
        all_subnet_ranges = panoptes.aws.whitelist.get_subnet_ranges(ec2)

        for default_subnet in SUBNET['default']:
            self.assertIn(default_subnet, all_subnet_ranges)

        for created_subnet in SUBNET['created']:
            self.assertIn(created_subnet, all_subnet_ranges)

    @classmethod
    def tearDownClass(self):
        self.mock_ec2.stop()
