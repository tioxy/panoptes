""" Panoptes - Cloud Authentication - AWS - AWS Panoptes

Responsible to the entire AWS analysis. Here the dynamic whitelist,
the logic behind unknown ingress rules and unused security groups are created.
"""


class AWSAnalysis:
    """
    Class used to gather data and format dictionaries to the final analysis
    """
    def __init__(self):
        pass

    def get_ec2_attached_security_groups(self, aws_client):
        """
        List security groups attached to EC2 instances
        """
        ec2_attached_groups = []
        ec2 = aws_client.client('ec2')
        boto_ec2_instances = ec2.describe_instances()
        for instance_json in boto_ec2_instances['Reservations']:
            for instance in instance_json['Instances']:
                for security_group in instance['SecurityGroups']:
                    ec2_attached_groups.append(
                        security_group['GroupId']
                    )
        return list(set(ec2_attached_groups))

    def get_rds_attached_security_groups(self, aws_client):
        """
        List security groups attached to RDS instances
        """
        rds_attached_groups = []
        rds = aws_client.client('rds')
        boto_rds_instances = rds.describe_db_instances()
        for db_instance_json in boto_rds_instances['DBInstances']:
            for security_group in db_instance_json['VpcSecurityGroups']:
                rds_attached_groups.append(
                    security_group['VpcSecurityGroupId']
                )
        return list(set(rds_attached_groups))

    def get_elb_attached_security_groups(self, aws_client):
        """
        List security groups attached to Elastic Load Balancers
        """
        elb_attached_groups = []
        elb = aws_client.client('elb')
        boto_load_balancers = elb.describe_load_balancers()
        for elb_json in boto_load_balancers['LoadBalancerDescriptions']:
            for security_group in elb_json['SecurityGroups']:
                elb_attached_groups.append(
                    security_group
                )
        return list(set(elb_attached_groups))

    def get_all_security_groups(self, aws_client):
        """
        Get all security groups created
        """
        ec2 = aws_client.client('ec2')
        all_security_groups = ec2.describe_security_groups()['SecurityGroups']
        return all_security_groups

    def generate_unused_security_group_entry(self, security_group):
        """
        Generates a dictionary from an unused security group to the analysis
        response
        """
        if 'VpcId' not in security_group.keys():
            vpc_id = 'no-vpc'
        else:
            vpc_id = security_group['VpcId']
        unused_group = {
            'GroupName': security_group['GroupName'],
            'GroupId': security_group['GroupId'],
            'Description': security_group['Description'],
            'VpcId': vpc_id,
        }
        return unused_group

    def generate_unsafe_security_group_entry(self, security_group,
                                             unsafe_ingress_entries):
        """
        Generates a dictionary from an unsafe security group, receiving all
        unsafe ingress entries related to this security group to the analysis
        response
        """
        unsafe_group = {
            "GroupName": security_group['GroupName'],
            "GroupId": security_group['GroupId'],
            "Description": security_group['Description'],
            "UnsafePorts": unsafe_ingress_entries,
        }
        return unsafe_group

    def generate_unsafe_ingress_entry(self, ingress_entry, unsafe_ip):
        """
        Generates a dictionary from an unsafe ingress entry to the analysis
        response
        """
        unsafe_ingress = {
            "IpProtocol": ingress_entry["IpProtocol"],
            "CidrIp": unsafe_ip,
        }
        if "FromPort" in ingress_entry.keys():
            unsafe_ingress["FromPort"] = ingress_entry["FromPort"]
        if "ToPort" in ingress_entry.keys():
            unsafe_ingress["ToPort"] = ingress_entry["ToPort"]
        return unsafe_ingress


class AWSWhitelist:
    """
    Class used to generate the dynamic whitelist of AWS Resources and consider
    them not harmful and known resources
    """
    def __init__(self, aws_client):
        self.safe_ips = list(set(self.get_vpc_ranges(aws_client)
                                 + self.get_subnet_ranges(aws_client)
                                 + self.get_vpc_instances_ips(aws_client)
                                 + self.get_elastic_ips(aws_client)))

    def get_vpc_ranges(self, aws_client):
        """
        List VPCs CIDR ranges in the account
        """
        ec2 = aws_client.client('ec2')
        boto_vpcs = ec2.describe_vpcs()
        vpc_ranges = [
            vpc['CidrBlock'] for vpc in boto_vpcs['Vpcs']
        ]
        return vpc_ranges

    def get_subnet_ranges(self, aws_client):
        """
        List Subnets CIDR ranges in the account
        """
        ec2 = aws_client.client('ec2')
        boto_subnets = ec2.describe_subnets()
        subnet_ranges = [
            subnet['CidrBlock'] for subnet in boto_subnets['Subnets']
        ]
        return subnet_ranges

    def get_vpc_instances_ips(self, aws_client):
        """
        List Public and Private IPs from EC2 instances inside a VPC in the
        account
        """
        ec2 = aws_client.client('ec2')
        boto_instances = ec2.describe_instances()
        vpc_instances_ips = []
        for instance_json in boto_instances['Reservations']:
            for instance in instance_json['Instances']:
                for instance_net in instance['NetworkInterfaces']:
                    if 'Association' in instance_net.keys():
                        vpc_instances_ips.append(
                            instance_net['Association']['PublicIp'] + '/32'
                        )
                    if 'PrivateIpAddress' in instance_net.keys():
                        vpc_instances_ips.append(
                            instance_net['PrivateIpAddress'] + '/32'
                        )
                    if 'PrivateIpAddresses' in instance_net.keys():
                        for priv_ip in instance_net['PrivateIpAddresses']:
                            if 'Association' in priv_ip.keys():
                                vpc_instances_ips.append(
                                    priv_ip['Association']['PublicIp'] + '/32'
                                )
                            if 'PrivateIpAddress' in priv_ip.keys():
                                vpc_instances_ips.append(
                                    priv_ip['PrivateIpAddress'] + '/32'
                                )
        return vpc_instances_ips

    def get_elastic_ips(self, aws_client):
        """
        List all Elastic IPs reserved in the account
        """
        ec2 = aws_client.client('ec2')
        boto_elastic_ips = ec2.describe_addresses()
        elastic_ips = []
        for elastic_ip in boto_elastic_ips['Addresses']:
            if 'PrivateIpAddress' in elastic_ip.keys():
                elastic_ips.append(
                    elastic_ip['PrivateIpAddress'] + '/32'
                )
            elastic_ips.append(
                elastic_ip['PublicIp'] + '/32'
            )
        return elastic_ips


def analyze_security_groups(aws_client, whitelist_file=None):
    """
    The main analysis function

    Parameters:
        - whitelist_file:
            Type: list
            Description: List of whitelisted CIDR from optional input file

        - aws_client:
            Type: boto3.Session
            Description: Client object from cloud_authentication modules

    DesiredReturn:
            "SecurityGroups": {
                "UnusedByInstances": [
                    {
                        "GroupName": str,
                        "GroupId": str,
                        "Description": str,
                        "VpcId": str,
                    }
                ],
                "UnsafeGroups": [
                    {
                        "GroupName": str,
                        "GroupId": str,
                        "Description": str,
                        "UnsafePorts": [
                            {
                                "FromPort": int,
                                "ToPort": int,
                                "IpProtocol": str,
                                "CidrIp": str,
                            },
                        ]
                    },
                ],
            }
    """
    response = {
        'SecurityGroups': {
            'UnusedByInstances': [],
            'UnsafeGroups': [],
        }
    }

    if whitelist_file is None:
        whitelist_file = []

    aws_whitelist = AWSWhitelist(aws_client)
    whitelist = whitelist_file + aws_whitelist.safe_ips

    analysis = AWSAnalysis()
    secgroup_services = {
        "ec2": analysis.get_ec2_attached_security_groups(aws_client),
        "rds": analysis.get_rds_attached_security_groups(aws_client),
        "elb": analysis.get_elb_attached_security_groups(aws_client),
    }
    all_attached_groups = []
    for secgroup_services, attached_groups in secgroup_services.items():
        all_attached_groups += attached_groups

    all_security_groups = analysis.get_all_security_groups(aws_client)
    for security_group in all_security_groups:
        # Validating if group is unused
        if security_group['GroupId'] not in all_attached_groups:
            response['SecurityGroups']['UnusedByInstances'].append(
                analysis.generate_unused_security_group_entry(
                    security_group=security_group
                )
            )

        # Validating if group is unsafe
        unsafe_ingress_entries = []
        for ingress_entry in security_group["IpPermissions"]:
            for allowed_ip in ingress_entry["IpRanges"]:
                if allowed_ip['CidrIp'] not in whitelist:
                    unsafe_ingress_entries.append(
                        analysis.generate_unsafe_ingress_entry(
                            ingress_entry=ingress_entry,
                            unsafe_ip=allowed_ip['CidrIp'],
                        )
                    )
        if unsafe_ingress_entries:
            response['SecurityGroups']['UnsafeGroups'].append(
                analysis.generate_unsafe_security_group_entry(
                    security_group=security_group,
                    unsafe_ingress_entries=unsafe_ingress_entries,
                )
            )
    return response


if __name__ == "__main__":
    pass
