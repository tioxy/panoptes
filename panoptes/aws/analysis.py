""" Panoptes - AWS - Analysis

Responsible to the entire AWS analysis. Here the dynamic whitelist,
the logic behind unknown ingress rules and unused security groups are created.
"""

from datetime import datetime
import panoptes.aws.whitelist
import panoptes.aws.attached


def generate_unused_secgroup_entry(security_group):
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

def generate_unsafe_secgroup_entry(security_group, unsafe_ingress_entries):
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

def generate_unsafe_ingress_entry(ingress_entry, unsafe_ip):
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


def analyze_security_groups(aws_client, whitelist=[]):
    """
    The main analysis function

    Parameters:
        - aws_client:
            Type: boto3.Session
            Description: Client object from cloud_authentication modules

        - whitelist:
            Type: list
            Description: List of whitelisted CIDR from optional input file

    DesiredReturn:
            "SecurityGroups": {
                "UnusedGroups": [
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
                "StartedAt": str[ISO 8601 Date],
                "FinishedAt": str[ISO 8601 Date],
            }
    """
    response = {
        'SecurityGroups': {
            'UnusedGroups': [],
            'UnsafeGroups': [],
        },
        'StartedAt': "",
        'FinishedAt': "",
    }

    response['StartedAt'] = datetime.now().isoformat()

    whitelist += panoptes.aws.whitelist.list_all_safe_ips(aws_client)
    all_security_groups = aws_client.client('ec2').describe_security_groups()['SecurityGroups']
    all_attached_groups = panoptes.aws.attached.list_all_attached_secgroups(aws_client)

    for security_group in all_security_groups:
        # Validating if group is unused
        if (
                security_group['GroupName'] not in all_attached_groups and
                security_group['GroupId'] not in all_attached_groups
        ):
            response['SecurityGroups']['UnusedGroups'].append(
                generate_unused_secgroup_entry(
                    security_group=security_group
                )
            )

        # Validating if group is unsafe
        unsafe_ingress_entries = []
        for ingress_entry in security_group['IpPermissions']:
            for allowed_ip in ingress_entry['IpRanges']:
                if allowed_ip['CidrIp'] not in whitelist:
                    unsafe_ingress_entries.append(
                        generate_unsafe_ingress_entry(
                            ingress_entry=ingress_entry,
                            unsafe_ip=allowed_ip['CidrIp'],
                        )
                    )
        if unsafe_ingress_entries:
            response['SecurityGroups']['UnsafeGroups'].append(
                generate_unsafe_secgroup_entry(
                    security_group=security_group,
                    unsafe_ingress_entries=unsafe_ingress_entries,
                )
            )

    response['FinishedAt'] = datetime.now().isoformat()

    return response


if __name__ == "__main__":
    pass
