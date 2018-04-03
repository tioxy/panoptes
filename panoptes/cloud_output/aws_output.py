""" Panoptes - Cloud Output - AWS

Collection of functions to print AWS analysis output.
"""

import json
import yaml
import colorama


def output_json(analysis):
    """
    Prints in the screen a prettified JSON version from AWS analysis dictionary
    """
    output = json.dumps(
        analysis,
        indent=4,
        sort_keys=True
    )
    print(output)
    return None


def output_yml(analysis):
    """
    Prints in the screen an YML version from AWS analysis dictionary
    """
    output = yaml.dump(
        analysis,
        default_flow_style=False,
        allow_unicode=True,
    )
    print(output)
    return None


def output_human(analysis):
    """
    Converts the AWS analysis dictionary into human readable output
    """
    def generate_info_message(content):
        return (colorama.Fore.LIGHTCYAN_EX
                + "INFO: {}".format(content)
                + colorama.Style.RESET_ALL)

    def generate_warning_message(content):
        return (colorama.Fore.YELLOW
                + "WARNING: {}".format(content)
                + colorama.Style.RESET_ALL)

    def generate_alert_message(content):
        return (colorama.Fore.LIGHTRED_EX
                + "ALERT: {}".format(content)
                + colorama.Style.RESET_ALL)

    def generate_section_message(content):
        return (colorama.Style.RESET_ALL
                + "\n\n\n"
                + colorama.Style.BRIGHT
                + colorama.Fore.WHITE
                + content
                + colorama.Style.RESET_ALL
                + "\n")

    def generate_ingress_message(protocol, range, cidr_ip, color):
        return (colorama.Style.RESET_ALL
                + colorama.Style.BRIGHT
                + color
                + "    "
                + protocol
                + "   "
                + range
                + "   "
                + cidr_ip
                + colorama.Style.RESET_ALL)

    def generate_security_group_message(security_group):
        return (
            colorama.Style.BRIGHT
            + colorama.Fore.MAGENTA + security_group['GroupId']
            + "   "
            + colorama.Fore.WHITE + security_group['GroupName']
            + colorama.Style.RESET_ALL
        )

    unused_groups_list = analysis['SecurityGroups']['UnusedGroups']
    unsafe_groups_list = analysis['SecurityGroups']['UnsafeGroups']

    colorama.init()
    print("""
=============================================================
||                                                         ||
||                  PANOPTES AWS Analysis                  ||
||                                                         ||
=============================================================""")

    print(
        generate_section_message(
            "01. UNUSED SECURITY GROUPS"
        )
    )

    if unused_groups_list:
        for unused_group in unused_groups_list:
            print(generate_security_group_message(unused_group))
        print(
            '\n' +
            generate_warning_message((
                str(len(unused_groups_list))
                + " security groups not being used"
            ))
        )
    else:
        all_attached_msg = (
            "All security groups are attached and being used"
        )
        print(generate_info_message(all_attached_msg))

    print(
        generate_section_message(
            "02. SECURITY GROUPS WITH UNSAFE INGRESS RULES"
        )
    )
    if unsafe_groups_list:
        alert_rule_count = 0
        warning_rule_count = 0
        for unsafe_group in unsafe_groups_list:
            print()
            print(generate_security_group_message(unsafe_group))
            for ingress in unsafe_group['UnsafePorts']:
                range = None
                protocol = None
                cidr_ip = None
                color = None

                if (
                    'FromPort' in ingress.keys() or
                    'ToPort' in ingress.keys()
                ):
                    if ingress['FromPort'] == ingress["ToPort"]:
                        range = str(ingress['FromPort'])
                    else:
                        range = (str(ingress['FromPort'])
                                 + " - "
                                 + str(ingress['ToPort']))

                if 'IpProtocol' in ingress.keys():
                    if ingress['IpProtocol'] == '-1':
                        protocol = 'All'
                        range = 'All'
                        color = colorama.Fore.LIGHTRED_EX
                    elif (
                        ingress['IpProtocol'] == 'tcp' or
                        ingress['IpProtocol'] == 'udp' or
                        ingress['IpProtocol'] == 'icmp'
                    ):
                        protocol = ingress['IpProtocol'].upper()
                    else:
                        protocol = str(ingress['IpProtocol'])

                if 'CidrIp' in ingress.keys():
                    cidr_ip = ingress['CidrIp']
                    if cidr_ip == "0.0.0.0/0":
                        color = colorama.Fore.LIGHTRED_EX

                if color is None:
                    color = colorama.Fore.LIGHTYELLOW_EX
                    warning_rule_count += 1
                elif color is colorama.Fore.LIGHTRED_EX:
                    alert_rule_count += 1

                print(generate_ingress_message(
                    protocol=protocol,
                    cidr_ip=cidr_ip,
                    range=range,
                    color=color,
                ))

        print()
        if warning_rule_count > 0:
            print(
                generate_warning_message((
                    str(warning_rule_count)
                    + " rules found with uknown IPs"
                ))
            )

        if alert_rule_count > 0:
            print(
                generate_alert_message((
                    str(alert_rule_count)
                    + " rules opened to the world/all traffic enabled"
                ))
            )
    else:
        all_attached_msg = (
            "All security groups have safe rules"
        )
        print(generate_info_message(all_attached_msg))

    return None


if __name__ == "__main__":
    pass
