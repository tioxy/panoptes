""" Panoptes - AWS - Output

Functions to print specific AWS analysis output.
"""

import colorama
import panoptes.generic.output


ALL_TRAFFIC_PROTOCOL = "-1"
PUBLIC_CIDR = "0.0.0.0/0"
COLOR_WARNING = colorama.Fore.LIGHTYELLOW_EX
COLOR_ALERT = colorama.Fore.LIGHTRED_EX

def print_human(analysis):
    """
    Converts the AWS analysis dictionary into human readable output
    """
    def generate_ingress_message(protocol, range, cidr_ip, color):
        return (
            colorama.Style.RESET_ALL
            + colorama.Style.BRIGHT
            + color
            + "    "
            + protocol
            + "   "
            + range
            + "   "
            + cidr_ip
            + colorama.Style.RESET_ALL
        )

    def generate_security_group_message(security_group):
        return (
            colorama.Style.RESET_ALL
            + colorama.Style.BRIGHT
            + colorama.Fore.MAGENTA + security_group['GroupId']
            + "   "
            + colorama.Fore.WHITE + security_group['GroupName']
            + colorama.Style.RESET_ALL
        )

    human_output = ""
    unused_groups_list = analysis['SecurityGroups']['UnusedGroups']
    unsafe_groups_list = analysis['SecurityGroups']['UnsafeGroups']

    colorama.init()

    human_output += (
        panoptes.generic.output.generate_header_message(
            "PANOPTES AWS Analysis"
        )
        + "\n"
    )

    human_output += (
        2 * "\n"
        + panoptes.generic.output.generate_section_message(
            "01. UNUSED SECURITY GROUPS",
        )
        + "\n"
    )

    if unused_groups_list:
        for unused_group in unused_groups_list:
            human_output += (
                generate_security_group_message(unused_group)
                + "\n"
            )
        human_output += (
            "\n"
            + panoptes.generic.output.generate_warning_message(
                f"{len(unused_groups_list)} security groups not being used"
            )
            + "\n"
        )
    else:
        human_output += (
            "\n"
            + panoptes.generic.output.generate_info_message(
                "All security groups are attached and being used"
            )
            + "\n"
        )

    human_output += (
        2 * "\n"
        + panoptes.generic.output.generate_section_message(
            "02. SECURITY GROUPS WITH UNSAFE INGRESS RULES"
        )
        + "\n"
    )
    if unsafe_groups_list:
        alert_rule_count = 0
        warning_rule_count = 0

        for unsafe_group in unsafe_groups_list:
            human_output += (
                generate_security_group_message(unsafe_group)
                + "\n"
            )
            for ingress in unsafe_group['UnsafePorts']:
                cidr_ip = ingress['CidrIp']
                protocol = ingress['IpProtocol']
                range = 'All'
                color = colorama.Fore.LIGHTYELLOW_EX

                # Making range values prettier
                if 'FromPort' in ingress.keys() or 'ToPort' in ingress.keys():
                    if ingress['FromPort'] == ingress["ToPort"]:
                        range = (
                            f"{ingress['FromPort']}"
                        )
                    else:
                        range = (
                            f"{ingress['FromPort']} - {ingress['ToPort']}"
                        )

                # ALERT if All Traffic protocol is enabled
                if 'IpProtocol' in ingress.keys():
                    if ingress['IpProtocol'] == ALL_TRAFFIC_PROTOCOL:
                        color = COLOR_ALERT
                        protocol = 'All'
                    # Making protocol names prettier
                    elif ingress['IpProtocol'] in ['tcp', 'udp', 'icmp']:
                        protocol = ingress['IpProtocol'].upper()

                # ALERT if IP is public
                if ingress['CidrIp'] == PUBLIC_CIDR:
                    color = COLOR_ALERT

                if color is COLOR_WARNING:
                    warning_rule_count += 1
                elif color is COLOR_ALERT:
                    alert_rule_count += 1

                human_output += (
                    generate_ingress_message(
                        protocol=protocol,
                        cidr_ip=cidr_ip,
                        range=range,
                        color=color,
                    )
                    + "\n"
                )
            human_output += "\n"

        if warning_rule_count:
            human_output += (
                panoptes.generic.output.generate_warning_message(
                    f"{warning_rule_count} rules found with unknown IPs"
                    + "\n"
                )
            )

        if alert_rule_count:
            human_output += (
                panoptes.generic.output.generate_alert_message(
                    f"{alert_rule_count} rules public/all traffic enabled"
                    + "\n"
                )
            )
    else:
        human_output += (
            panoptes.generic.output.generate_info_message(
                "All security groups have safe rules"
                + "\n"
            )
        )

    return human_output


if __name__ == "__main__":
    pass
