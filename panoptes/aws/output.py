""" Panoptes - AWS - Output

Functions to print specific AWS analysis output.
"""

import panoptes
import jinja2
import colorama


ALL_TRAFFIC_PROTOCOL = "-1"
COLOR_ALERT = colorama.Fore.LIGHTRED_EX
COLOR_WARNING = colorama.Fore.LIGHTYELLOW_EX
PUBLIC_CIDR = "0.0.0.0/0"
TEMPLATE = """{{ HEADER }}


{{ FIRST_SECTION }}
{% for secgroup in UNUSED_SECGROUPS %}{{ secgroup }}
{% endfor %}
{% for notification in UNUSED_SECGROUP_NOTIFICATIONS %}{{ notification }}{% endfor %}


{{ SECOND_SECTION }}
{% for secgroup,rules in UNSAFE_SECGROUPS %}{{ secgroup }}
{{ rules }}
{% endfor %}
{% for notification in UNSAFE_RULES_NOTIFICATIONS %}{{ notification }}
{% endfor %}"""


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
            + protocol + "   " + range + "   " + cidr_ip
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

    human_output_template = jinja2.Template(TEMPLATE)
    unused_groups_list = analysis['SecurityGroups']['UnusedGroups']
    unsafe_groups_list = analysis['SecurityGroups']['UnsafeGroups']

    colorama.init()
    HEADER = panoptes.generic.output.generate_header_message(
        "PANOPTES Analysis"
    )

    FIRST_SECTION = panoptes.generic.output.generate_section_message(
        "01. UNUSED SECURITY GROUPS"
    )
    UNUSED_SECGROUP_NOTIFICATIONS = []
    if unused_groups_list:
        UNUSED_SECGROUPS = list(map(generate_security_group_message, unused_groups_list))
        UNUSED_SECGROUP_NOTIFICATIONS.append(
            panoptes.generic.output.generate_warning_message(
                f"{len(unused_groups_list)} security groups not being used"
            )
        )
    else:
        UNUSED_SECGROUP_NOTIFICATIONS.append(
            panoptes.generic.output.generate_info_message(
                "All security groups are attached and being used"
            )
        )

    SECOND_SECTION = panoptes.generic.output.generate_section_message(
        "02. SECURITY GROUPS WITH UNSAFE INGRESS RULES"
    )
    UNSAFE_RULES_NOTIFICATIONS = []
    if unsafe_groups_list:
        alert_rules = 0
        warning_rules = 0
        UNSAFE_SECGROUPS = []
        for unsafe_group in unsafe_groups_list:
            secgroup = generate_security_group_message(unsafe_group)
            rules = ""

            for ingress in unsafe_group['UnsafePorts']:
                color = COLOR_WARNING
                protocol = ingress['IpProtocol'].upper()

                # Making range values prettier
                if any(k in ingress for k in ['FromPort', 'ToPort']):
                    if ingress['FromPort'] == ingress["ToPort"]:
                        range = (
                            f"{ingress['FromPort']}"
                        )
                    else:
                        range = (
                            f"{ingress['FromPort']} - {ingress['ToPort']}"
                        )
                else:
                    range = "All"

                # ALERT if All Traffic protocol is enabled                
                if ingress['IpProtocol'] == ALL_TRAFFIC_PROTOCOL:
                    protocol = 'All'
                    color = COLOR_ALERT

                # ALERT if IP is public
                if ingress['CidrIp'] == PUBLIC_CIDR:
                    color = COLOR_ALERT

                rules += (
                    generate_ingress_message(
                        protocol=protocol,
                        cidr_ip=ingress['CidrIp'],
                        range=range,
                        color=color,
                    )+'\n'
                )
                if color is COLOR_WARNING:
                    warning_rules += 1
                elif color is COLOR_ALERT:
                    alert_rules += 1
            UNSAFE_SECGROUPS.append((secgroup, rules))
    
        if warning_rules:
            UNSAFE_RULES_NOTIFICATIONS.append(
                panoptes.generic.output.generate_warning_message(
                    f"{warning_rules} rules found with unknown IPs"
                )
            )
        if alert_rules:
            UNSAFE_RULES_NOTIFICATIONS.append(
                panoptes.generic.output.generate_alert_message(
                    f"{alert_rules} rules public/all traffic enabled"
                )
            )
    else:
        UNSAFE_RULES_NOTIFICATIONS.append(
            panoptes.generic.output.generate_info_message(
                "All security groups have safe rules"
            )
        )

    template_variables = {
        "HEADER": HEADER,
        "FIRST_SECTION": FIRST_SECTION,
        "UNUSED_SECGROUPS": UNUSED_SECGROUPS,
        "UNUSED_SECGROUP_NOTIFICATIONS": UNUSED_SECGROUP_NOTIFICATIONS,
        "SECOND_SECTION": SECOND_SECTION,
        "UNSAFE_SECGROUPS": UNSAFE_SECGROUPS,
        "UNSAFE_RULES_NOTIFICATIONS": UNSAFE_RULES_NOTIFICATIONS,
    }

    human_output = human_output_template.render(**template_variables)
    return human_output


if __name__ == "__main__":
    pass
