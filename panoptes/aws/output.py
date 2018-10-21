""" Panoptes - AWS - Output

Functions to print specific AWS analysis output.
"""

import colorama
import jinja2
import panoptes


ALL_TRAFFIC_PROTOCOL = "-1"
COLOR_ALERT = colorama.Fore.LIGHTRED_EX
COLOR_WARNING = colorama.Fore.LIGHTYELLOW_EX
TEMPLATE = """{{ HEADER }}



Cloud provider  ->  {{ CLOUD_PROVIDER_NAME }}
Authentication  ->  {{ CLOUD_PROVIDER_AUTH }}
Started at      ->  {{ ANALYSIS_START_TIME }}
Finished at     ->  {{ ANALYSIS_END_TIME }}



{{ FIRST_SECTION }}
{% for secgroup in UNUSED_SECGROUPS %}{{ secgroup }}
{% endfor %}

{% for notification in UNUSED_SECGROUP_NOTIFICATIONS %}{{ notification }}
{% endfor %}


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
                f"{len(unused_groups_list)} security groups found not being used"
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
                # Prettifying "protocol"
                protocol = ingress['IpProtocol'].upper()
                if protocol == ALL_TRAFFIC_PROTOCOL:
                    protocol = "All"

                # Prettifying "range"
                if any(k in ingress for k in ['FromPort', 'ToPort']):
                    if ingress['FromPort'] == ingress["ToPort"]:
                        range = (
                            f"{ingress['FromPort']}"
                        )
                    else:
                        range = (
                            f"{ingress['FromPort']}-{ingress['ToPort']}"
                        )
                else:
                    range = "All"

                if ingress['Status'] == "warning":
                    color = COLOR_WARNING
                    warning_rules += 1
                elif ingress['Status'] == "alert":
                    color = COLOR_ALERT
                    alert_rules += 1

                rules += (
                    generate_ingress_message(
                        protocol=protocol,
                        cidr_ip=ingress['CidrIp'],
                        range=range,
                        color=color,
                    )+'\n'
                )
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
                    f"{alert_rules} rules found with public IPs or all traffic enabled"
                )
            )
    else:
        UNSAFE_RULES_NOTIFICATIONS.append(
            panoptes.generic.output.generate_info_message(
                "All security groups have safe rules"
            )
        )

    start_time = panoptes.generic.helpers.generate_human_time(
        panoptes.generic.helpers.convert_string_datetime(analysis["Metadata"]["StartedAt"])
    )
    end_time = panoptes.generic.helpers.generate_human_time(
        panoptes.generic.helpers.convert_string_datetime(analysis["Metadata"]["FinishedAt"])
    )

    template_variables = {
        "HEADER": HEADER,
        "FIRST_SECTION": FIRST_SECTION,
        "UNUSED_SECGROUPS": UNUSED_SECGROUPS,
        "UNUSED_SECGROUP_NOTIFICATIONS": UNUSED_SECGROUP_NOTIFICATIONS,
        "SECOND_SECTION": SECOND_SECTION,
        "UNSAFE_SECGROUPS": UNSAFE_SECGROUPS,
        "UNSAFE_RULES_NOTIFICATIONS": UNSAFE_RULES_NOTIFICATIONS,
        "CLOUD_PROVIDER_NAME": analysis["Metadata"]["CloudProvider"]["Name"].upper(),
        "CLOUD_PROVIDER_AUTH": analysis["Metadata"]["CloudProvider"]["Auth"],
        "ANALYSIS_START_TIME": start_time,
        "ANALYSIS_END_TIME": end_time,
    }

    human_output = human_output_template.render(**template_variables)
    return human_output


if __name__ == "__main__":
    pass
