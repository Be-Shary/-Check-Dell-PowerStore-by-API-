import requests
import sys
import argparse
import json
from argparse import RawTextHelpFormatter, SUPPRESS

# NOTE: This is to suppress the insecure connection warning for certificate verification.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_data(url, username, password, type="GET"):
    try:
        if type == "GET":
            response = requests.get(url, auth=(username, password), verify=False, timeout=30)
        elif type == "POST":
            post_data = {"entity": "space_metrics_by_cluster", "entity_id": "0", "interval": "Best_Available"}
            response = requests.post(url, auth=(username, password), json=post_data, timeout=10, verify=False)
        code = (response.status_code)
        if code == 206 or code == 200:
            data = response.json()
            return data
        else:
            sys.exit(3)
    except requests.exceptions.ConnectTimeout:
        print("UNKNOWN - Connection timeout!")
        sys.exit(3)
    except requests.exceptions.ConnectionError:
        print("UNKNOWN - Connection failed: " + str(sys.exc_info()[1]))
        sys.exit(3)
    except:
        print("UNKNOWN - Unexpected error: " + str(sys.exc_info()))
        sys.exit(3)


def check_hardware(hostname, checks):
    global exit_code, output, verbose
    url = "https://" + str(hostname) + "/api/rest/hardware?select=*"
    data = get_data(url, username, password)
    for i in range(len(checks)):
        for item in data:
            if item["type"] == checks[i]:
                if verbose:
                    output += "\n" + str(item["name"].replace("BaseEnclosure-", "")) + ": " + str(
                        item["lifecycle_state"]) + " - serial number: " + str(item["serial_number"])
                if item["lifecycle_state"] != "Healthy" and item["lifecycle_state"] != "Empty":
                    if not verbose:
                        output += "\n" + str(item["name"].replace("BaseEnclosure-", "")) + ": " + str(
                            item["lifecycle_state"]) + " - serial number: " + str(item["serial_number"])
                    exit_code = 2
                    output += " (!!)"
        if verbose:
            output += "\n-----------------------------"


def check_volumes(hostname):
    global exit_code, output, verbose
    url = "https://" + str(hostname) + "/api/rest/volume?select=name,state,node_affinity"
    data = get_data(url, username, password)
    for item in data:
        if verbose:
            output += "\nName: " + str(item["name"]) + " - " + str(item["node_affinity"]) + " state: " + str(
                item["state"])
        if item["state"] != "Ready":
            if not verbose:
                output += "\nName: " + str(item["name"]) + " - " + str(item["node_affinity"]) + " state: " + str(
                    item["state"])
            exit_code = 2
            output += " (!!)"
    if verbose:
        output += "\n-----------------------------"


def check_alerts(hostname):
    global exit_code, output, verbose
    url = "https://" + str(hostname) + "/api/rest/alert?select=*"
    data = get_data(url, username, password)
    for item in data:
        if item["severity"] == "Critical" or item["severity"] == "Major" and item["is_acknowledged"] == False:
            output += "\nALERT code: " + str(item["event_code"]) + "; Severity: " + str(
                item["severity"]) + "; state: " + str(item["state"])
            exit_code = 2
            output += " (!!)"
            output += "\n-----------------------------"


def check_capacity(hostname, limit):
    global exit_code, output, verbose
    raise_alert = False
    url = "https://" + str(hostname) + "/api/rest/metrics/generate"
    data = get_data(url, username, password, "POST")
    total_space = float(data[0]["physical_total"]) / 1024 / 1024 / 1024 / 1024
    used_space = float(data[0]["physical_used"]) / 1024 / 1024 / 1024 / 1024
    free = (total_space - used_space)
    free_procent = round(((used_space * 100) / total_space), 2)
    try:
        if free_procent >= float(limit[1]):
            exit_code = 2
            raise_alert = True
        elif free_procent >= float(limit[0]):
            raise_alert = True
            if exit_code == 0:
                exit_code = 1
    except IndexError:
        print("UNKNOWN: Disk space free limits error - check your command line!")
        sys.exit(3)

    if verbose or raise_alert:
        output += "\nCapacity - FREE:" + str(free) + "TB (" + str(free_procent) + "%), USED: " + str(
            round(used_space, 2)) + "TB, TOTAL: " + str(round(total_space)) + "TB"
        if raise_alert:
            output += " (!!)"
        output += "\n-----------------------------"


def check_volumegroup(hostname):
    global exit_code, output, verbose
    url = "https://" + str(hostname) + "/api/rest/volume_group?select=*"
    data = get_data(url, username, password)
    for item in data:
        if verbose:
            output += "\nName: " + str(item["name"]) + ", is protectable: " + str(
                item["is_protectable"]) + ", is write order consistent: " + str(item["is_write_order_consistent"])
            if not item["is_protectable"] or not item["is_write_order_consistent"]:
                output += " (!!)"
                exit_code = 2
            output += "\n-----------------------------"


def check_ports(hostname):
    global exit_code, output, verbose
    url = "https://" + str(hostname) + "/api/rest/eth_port?select=*"
    ports = get_data(url, username, password)
    url = "https://" + str(hostname) + "/api/rest/fc_port?select=*"
    ports += get_data(url, username, password)
    ports_stats = [0, 0, 0] # link up, link unused, link down
    for item in ports:
        if item["is_link_up"]:
            ports_stats[0] += 1
        if not item["is_in_use"]:
            ports_stats[1] += 1
        if not item["is_link_up"] and item["is_in_use"]:
            ports_stats[2] += 1
            output += "/nPort name: " + str(item["name"]) + ", in use: " + str(item["is_in_use"]) + ", link up: " + str( item["is_link_up"]) + " (!!)"
            exit_code = 2
    if verbose:
        output += "\nPorts - Link Up: " + str(ports_stats[0]) + "; Link Unused: " + str(ports_stats[1]) + "; Link Down: " + str(ports_stats[2])
        output += "\n-----------------------------"


if __name__ == "__main__":
    hostname = ""
    username = ""
    password = ""
    verbose = False
    checks = []
    output = ""
    exit_code = 0
    hardware_checks = []

    try:
        parser = argparse.ArgumentParser(
            description="Nagios plugin to monitor health of Your PowerStore.",
            epilog="""
            Short description of checks option:
            all - show all checks
            mem - show status of DIMM slots
            psu - show status of powersupply
            fan - show status of fans
            disk - show status of drives
            ports - show numbers of ports linkup, used, and link down (raise alert if port is used and port is link down)
            volume - show volumes, checks if volume is operating normally
            volgroup - check volume groups, checks if it's protectable and write order consistent
            alert - show Critical and Major alerts (raise alert if there is no acknowledged)
            capacity - check total capacity
                   """,
            formatter_class=RawTextHelpFormatter,
            usage=SUPPRESS)
        parser.add_argument("-H", metavar="host address", help="(Required) IP or hostname", required=True)
        parser.add_argument("-u", metavar="api username", help="(Required) Your API username", required=True)
        parser.add_argument("-p", metavar="api password", help="(Required) Your API username", required=True)
        parser.add_argument('-v', help="(Optional) List full output (not only alerts), default: off",
                            default=False, action="store_true")
        parser.add_argument("-f", metavar="capacity",
                            help="(Not required) Raise alert if limit is hit: 80,90 as percent for WARNING,CRITICAL",
                            required=False, default="80,90")
        parser.add_argument("-c", metavar="all mem psu fan disk ports volume volgroup alert",
                            help="(Required) List of checks, choose all, one or few.",
                            nargs="+", choices=["all", "mem", "psu", "fan", "disk", "ports", "volume", "volgroup", "alert","capacity"], required=True)
        args = parser.parse_args()
    except SystemExit as error:
        if error.code == 2:
            parser.print_help()
        sys.exit(3)
    except:
        parser.print_help()
        sys.exit(3)

    # Assign parsed arguments to variables
    hostname = args.H
    username = args.u
    password = args.p
    free_limit = args.f.split(",")
    verbose = args.v
    checks = args.c

    if "all" in checks:
        hardware_checks = ["DIMM", "Power_Supply", "Fan", "Drive"]
    else:
        if "mem" in checks:
            hardware_checks.append("DIMM")
        if "psu" in checks:
            hardware_checks.append("Power_Supply")
        if "fan" in checks:
            hardware_checks.append("Fan")
        if "disk" in checks:
            hardware_checks.append("Drive")

    check_hardware(hostname, hardware_checks)

    if "volume" in checks and not "all" in checks:
        check_volumes(hostname)
    if "volgroup" in checks and not "all" in checks:
        check_volumegroup(hostname)
    if "alert" in checks and not "all" in checks:
        check_alerts(hostname)
    if "ports" in checks and not "all" in checks:
        check_ports(hostname)
    if "capacity" in checks and not "all" in checks:
        check_capacity(hostname, free_limit)
    if "all" in checks:
        check_volumes(hostname)
        check_alerts(hostname)
        check_volumegroup(hostname)
        check_ports(hostname)
        check_capacity(hostname, free_limit)

    if exit_code == 0:
        if verbose:
            print("OK: No problem detected.\n" + output)
        else:
            print("OK: No problem detected." + output)
    else:
        if exit_code == 1:
            print("WARNING: Some problem detected!\n" + output)
        if exit_code == 2:
            print("CRITICAL: Some problem detected!\n" + output)

    sys.exit(exit_code)
