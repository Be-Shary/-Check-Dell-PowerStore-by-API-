# Check Dell PowerStore by API


## Installation + Requirements
* python3 -> python -m pip install requests 
* python2.7 -> python -m pip install requests==2.7.0 
* python 2.6 ->  sudo yum install python-requests

## Nagios configuration
Sample configuration files:

commands.cfg file:

    define command{
            command_name    check_dell_powerstore
            command_line    /usr/bin/python $USER1$/check_powerstore_api.py -H $HOSTADDRESS$ $ARG1$
    }

host.cfg file:

    define host {
    use                            generic-host
    host_name                      test-dell-powerstore-cluster
    alias                          test-dell-powerstore-cluster
    address                        10.200.20.100
    }

    define service {
    use                            generic-service
    host_name                      test-dell-powerstore-cluster
    service_description            Dell PowerStore Health Check
    check_command                  check_dell_powerstore!-u mon -p 'qwerty123?' -f 80,90 -c all -v
    }


## Usage
python check_powervault_api.py -H IP/hostname -u user -p 'password' -f 80,90 -c all -v

optional arguments:
*   -h, --help            show this help message and exit
*   -H host address       **(Required)** IP or hostname
*   -u api username       **(Required)** Your API username
*   -p api password       **(Required)** Your API username
*   -v                    **(Optional)** List full output (not only alerts), default: off
*   -f capacity           **(Not required)** Raise alert if limit is hit: 80,90 as percent for WARNING,CRITICAL
*   -c all mem psu fan disk ports volume volgroup alert [all mem psu fan disk ports volume volgroup alert ...] **(Required)** List of checks, choose all, one or few.

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

