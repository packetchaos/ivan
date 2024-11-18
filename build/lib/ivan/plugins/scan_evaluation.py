import click
from .database import db_query
import csv


def grab_hop_count(table, ipaddy):

    if table != "vulns":
        # Set the table properly
        table = "scanid"
    # grab the output of 10287 - Trace Route
    try:
        hop_count_data = db_query("select output from {} where asset_ip='{}' and plugin_id='10287';".format(table, ipaddy))
        # Send the raw data back
        hopcount = hop_count_data[0][-1].split(" ")[-1]

        if "way" in hopcount:
            hopcount = hop_count_data[0][-1].split(" ")[-7]
            if "an" in hopcount:
                print("Error")
                return "error"

            return hopcount
        else:
            return hopcount
    except:
        return "none"


def evaluate_a_scan(table):
    click.echo("*" * 100)
    click.echo("\nThis command uses the 19506 plugin data found in the navi.db\n"
               "Run a navi update command to refresh the database.\n")
    click.echo("*" * 100)
    # Pull all 19506 Plugins from the DB
    if table != "vulns":
        table = "scanid"
    plugin_data = db_query("select asset_ip, output from {} where plugin_id='19506';".format(table))

    # Set some dicts for organizing Data
    scan_policy_dict = {}
    scanner_dict = {}
    scan_name_dict = {}
    scanner_list = []
    # Open a CSV for export
    with open('evaluate-{}.csv'.format(table), mode='w', encoding='utf-8', newline="") as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["Asset IP Address", "Scan Name", "Scan Policy", "Scanner IP", "Scan Time", "Max Checks",
                       "Max Hosts", "Minutes", "RTT", "Hop Count"]

        # Write the header to the csv
        agent_writer.writerow(header_list)

        # This function is used to parse the data
        # Getting the length of the Category and using it to get the average
        def average_by_policy(name, scan_info):
            # Print the Category to the Screen ( Scanner, Policy, Scan Name)
            click.echo("\n{:100s} {:25s} {:10}".format(name, "AVG Minutes Per/Asset", "Total Assets"))
            click.echo("-" * 20)

            # Cycle through each category
            for scan in scan_info.items():

                # data is in a list [asset_uuid, mins] We need the length of the total mins found
                length = len(scan[1])

                # Reset the total per Category Item - Specific Scan ID, Scanner, Policy ID
                total = 0

                # Cycle through each asset record
                for assets in scan[1].values():
                    # Gather a total
                    total = assets + total

                # After calculating the total, lets get an average
                average = total/length

                # Print results to the screen
                click.echo("\n{:100s} {:25d} {:10d}".format(scan[0], int(average), length))

            click.echo("-" * 150)

        # Loop through each plugin 19506 and Parse data from it
        for vulns in plugin_data:
            plugin_dict = {}

            # Output is the second item in the tuple from the DB
            plugin_output = vulns[1]

            # split the output by return
            parsed_output = plugin_output.split("\n")

            for info_line in parsed_output:
                try:
                    new_split = info_line.split(" : ")
                    plugin_dict[new_split[0]] = new_split[1]

                except:
                    pass
            try:
                intial_seconds = plugin_dict['Scan duration']
            except KeyError:
                intial_seconds = 'unknown'

            # For an unknown reason, the scanner will print unknown
            # for some assets leaving no way to calculate the time.
            if intial_seconds != 'unknown':
                try:
                    # Numerical value in seconds parsed from the plugin
                    try:
                        seconds = int(intial_seconds[:-3])
                        minutes = seconds / 60
                    except ValueError:
                        minutes = 0

                    try:
                        scan_name = plugin_dict['Scan name']
                    except KeyError:
                        scan_name = "none"
                    try:
                        scan_policy = plugin_dict['Scan policy used']
                    except KeyError:
                        scan_policy = "none"
                    try:
                        scanner_ip = plugin_dict['Scanner IP']
                        # Enumerate all scanners for per/scanner stats
                        if scanner_ip not in scanner_list:
                            scanner_list.append(scanner_ip)
                    except KeyError:
                        scanner_list = "none"
                        scanner_ip= "none"
                    try:
                        max_hosts = plugin_dict['Max hosts']
                    except KeyError:
                        max_hosts = "none"
                    try:
                        max_checks = plugin_dict['Max checks']
                    except KeyError:
                        max_checks = "none"

                    # Grabbing the start time from the plugin
                    try:
                        start_time = plugin_dict['Scan Start Date']
                    except KeyError:
                        start_time = "none"
                    try:
                        rtt = plugin_dict['Ping RTT']
                    except KeyError:
                        rtt = "none"

                    try:
                        # Grab the last line in the Trace route Plugin output
                        # Split on the space and grab the numerical value.
                        hopcount = grab_hop_count(table, vulns[0])
                    except IndexError:
                        hopcount = "Unknown"

                    parsed_data_organized = [vulns[0], scan_name, scan_policy, scanner_ip, start_time, max_checks, max_hosts, minutes, rtt, hopcount]

                    agent_writer.writerow(parsed_data_organized)

                    # Organize Data by Scan Policy
                    # If the category is not in the new dict, add it; else update it.
                    if scan_policy not in scan_policy_dict:
                        scan_policy_dict[scan_policy] = {vulns[0]: minutes}
                    else:
                        scan_policy_dict[scan_policy].update({vulns[0]: minutes})

                    if scanner_ip not in scanner_dict:
                        scanner_dict[scanner_ip] = {vulns[0]: minutes}
                    else:
                        scanner_dict[scanner_ip].update({vulns[0]: minutes})

                    if scan_name not in scan_name_dict:
                        scan_name_dict[scan_name] = {vulns[0]: minutes}
                    else:
                        scan_name_dict[scan_name].update({vulns[0]: minutes})
                except IndexError:
                    # This error occurs when an old scanner is used.
                    # the 19506 plugin filled with an error indicating the need for an upgrade
                    pass

        average_by_policy("Policies", scan_policy_dict)

        average_by_policy("Scanners", scanner_dict)

        average_by_policy("Scan Name", scan_name_dict)

