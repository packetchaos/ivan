import click
import pprint
from .database import db_query
import textwrap


def find_by_plugin(pid):
    rows = db_query("SELECT asset_ip, asset_uuid, asset_hostname, repo_name, repo_id from vulns where plugin_id={}".format(pid))

    click.echo("\n{:8s} {:16s} {:46s} {:46} {}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
    click.echo("-" * 150)

    for row in rows:
        click.echo("{:8s} {:16s} {:46s} {:46} {}".format(str(pid), row[0], textwrap.shorten(row[2], 46), row[3], row[4]))

    click.echo()


@click.group(help="Discover assets with Open ports, Running containers and more")
def find():
    pass


@find.command(help="Find Assets where a plugin fired using the plugin ID")
@click.argument('plugin_id')
@click.option('--o', '--output', default='', help='Find Assets based on the text in the output')
def plugin(plugin_id, o):
    if not str.isdigit(plugin_id):
        click.echo("You didn't enter a number")
        exit()
    else:
        if o != "":
            click.echo("\n{:8s} {:16s} {:46s}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
            click.echo("-" * 150)

            plugin_data = db_query("SELECT asset_ip, asset_uuid, asset_hostname, repo_name, repo_id from vulns where plugin_id='{}' and output LIKE '%{}%';".format(plugin_id,o))

            for row in plugin_data:
                try:
                    fqdn = row[2]
                except:
                    fqdn = " "
                click.echo("{:8s} {:16s} {:46s {:46} {}".format(str(plugin_id), row[0], textwrap.shorten(fqdn, 46), row[3], row[4]))

        else:
            find_by_plugin(plugin_id)


@find.command(help="Find Assets that have a given CVE iD")
@click.argument('cve_id')
def cve(cve_id):

    if len(cve_id) < 10:
        click.echo("\nThis is likely not a CVE...Try again...\n")

    elif "CVE" not in cve_id:
        click.echo("\nYou must have 'CVE' in your CVE string. EX: CVE-1111-2222\n")

    else:
        click.echo("\n{:8s} {:16s} {:46s} {:46} {}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
        click.echo("-" * 150)

        plugin_data = db_query("SELECT asset_ip, asset_uuid, asset_hostname where cves LIKE '%{}%';".format(cve_id))

        for row in plugin_data:
            try:
                fqdn = row[2]
            except:
                fqdn = " "
            click.echo("{:8s} {:16s} {:46s} {:46} {}".format(row[3], row[0], textwrap.shorten(fqdn, 46), row[3], row[4]))

        click.echo()


@find.command(help="Find Assets that have an exploitable vulnerability")
def exploit():

    click.echo("\n{:8s} {:16s} {:46s} {:46} {}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
    click.echo("-" * 150)

    plugin_data = db_query("SELECT asset_ip, asset_hostname, plugin_id, repo_name, repo_id from vulns where exploit = 'True';")

    for row in plugin_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "
        click.echo("{:8s} {:16s} {:46s} {:46} {}".format(row[3], row[0], textwrap.shorten(fqdn, 46), row[3], row[4]))

    click.echo()


@find.command(help="Find Assets where Text was found in the output of any plugin")
@click.argument('out_put')
def output(out_put):

    click.echo("\n{:8s} {:16s} {:46s} {:46} {}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
    click.echo("-" * 150)

    plugin_data = db_query("SELECT asset_ip, asset_uuid, asset_hostname, plugin_id, repo_name, repo_id from vulns where output LIKE '%{}%';".format(str(out_put)))

    for row in plugin_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "
        click.echo("{:8s} {:16s} {:46s} {:46} {}".format(row[4], row[0], textwrap.shorten(fqdn, 46), row[3], row[4]))

    click.echo()


@find.command(help="Find Docker Hosts using plugin 93561")
def docker():
    click.echo("Searching for RUNNING docker containers...")
    find_by_plugin(str(93561))


@find.command(help="Find Assets with Credential Issues using plugin 104410")
def creds():
    click.echo("\nBelow are the Assets that have had Credential issues\n")
    find_by_plugin(104410)


@find.command(help="Find Assets that took longer than a given set of minutes to complete")
@click.argument('minute')
def scantime(minute):

    click.echo("\n*** Below are the assets that took longer than {} minutes to scan ***".format(str(minute)))

    data = db_query("SELECT asset_ip, asset_hostname, plugin_id, repo_name, repo_id, output from vulns where plugin_id='19506';")

    try:
        click.echo("\n{:8s} {:16s} {:46s} {:46} {}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
        click.echo("-" * 150)
        for vulns in data:

            plugin_output = vulns[5]

            # split the output by return
            parsed_output = plugin_output.split("\n")

            # grab the length so we can grab the seconds
            length = len(parsed_output)

            # grab the scan duration- second to the last variable
            duration = parsed_output[length - 2]

            # Split at the colon to grab the numerical value
            seconds = duration.split(" : ")

            # split to remove "secs"
            number = seconds[1].split(" ")

            # grab the number for our minute calculation
            final_number = number[0]

            if final_number != 'unknown':
                # convert seconds into minutes
                minutes = int(final_number) / 60

                # grab assets that match the criteria
                if minutes > int(minute):
                    try:
                        click.echo("{:8} {:16s} {:46s} {:46s} {}".format(str(vulns[2]), str(vulns[0]),
                                                                         str(vulns[1]), str(vulns[3]),
                                                                         str(vulns[4])))
                    except ValueError:
                        pass
        click.echo()
    except Exception as E:
        print(E)


@find.command(help="Find Assets with a given port open")
@click.argument('open_port')
def port(open_port):
    data = db_query("SELECT plugin_id, asset_ip, asset_hostname, repo_name, repo_id from vulns where port='{}' and (plugin_id='11219' or plugin_id='14272' or plugin_id='14274' or plugin_id='34220' or plugin_id='10335');".format(open_port))

    try:
        click.echo("\nThe Following assets had Open ports found by various plugins")
        click.echo("\n{:8s} {:16s} {:46s} {:40s} {}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
        click.echo("-" * 150)

        for vulns in data:
            try:
                fqdn = vulns[2]
            except:
                fqdn = " "

            click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(str(vulns[0]), vulns[1], textwrap.shorten(fqdn, 46),
                                                              vulns[3], vulns[4]))

        click.echo()
    except ValueError:
        pass


@find.command(help="Find Assets using a custom SQL query.")
@click.argument('statement')
def query(statement):
    data = db_query(statement)
    pprint.pprint(data)


@find.command(help="Find Assets where a plugin fired with TEXT found in a plugin name")
@click.argument('plugin_name')
def name(plugin_name):

    plugin_data = db_query("SELECT asset_ip, plugin_name, plugin_id, repo_name, repo_id from vulns where plugin_name LIKE '%" + plugin_name + "%';")

    click.echo("\nThe Following assets had '{}' in the Plugin Name".format(plugin_name))
    click.echo("\n{:8s} {:20} {:70} {:40} {} ".format("Plugin", "IP address", "Plugin Name", "Repo Name", "Repo ID"))
    click.echo("-" * 150)

    for vulns in plugin_data:
        click.echo("{:8s} {:20} {:70} {:40} {}".format(vulns[2], vulns[0], textwrap.shorten(str(vulns[1]), 65), str(vulns[3]), vulns[4]))

    click.echo()


@find.command(help="Find Assets that have a Cross Reference Type and/or ID")
@click.argument('xref')
@click.option("--xid", "--xref-id", default='', help="Specify a Cross Reference ID")
def xrefs(xref, xid):
    click.echo("\n{:8s} {:16s} {:46s} {:46} {}".format("Plugin", "IP Address", "FQDN", "Repo Name", "Repo ID"))
    click.echo("-" * 150)

    if xid:
        xref_data = db_query("select plugin_id, asset_ip, asset_hostname, repo_name, repo_id, xrefs from vulns where xrefs LIKE '%{}%' AND xrefs LIKE '%{}%'".format(xref, xid))

    else:
        xref_data = db_query("select plugin_id, asset_ip, asset_hostname, repo_name, repo_id, xrefs from vulns where xrefs LIKE '%{}%'".format(xref))

    for row in xref_data:
        try:
            fqdn = row[2]
        except:
            fqdn = " "

        click.echo("{:8s} {:16s} {:46s} {:40s} {}".format(row[0], row[1], textwrap.shorten(fqdn, 46), row[3], row[4]))

    click.echo()
