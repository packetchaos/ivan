import click
import textwrap
from sqlite3 import Error
from .database import db_query


def plugin_by_ip(ipaddr, plugin):
    try:
        if len(ipaddr) < 17:
            rows = db_query("SELECT output, cves, score, xrefs, repo_name, repo_id from vulns where asset_ip='{}' and plugin_id='{}'".format(ipaddr, plugin))
        else:
            rows = db_query("SELECT output, cves, score, xrefs, repo_name, repo_id from vulns where asset_uuid='{}' and plugin_id='{}'".format(ipaddr, plugin))

        for plug in rows:
            click.echo("Found in Repository:\n{} - {}".format(plug[4], plug[5]))
            if plug[2] != ' ':
                click.echo("\nVPR Score: {}".format(plug[2]))

            if plug[3] != ' ':
                click.echo("\nCross References\n")
                click.echo("-" * 80)
                for xref in plug[3]:
                    click.echo(xref)

            click.echo("\nPlugin Output")
            click.echo("-" * 60)
            click.echo(plug[0][15:-16])

            if plug[1] != ' ':
                click.echo("\nCVEs attached to this plugin")
                click.echo("-" * 80)
                click.echo("{}\n".format(plug[1]))
        click.echo()
    except IndexError:
        click.echo("No information found for this plugin")


def vulns_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, severity, repo_name from vulns where asset_ip='{}' and severity !='info';".format(uuid))

        click.echo("\n{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format("Plugin", "Plugin Name", "Plugin Family", "Repo_name", "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            plugin_name = vulns[1]
            plugin_family = vulns[2]
            port = vulns[3]
            protocol = vulns[4]
            severity = vulns[5]
            repo_name = vulns[6]
            click.echo("{:10s} {:70s} {:35s} {:10s} {:6s} {:6s} {}".format(plugin_id, textwrap.shorten(plugin_name, 70), textwrap.shorten(plugin_family, 35), repo_name, port, protocol, severity))
        click.echo("")
    except Error as e:
        click.echo(e)


def info_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, plugin_name, plugin_family, port, protocol, severity from vulns where asset_ip='{}' and severity =='info';".format(uuid))

        click.echo("\n{:10s} {:90s} {:25s} {:6s} {:6s} {}".format("Plugin", "Plugin Name", "Plugin Family", "Port", "Proto", "Severity"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            plugin_name = vulns[1]
            plugin_family = vulns[2]
            port = vulns[3]
            protocol = vulns[4]
            severity = vulns[5]
            click.echo("{:10s} {:90s} {:25s} {:6s} {:6s} {}".format(plugin_id, plugin_name, plugin_family, port, protocol, severity))
        click.echo("")
    except Error as e:
        click.echo(e)


def cves_by_uuid(uuid):
    try:
        data = db_query("select plugin_id, cves from vulns where asset_ip='{}' and cves !=' ';".format(uuid))

        click.echo("\n{:10s} {}".format("Plugin", "CVEs"))
        click.echo("-"*150)

        for vulns in data:
            plugin_id = vulns[0]
            cves = vulns[1]
            click.echo("{:10s} {}".format(plugin_id, textwrap.shorten(cves, 140)))
        click.echo("")
    except IndexError:
        click.echo("Something went wrong")


@click.command(help="Get Asset details based on IP or UUID")
@click.argument('ipaddr')
@click.option('--plugin', default='', help='Find Details on a particular plugin ID')
@click.option('-n', '-netstat', is_flag=True, help='Netstat Established(58561) and Listening and Open Ports(14272)')
@click.option('-p', '-patch', is_flag=True, help='Patch Information - 66334')
@click.option('-t', '-tracert', is_flag=True, help='Trace Route - 10287')
@click.option('-o', '-processes', is_flag=True, help='Process Information - 70329')
@click.option('-c', '-connections', is_flag=True, help='Connection Information - 64582')
@click.option('-s', '-services', is_flag=True, help='Services Running - 22964')
@click.option('-r', '-firewall', is_flag=True, help='Local Firewall Rules - 56310')
@click.option('-patches', is_flag=True, help='Missing Patches - 38153')
@click.option('-d', is_flag=True, help="Scan Detail: 19506 plugin output")
@click.option('-software', is_flag=True, help="Find software installed on Unix(22869) of windows(20811) hosts")
@click.option('-outbound', is_flag=True, help="outbound connections found by nnm")
@click.option('-exploit', is_flag=True, help="Display Solution, Description for each Exploit")
@click.option('-critical', is_flag=True, help="Display Plugin Output for each Critical Vuln")
@click.option('-details', is_flag=True, help="Details on an Asset: IP, UUID, Vulns, etc")
@click.option('-vulns', is_flag=True, help="Display all vulnerabilities and their plugin IDs")
@click.option('-info', is_flag=True, help="Display all info plugins and their IDs")
@click.option('-cves', is_flag=True, help="Display all cves found on the asset")
@click.option('-compliance', '-audits', is_flag=True, help="Display all Compliance info for a given asset UUID")
@click.pass_context
def ip(ctx, ipaddr, plugin, n, p, t, o, c, s, r, patches, d, software, outbound, exploit, critical, details, vulns,
       info, cves, compliance):

    if d:
        click.echo('\nScan Detail')
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(19506))

    if n:
        click.echo("\nNetstat info")
        click.echo("Established and Listening")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(58651))
        click.echo("\nNetstat Open Ports")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(14272))

    if p:
        click.echo("\nPatch Information")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(66334))

    if t:
        click.echo("\nTrace Route Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(10287))

    if o:
        click.echo("\nProcess Info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(70329))
        plugin_by_ip(ipaddr, str(110483))

    if patches:
        click.echo("\nMissing Patches")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(38153))
        plugin_by_ip(ipaddr, str(66334))

        click.echo("\nLast Reboot")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(56468))

    if c:
        click.echo("\nConnection info")
        click.echo("-" * 15)
        click.echo()
        plugin_by_ip(ipaddr, str(64582))

    if s:
        try:
            if len(ipaddr) < 17:
                data = db_query("SELECT output, port from vulns where asset_ip=\"%s\" and plugin_id='22964'" % ipaddr)
            else:
                data = db_query("SELECT output, port from vulns where asset_uuid=\"%s\" and plugin_id='22964'" % ipaddr)

            for plugins in data:
                output = plugins[0]
                port = plugins[1]
                click.echo("\n{} {}".format(str(output), str(port)))
            click.echo()
        except IndexError:
            click.echo("No information for plugin 22964")

    if r:
        click.echo("Local Firewall Info")
        click.echo("-" * 15)
        plugin_by_ip(ipaddr, str(56310))
        plugin_by_ip(ipaddr, str(61797))

    if software:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
            click.echo("No Software found")

    if outbound:
        try:
            if len(ipaddr) < 17:
                data = db_query("SELECT output, port, protocol from vulns where asset_ip=\"%s\" and plugin_id='16'" % ipaddr)
            else:
                data = db_query("SELECT output, port, protocol from vulns where asset_uuid=\"%s\" and plugin_id='16'" % ipaddr)

            click.echo("\n{:15s} {:5} {}".format("IP address", "Port", "Protocol"))
            click.echo("-" * 25)
            for plugins in data:
                output = plugins[0]
                port = plugins[1]
                proto = plugins[2]
                click.echo("\n{:15s} {:5} {}".format(str(output), str(port), str(proto)))
            click.echo()
        except Exception as E:
            click.echo("No information for plugin 16")
            click.echo(E)

    if vulns:
        if len(ipaddr) < 17:
            vulns_by_uuid(ipaddr)

    if cves:
        if len(ipaddr) < 17:
            cves_by_uuid(ipaddr)

    if info:
        info_by_uuid(ipaddr)

    if plugin != '':
        plugin_by_ip(ipaddr, plugin)
