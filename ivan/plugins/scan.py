import click
import arrow
from .scan_evaluation import evaluate_a_scan
from .sc_vuln_export import tenb_connection
from .scanidv_vuln_export import tenb_connection, scanid_export


@click.group(help="Start and Evaluate Scans")
def scan():
    pass


@scan.command(help="Evaluate a specific scan or the entire database")
@click.option("--scanid", default=None, help="A Scan ID you want to evaluate")
@click.option("-full", is_flag=True, help="Evaluate entire available history")
def evaluate(full, scanid):

    if full:
        evaluate_a_scan(table="vulns")

    elif scanid:
        # Create new table named scan_id
        # download data into new table
        scanid_export(scanid)

        evaluate_a_scan(table=scanid)
    else:
        click.echo("\nYou must select full or select a scanid to evaluate\n")


@scan.command(help="Start a valid Scan by Scan ID")
@click.argument('scan_id')
@click.option('--targets', default=None, help="Start the scan with alternative targets")
def start(scan_id, targets):
    tsc = tenb_connection()
    if targets is None:
        tsc.scans.launch(scan_id)
    else:
        tsc.scans.launch(scan_id, targets=targets)


@scan.command(help="Get details on a Scan")
@click.argument('scan_id')
def details(scan_id):
    sc = tenb_connection()
    scan_details = sc.scan_instances.details(id=scan_id)

    click.echo("\nScan Details")
    click.echo("-" * 75)
    click.echo()

    # Grab scan data
    scan_duration = scan_details['scanDuration']
    scanned_ips = scan_details['scannedIPs']
    start_time = arrow.get(float(scan_details['startTime']))
    current_status = scan_details['status']
    total_checks = scan_details['totalChecks']
    total_ips = scan_details['totalIPs']
    completed_checks = scan_details['progress']['completedChecks']
    completed_ips = scan_details['progress']['completedIPs']
    checks_per_host = scan_details['progress']['checksPerHost']
    scanned_size = scan_details['progress']['scannedSize']
    deadhost_size = scan_details['progress']['deadHostSize']
    distributed_size = scan_details['progress']['distributedSize']
    average = (int(scan_duration) / int(scanned_size)) / 60

    click.echo("{:40s}{}".format("Current Status: ", current_status))
    click.echo("{:40s}{}".format("Scanned Start time: ", start_time.format("MM-DD-YYYY HH:mm:ss")))
    click.echo("{:40s}{}{}".format("Scan Duration: ", scan_duration, " Seconds"))

    click.echo("-" * 50)
    click.echo("-" * 50)

    click.echo("\nTarget Details")
    click.echo("-" * 75)
    click.echo()

    click.echo("{:40s}{}".format("Total IPs Targeted: ", total_ips))
    click.echo("{:40s}{}".format("Total number of IPs scanned:",scanned_ips))
    click.echo("{:40s}{}".format("Assets found in the scan", scanned_size))
    click.echo("{:40s}{}".format("Total number of Dead Hosts", deadhost_size))
    click.echo("{:40s}{}".format("Total Distributed Size", distributed_size))
    click.echo("{:40s}{}".format("Total Completed IPs", completed_ips))

    click.echo("-" * 50)
    click.echo("-" * 50)

    click.echo("\nPlugin Details")
    click.echo("-" * 75)
    click.echo()
    click.echo("{:40s}{}".format("Total plugins performed: ",total_checks))
    click.echo("{:40s}{}".format("Total Completed Plugins: ", completed_checks))
    click.echo("{:40s}{}".format("Total Plugins per host: ", checks_per_host))
    click.echo("{:40s}{}{}".format("Avg Duration per asset: ", str(average), " mins"))

    click.echo("-" * 50)
    click.echo("-" * 50)

    click.echo("\nScanner Details")
    click.echo("-" * 75)
    click.echo()
    scanner_details = scan_details['progress']['scanners']

    for scanners in scanner_details:
        chunk_completed = scanners['chunkCompleted']
        completed_checks = scanners['completedChecks']
        dead_host_size = scanners['deadHostSize']
        distributed_size_by_scanner = scanners['distributedSize']
        scanner_name = scanners['name']
        asset_count = scanners['scannedSize']

        click.echo("{:40s}{}".format("Scanner Name", scanner_name))
        click.echo("-" * 50)
        click.echo("{:40s}{}".format("   -Total Chunks Completed", chunk_completed))
        click.echo("{:40s}{}".format("   -Total Checks Completed", completed_checks))
        click.echo("{:40s}{}".format("   -Dead hosts found by the Scanner", dead_host_size))
        click.echo("{:40s}{}".format("   -IPs distributed to the scanner", distributed_size_by_scanner))
        click.echo("{:40s}{}".format("   -Assets found by the scanner", asset_count))
        click.echo("-" * 50)
        click.echo()
    click.echo("-" * 50)
    click.echo("-" * 50)

    click.echo("\nImport Details")
    click.echo("-" * 75)
    click.echo()

    import_duration = scan_details['importDuration']
    import_finish = arrow.get(float(scan_details['importFinish']))
    import_start = arrow.get(float(scan_details['importStart']))
    import_status = scan_details['importStatus']

    click.echo("{:40s}{}{}".format("Import Duration", import_duration, " Seconds"))
    click.echo("{:40s}{}".format("Import Start Time", import_start.format("MM-DD-YYYY HH:mm:ss")))
    click.echo("{:40s}{}".format("Import Finish Time", import_finish.format("MM-DD-YYYY HH:mm:ss")))
    click.echo("{:40s}{}".format("Import Status", import_status))
    click.echo("-" * 50)
    click.echo("-" * 50)

    click.echo("\nError Details")
    click.echo("-" * 75)
    click.echo()

    error_details = scan_details['errorDetails']
    error_sync_details = scan_details['ioSyncErrorDetails']
    import_errors = scan_details['importErrorDetails']

    click.echo("{:40s}{}".format("Error Details:\n", error_details))
    click.echo("{:40s}{}".format("Tenable VM Sync Error Details:\n", error_sync_details))
    click.echo("{:40s}{}".format("Import Error Details:\n", import_errors))


@scan.command(help="Export a Scan")
@click.argument('scan_id')
def export(scan_id):
    tsc = tenb_connection()
    with open('scan-id-{}.nessus'.format(scan_id), 'wb') as fobj:
        tsc.scan_instances.export_scan(scan_id, fobj)
