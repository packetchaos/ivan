# Ivan - The Tenable Security Center Swiss Army Knife
A command-line tool which leverages the Tenable Security Center API to automate common tasks
in Cyber Exposure or Vulnerability Management.

    *** This tool is not an officially supported Tenable project ***
    
    *** Use of this tool is subject to the terms and conditions identified below,
     and is not subject to any license agreement you may have with Tenable ***

### Authenticating to Tenable Security Center

    ivan keys --a <your access key or username> --s <your secret key or password> --h <ipaddresss or FQDN>

### Are my Keys inputted correctly?
In different terminals it can be a challenge to copy the keys to navi since you can not be sure it copied correctly.  

Use the below commands to check your keys
    
    ivan find query "select * from keys;"

Alternatively, you could try entering your keys again using the '-clear' command to see what is being copied to the screen.

    ivan keys -clear


### Update the Ivan Database

    ivan update vulns

### Query the database directly

    ivan find query "select * from vulns;"

Show me the assets which have docker installed and the containers running

    ivan find query "select asset_ip, plugin_id, output from vulns where plugin_id='93561';"

How many critical vulns do we have?

    ivan find query "select count(*) from vulns where severity='critical';"


### Export data into a CSV

    ivan export query "select asset_ip, plugin_name, description, solution, severity, score from vulns where score <='7';"
