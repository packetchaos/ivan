# Ivan - The Tenable Security Center Swiss Army Knife

A command-line tool which leverages the Tenable Security Center API to automate common tasks
in Cyber Exposure or Vulnerability Management.

    *** This tool is not an officially supported Tenable project ***
    
    *** Use of this tool is subject to the terms and conditions identified below,
     and is not subject to any license agreement you may have with Tenable ***

### Installing IVAN

    pip3 install ivan-pro

    OR 

    Local Docker Instance:

Navigate in terminal to the folder where the Ivan source code was downloaded. 

    docker build ./ -f Dockerfile -t ivan-pro-image
    docker run -d ivan-pro-image

### Authenticating to Tenable Security Center

    ivan keys --a <your access key or username> --s <your secret key or password> --h <ipaddresss or FQDN> --p <port>

### Are my Keys inputted correctly?

In different terminals it can be a challenge to copy the keys to Ivan since you can not be sure it copied correctly.  

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

### Local Development

If you want to perform local development, pull the package down from Github and comment out the line specified in the Dockerfile. 

A Virtual Python Environment is encouraged for development work. The command to spin up local instance for testing in regular terminal or Virtual Python Env is:
    
    pip3 install -e <Directory of Ivan Source Code>

