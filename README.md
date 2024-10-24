# Monitoring-and-Alerting-on-SSH-Attacks-with-Kippo-Honeypot
In today’s threat landscape, SSH attacks are a persistent risk that organizations must proactively monitor and defend against. Brute force attempts, compromised credentials, and post-exploitation activities can lead to data breaches, malware infections, and other severe consequences. To address this challenge, we have developed KippoSSHWatch, a robust solution that combines the power of the Kippo SSH honeypot with the analytics capabilities of Splunk.

![image](https://github.com/user-attachments/assets/477f5c7a-ec94-449f-a4f7-aeed5b395fef)


Network diagram
There will be use of 3 Virtual Machines:

1) Parrot Security operating system

2) Ubuntu operating system

3) Kali Operating system

Installation of Kippo Honeypot on Parrot Security operating system

Perform every step as the root user

1) Install the required packages:

sudo apt-get update

sudo apt-get install python3-virtualenv authbind build-essential libssl-dev libffi-dev libpython3-dev python3-minimal virtualenv libffi-dev python3-minimal git

2) Create a user and group for Cowrie:

sudo adduser — disabled-password cowrie

3) Download the Cowrie honeypot:

su — cowrie

git clone https://github.com/cowrie/cowrie.git

cd cowrie

![image](https://github.com/user-attachments/assets/66702989-2d51-4080-a32a-3956ba079687)

Some important directories to notice in the above image:

bin/: This directory contains scripts used to start, stop, and restart the Cowrie service and also provides a feature to play log files using ./playlog.

etc/: This directory contains a configuration file of Honeypot and a used file where we can add more users for Honeypot.

honeyfs/: This directory contains the file system that Cowrie presents to attackers when they connect to the honeypot. It includes directories such as /etc/, /bin/, and /home/.

Docker/: This directory contains the necessary files to build and run Cowrie as a Docker container.

var/: This directory contains log files that will be in JSON format or log format which can be playable.

4) Install Cowrie/Kippo Honeypot:

Virtualenv –python=python3 cowrie-env

source cowrie-env/bin/activate

pip install — upgrade pip

pip install -r requirements.txt

5) Configure Cowrie:

cp cowrie.cfg.dist cowrie.cfg

6) This rule will redirect all incoming TCP traffic to port 22 to the honeypot SSH port (2222). You can adjust the — dport option to specify a different source port if needed. On the cowrie.cfg file:

iptables -t nat -A PREROUTING -p tcp — dport 22 -j REDIRECT — to-port 2222

7) Then run these commands so a non-root user can listen on port 22 (blocked by default and we can’t run Cowrie as root so this will be necessary):

sudo touch /etc/authbind/byport/22

sudo chown cowrie:cowrie /etc/authbind/byport/22

sudo chmod 770 /etc/authbind/byport/22

8) Start Honeypot service

bin/cowrie start

Installation of Splunk server on Ubuntu operating system

1) Download the latest version of Splunk from the Splunk website using wget command:

wget -O splunk-<version>-linux-<architecture>.deb ‘https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=<architecture>&platform=linux&version=<version>&product=splunk&filename=splunk-<version>-linux-<architecture>.deb&wget=true'

2) Start the Splunk service using systemctl command:

sudo systemctl start splunk

3) Enable Splunk to start automatically on system boot using systemctl command:

sudo systemctl enable splunk

4) Set the Splunk admin password using splunk command:

sudo /opt/splunk/bin/splunk enable boot-start

sudo /opt/splunk/bin/splunk start — accept-license

sudo /opt/splunk/bin/splunk edit user admin -password <password> -role admin -auth admin:changeme

Access the Splunk web interface by navigating to http://<splunk-server-ip>:8000 in your web browser.

Installation of Splunk forwarder and configure honeypot logs on Parrot Security operating system.

Install and configure the Splunk forwarder on the Cowrie honeypot system.
![image](https://github.com/user-attachments/assets/cab2fc8b-57b1-422d-a26c-e768ae2aa807)


/opt/splunkforwarder/bin/splunk add forward-server <splunk-indexer-ip>:<splunk-receiver-port>

2) Configure the Splunk forwarder to monitor the log files and forward them to the Splunk indexing or search head.

nano /opt/splunkforwarder/etc/system/local/inputs.conf

3) Add the following stanza to the inputs.conf file to monitor the Cowrie JSON logs:

[monitor:///home/username/cowrie/var/log/cowrie/cowrie.json]

disabled = false

index = cowrie

source type = cowrie

4) Restart the Splunk forwarder to apply the configuration changes:

./splunk restart from the bin directory of splunk forwarder

NMAP and HYDRA tool installed on the attacker machine (Kali operating system)

1) Open the terminal on your Linux system.

2) Update the package list by running the following command:

sudo apt-get update

3) Install Nmap by running the following command:

sudo apt-get install nmap

4) Install Hydra by running the following command:

sudo apt-get install hydra

Snort Configuration with Honeypot logs and forwarding to Splunk server.

1) installation of snort

sudo apt-get install snort

2) Configuring Splunk forwarder to collect logs from snort to display on Splunk server

nano /opt/splunkf/etc/apps/search/local/inputs.conf

[monitor:///var/log/snort/]

Disabled=false

index=snort_ids

source = snort

3) Restart Splunk after adding snort monitor changes in the configuration file

/opt/splunkforwarder/bin splunk restart

4) Rule to monitor Cowrie traffic

nano /etc/snort/rules/cowrie.rules

alert tcp any any -> <honeypotipaddress> 22 (msg:”Cowrie SSH Honeypot Connection”; sid:1000001; rev:1;)

5) Configure Snort to monitor the rule file:

nano /etc/snort/snort.conf

include $RULE_PATH/cowrie.rules

6) Checking snort logs

snort -A console -K ascii -L /var/log/snort -c /etc/snort/snort.conf

Let’s perform the attack collect the logs from Honeypot and forward to the Splunk server to analyze and visualize the logs.

Nmap and Hydra brute force attack

Commands:

Nmap -sS victim-machine ip

● It will check open ports

Sudo -L uname.txt -P password.txt victim-machine ssh

● It will conduct a brute force attack and try to log in with a different combination of username and password provided with the given filename in the command

![image](https://github.com/user-attachments/assets/fd7f7a1f-b91c-47d4-beea-d098b0c48465)


Attacker in Honeypot System

● In the below image attacker successfully entered into honeypot system via SSH command and performed various commands
![image](https://github.com/user-attachments/assets/4d40db71-3743-4ee8-aa23-e2665bb0426a)


Playing the attacker session

● Once the attacker is out of the system. Honeypot will create logs and in the below, we played a log file using the ./playlog command which will play the attacker’s session while in the honeypot system.
![image](https://github.com/user-attachments/assets/f20bbd85-f14f-4428-8a5a-25c05a616db9)


Splunk logs of Honeypot

As shown in the below image, logs from the honeypot are forwarded to the Splunk server for analysis.


Dashboard based on Kippo honeypot logs on Splunk

● Different query-based reports are created and merged in the dashboard to visualize honeypot logs data in chart format.
![image](https://github.com/user-attachments/assets/d1fd35c0-93f2-4d2a-b64b-e13fd6540867)
![image](https://github.com/user-attachments/assets/755db285-d403-4d2a-9551-0ef681211e78)
![image](https://github.com/user-attachments/assets/c684df90-03b8-4f08-baff-13d81eae27b6)
![image](https://github.com/user-attachments/assets/44d8394a-b2e3-48d1-a4c5-48e91689d884)


Snort Alerts based on custom rules about kippo honeypot login session
![image](https://github.com/user-attachments/assets/6603c1bc-a27d-4fdd-8e7b-232e25fed252)


Conclusion

KippoSSHWatch represents a powerful fusion of the Kippo SSH honeypot and Splunk’s analytics capabilities, providing organizations with a comprehensive solution for monitoring and alerting SSH attacks. By leveraging this solution, you can gain invaluable insights into attacker behavior, proactively defend against brute force attempts, and respond swiftly to compromised systems, ensuring the security and integrity of your critical infrastructure.
