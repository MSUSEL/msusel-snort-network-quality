# Problem Statement

The Department of Homeland Security is committed to ensuring the quality and security of critical software systems. In collaboration with the DHS, Montana State University developed the software quality analysis tool, PIQUE. One PIQUE model is specifically focused on cloud microservice ecosystems, which involve containerizing services in cloud infrastructures using Docker to create efficient and scalable web applications. An integral aspect of cloud microservice ecosystems is networking, falling under infrastructure services.
In our ever-evolving digital landscape, malicious actors continually discover new methods to disrupt networks. Tools such as Snort and Wireshark empower cybersecurity professionals to counteract and measure attempts to disrupt network quality. These tools provide the means to log and detect both benign and malicious network traffic, allowing professionals to react accordingly. By using Snort and Wireshark in tandem, we can construct testing methods to measure and quantify network quality.

# Project Goals

* Create a stable testing environment for generating and testing Snort rules.
* Gain proficiency in writing Snort rules.
* Understand network traffic patterns between Docker containers.

# Steps

1. Install a free Linux distribution. We used Ubuntu 22.04.3 LTS 
2. Install the most recent versions of Snort, Docker, and Wireshark.
3. Configure Snort, Docker, and Wireshark.
4. Validate consistency of tools:
   * Test the consistency of Snort.
   * Test communication between Docker containers.
5. Introduce malware:
   * Containerize malware with Docker.
   * Analyze communication patterns and specific packets triggering Snort alerts in Wireshark.
7. Develop a scheme for measuring the effect of Snort alerts on network quality (severity & frequency).

# Environment 

* Operating System: Ubuntu Linux Version 22.04.3 LTS
* Wireshark Version 4.2.2-1 ubuntu22.04.0 ppa2
  * Details
    * Priority: Optional
    * Section: Net
    * Maintainer: Balint Reczey
    * Installed-Size: 10.2 MB
    * Download-Size: 4,673 KB
    * APT-Manual_Installed: Yes
* Docker Version 25.0.3, Build 4debf41
  * Installation
    * [Instructions](https://docs.docker.com/desktop/install/ubuntu/)
      * Installed Docker’s apt Repository
      * Download DEB Package
      * Install Package w/ apt
  * Details
    * Server: Docker Desktop 4.27.2
      * Version: 25.0.3
      * API Version: 1.44
      * Go Version: go1.21.6
    * Client: Docker Engine - Community
      * Cloud Integration: v1.0.35+desktop.10
      * Version: 25.0.3
      * API Version: 1.44
      * Go Version: go1.21.6
      * OS/Arch: linux/amd64
      * Context: desktop-linux
* Snort Version 3.1.78.0
  * Installation
    * [Instructions](https://www.zenarmor.com/docs/linux-tutorials/how-to-install-and-configure-snort-on-ubuntu-linux#how-to-install-snort-3-on-ubuntu-2204)
  * Details
    * DAQ Version: 3.0.14
    * LuaJIT Version: 2.1.0-beta3
    * OpenSSL Version: 3.0.2 15 Mar 2022
    * Libpcap Version: 1.10.1
    * PCRE Version: 8.39 2016-06-14
    * ZLIB Version: 1.2.11
    * LZMA Version: 5.2.5

# Snort

### Introduction

* An open-source network intrusion detection and prevention system that monitors network traffic in real time, analyzing packets against rule files and generating alerts.
* Detection can be done through community rulesets and custom rules.
* Rules define the criteria for detecting specific network traffic patterns associated with known threats or suspicious activity.
* Snort also provides detailed logging and output capabilities for effective threat investigation.

### Snort Rules

* [Action] [Protocol] [Source IP] [Source Port] -> [Destination IP] [Destination Port] ([Options])
  * Action: This specifies what action Snort should take when the rule matches. Common actions include "alert," which generates an alert, and "drop," which drops the packet.
  * Protocol: This specifies the network protocol being used, such as TCP, UDP, or ICMP.
  * Source IP: This specifies the source IP address from which the traffic originates.
  * Source Port: This specifies the source port number used by the sender.
  * Destination IP: This specifies the destination IP address to which the traffic is being sent.
  * Destination Port: This specifies the destination port number on the destination IP.
  * Options: This optional field can include additional parameters to refine the rule, such as payload content to match against, packet length, or specific flags.

### Snort Process

* Packet Decoder
  * Collects packets from various network interfaces and forwards them to the preprocessor.
* Preprocessor
  * Modifies and organizes packets before they're analyzed by the detection engine.
* Detection Engine
  * Identify intrusion activities within packets by utilizing Snort rules.
* Output Stage
  * Generates alerts and logs packets based on the detection engine's findings, with options to customize logging details.
 
### Snort Configuration

* Section 5: Configure Detection
  * Include custom rules file in Snort configuration.
    * ` ips = {variables = default_variables, include = 'local.rules'} `
* Section 7: Configure Outputs
  * Uncomment the alert_fast line to enable the output log and specify file options.
    * ` alert_fast = {file = true} `

# Test Case One

### Description
  * Test Case One ensures the consistent and proper functioning of Snort. Test Case One will verify if Snort can detect a TCP connection through Netcat by sending a benign file with a specific port number and matching the content of the file data.

### Steps
  1. Find a Port Number
      * `netstat -an | grep 4444`
      * `netstat -an | grep LISTEN | grep 4444`
  2. Put Networks in Promiscuous Mode
      * `sudo ip link set dev enp0s31f6 promisc on`
      * `sudo ip link set dev lo promisc on`
  3. Create Snort Rules
      * Create a rule file and add the rules in local.rules
  4. Start Snort
      * Terminal window 1:
        * `sudo snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/snort/local.rules -i lo -A alert_fast -k none`
          * “-A alert_fast” tells Snort to direct the alerts to alert_fast.txt
          * “-c /usr/local/etc/snort/snort.lua” specifies the Snort configuration
          * “-i lo” specifies the interface that Snort should listen on for traffic
          * “-R /usr/local/etc/snort/local.rules” specifies the rule file
          * “-k none” disables checksum validation
  5. Send Benign File Using Netcat
      * Terminal window 2:
        * `nc -l 4444`
      * Terminal window 3:
        * `nc 127.0.0.1 4444 < file_to_send.txt`
          * “nc 127.0.0.1 4444” establishes a connection to the local machine (127.0.0.1) on port 4444
          * “< file_to_send.txt” uses input redirection (<) to read data from the file named file_to_send.txt and sends through the established connection
  6. Stop Snort and check the alert_fast.txt output log
      
### Rule Descriptions
  * Benign File Detected Using Content Matching (v1):
    * Description: This rule is triggered when Snort detects a TCP packet with the specified content.
    * Action: It generates an alert message stating that a benign file has been detected.
    * Content Matching: The rule looks for the string "This is a benign file. There is nothing interesting here." within the TCP packet.
    * SID: 1
  * Activity on Port 4444 (v1):
     * Description: This rule detects any activity on TCP port 4444, regardless of the source and destination.
     * Action: It generates an alert message indicating activity on port 4444.
     * SID: 3
  * Activity on Port 4444 (v2):
     * Description: This rule specifically detects TCP traffic going from any source to port 4444 on the local machine (127.0.0.1).
     * Action: It generates an alert message indicating activity on port 4444 with this specific source-destination pattern.
     * SID: 4
  * Activity on Port 4444 (v3):
     * Description: This rule detects TCP traffic going from port 4444 on the local machine (127.0.0.1) to any destination.
     * Action: It generates an alert message indicating activity on port 4444 with this specific source-destination pattern.
     * SID: 5
  * Activity on Port 4444 (v4):
     * Description: This rule detects TCP traffic going from any source to port 4444 on any destination.
     * Action: It generates an alert message indicating activity on port 4444 with this specific source-destination pattern.
     * SID: 6

### Data Analysis and Results
* We repeated the Test Case One process several times to determine if Snort alerts were consistently triggered.
* Variables we examined include runtime, alerts, logged alerts, total alerts, port activity alerts, and content matching alerts.
  * Alerts, logged alerts, total alerts, port activity alerts, and content-matching alerts remained constant across all runs of the experiment.
  * The consistent port activity and content-matching alerts indicate a reliable testing environment.
* While Snort was alerting consistently, the runtime somewhat varied across executions in Test Case One.
  * The mean runtime of Snort was 93.868 seconds in Test Case One.
  * Found that running Snort on Wireshark captures created a consistent and fast runtime.
* Found that the Snort rule in local.rules with SID: 2 would only trigger while running Snort on Wireshark captures.

# Test Case Two

### Description
* Test Case Two was created to test Snort’s SHA-256 hash-matching and signature-based detection capabilities. This test case is also modeled after a previous experiment with Snort which can be found [here](https://github.com/megansteinmasel/snort-malware-detection).

### Steps
1. Create a Python Web Server
    * [Instructions](https://www.geeksforgeeks.org/network-programming-python-http-server/)
    * Create an index.html file that contains a download button for benign file 
2. Put Networks in Promiscuous Mode
    * `sudo ip link set dev enp0s31f6 promisc on`
    * `sudo ip link set dev lo promisc on`
3. Start Packet Capture on Wireshark
4. Spin Up Web Server
    * Go to localhost: 8080
    * Press the download button to download the benign file
5. Stop Packet Capture
6. Run Snort on Packet Capture

### Results
* The port activity and content-matching rules from Test Case One still triggered when running Test Case Two.
* Unfortunately, the SHA-256 hash matching rules did not trigger.
* Decided to reach out to the Snort community via Discord for help.

### Reaching Out to Development Team
* Reached out via the Snort Discord channel for information regarding hash-matching in the context of the project.
* Here’s what we learned:
  * Using hash options (MD5, SHA-256, SHA-512) for real-time payload detection is inefficient.
  * Without adding extra clarification for content-matching beforehand, every single packet’s hash value will have to be calculated.
    * Note - This could be the reason for varying runtime in Test Case One since some signature-based detection rules were in our rule file at the time.
  * Often won’t work for larger files as files must be reassembled from memory. 
















