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
* Wireshark Version 4.2.2-1~ubuntu22.04.0~ppa2
  * Details
    * Priority: Optional
    * Section: Net
    * Maintainer: Balint Reczey
    * Installed-Size: 10.2 MB
    * Download-Size: 4,673 KB
    * APT-Manual_Installed: Yes
* Docker Version 25.0.3, Build 4debf41
  * Installation
    * Instructions: https://docs.docker.com/desktop/install/ubuntu/
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
    * Instructions: https://www.zenarmor.com/docs/linux-tutorials/how-to-install-and-configure-snort-on-ubuntu-linux#how-to-install-snort-3-on-ubuntu-2204
  * Details
    * DAQ Version: 3.0.14
    * LuaJIT Version: 2.1.0-beta3
    * OpenSSL Version: 3.0.2 15 Mar 2022
    * Libpcap Version: 1.10.1
    * PCRE Version: 8.39 2016-06-14
    * ZLIB Version: 1.2.11
    * LZMA Version: 5.2.5

# Snort

* An open-source network intrusion detection and prevention system that monitors network traffic in real time, analyzing packets against rule files and generating alerts.
* Detection can be done through community rulesets and custom rules.
* Rules define the criteria for detecting specific network traffic patterns associated with known threats or suspicious activity.
* Snort also provides detailed logging and output capabilities for effective threat investigation.

## Snort Rules

* [Action] [Protocol] [Source IP] [Source Port] -> [Destination IP] [Destination Port] ([Options])
  * Action: This specifies what action Snort should take when the rule matches. Common actions include "alert," which generates an alert, and "drop," which drops the packet.
  * Protocol: This specifies the network protocol being used, such as TCP, UDP, or ICMP.
  * Source IP: This specifies the source IP address from which the traffic originates.
  * Source Port: This specifies the source port number used by the sender.
  * Destination IP: This specifies the destination IP address to which the traffic is being sent.
  * Destination Port: This specifies the destination port number on the destination IP.
  * Options: This optional field can include additional parameters to refine the rule, such as payload content to match against, packet length, or specific flags.

## Snort Process

* Packet Decoder
  * Collects packets from various network interfaces and forwards them to the preprocessor.
* Preprocessor
  * Modifies and organizes packets before they're analyzed by the detection engine.
* Detection Engine
  * Identify intrusion activities within packets by utilizing Snort rules.
* Output Stage
  * Generates alerts and logs packets based on the detection engine's findings, with options to customize logging details.
 
## Snort Configuration

* Section 5: Configure Detection
  * Include custom rules file in Snort configuration.
    * ` ips = {variables = default_variables, include = 'local.rules'} `
* Section 7: Configure Outputs
  * Uncomment the alert_fast line to enable the output log and specify file options.
    * ` alert_fast = {file = true} `

# 




