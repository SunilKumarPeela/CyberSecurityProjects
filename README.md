# Portfolio
<h> Personal Statement </h>
> I am deeply committed to safeguarding organizational and customer data from malicious actors. As a research-oriented individual with a passion for solving puzzles, I aspire to integrate my quantum expertise with my cybersecurity skills to streamline processes and minimize impact.
<h1>Internal Audit Report</h1>

>I have completed the internal audit report for the toy company for compliance following NIST CF.

<h1>List privilege Access</h1>

>I have provided access to the files to users, groups, and others using Linux bash scripting, and the file is attached above

<h1>SQL tool Filters</h1>

>I have used the SQL tool to filter databases for the investigation. I have attached the document the steps I have done above

<h1>Vulnarability Accessment</h1>

> The vulnerability assessment is done and documented which is attached above.

<h1>Incident Response</h1>

> The Ransome incident in the healthcare sector shook the company. I have provided the details regarding this incident in the incident response form.

<h1>Update file through Python Algorithm</h1>

> I have used the Python programming language to update the file after reading it which is attached above.

<h1>Google Cloud Capstone Project</h1>

> Cymbal Retail, a retail giant with 170 physical stores and an online platform across 28 countries, generating $15 billion in revenue, recently experienced a data breach. As a junior member of the security team, 
  I have been tasked with identifying the vulnerabilities related to the breach, isolating and containing it to prevent further unauthorized access, recovering the compromised systems, verifying compliance with 
  relevant frameworks, and addressing any outstanding compliance-related issues.

  Task 1: Finding vulnerabilities in the Security Command Center 
  
  > - Navigated to the *Security Command Center* and accessed the *Active Vulnerabilities* section.
> - Used the *"Findings By Resource Type"* filter to sort active vulnerabilities by resource.
> - Focused on three cloud resource types with vulnerabilities that needed remediation:
>   - *Cloud storage bucket*
>   - *Compute Instance virtual machine (VM)*
>   - *Firewall*
> - Reviewed the details of the *PCI DSS 3.2.1* report in the *Compliance* section.
> - Identified the rules that were non-compliant with PCI DSS, which corresponded to the vulnerabilities in the bucket, VM, and firewall.
> - Focused on remediating these vulnerabilities in the subsequent tasks and challenges.
> 
>   ![Vulnarability Scanning](https://raw.githubusercontent.com/sunilryo/Images/main/vulnarability%20scan.png)
>
>   ![Compliance Check for PCI](https://raw.githubusercontent.com/sunilryo/Images/main/Compliance%20Visibility.png)


  Task 2: Address the vulnerabilities in the Compute Engine

> - Identified the following *vulnerabilities*:
>   - *Public IP address* (VMs should not have public IP addresses assigned)
>   - *Secure boot disabled* on the Compute Engine
>   - *Default service account* in use
>   - *Full API access* (Instances should not use the default service account with unrestricted access to all Cloud APIs)
>   - *Malware detected*: bad domain
>
> - Removed the existing VM instance named *"cc-app-01."*
> - Created a new VM instance named *"cc-app-02."*
> - Disabled secure boot on the new VM instance.
>
> ![Removed VM instance](https://github.com/sunilryo/Images/blob/main/Removed%20VM%20Instance.png)
>
> ![Created VM instance](https://raw.githubusercontent.com/sunilryo/Images/main/Created%20VM%20instance.png)

  Task 3: Resolve Cloud Storage Bucket Permissions

> **Vulnerabilities addressed:**
> 
> - Public bucket ACL (Cloud Storage buckets should not be anonymously or publicly accessible)
> - Bucket policy only disabled
> 
> **The following vulnerabilities related to the Cloud Storage bucket were remediated by:**
> 
> - Removing the public access control list
> - Disabling public bucket access
> - Enabling uniform bucket-level access control
>
>    ![Remove public access](https://github.com/sunilryo/Images/blob/main/Remove%20public%20access.png)
>
>   ![Remove allUser access](https://github.com/sunilryo/Images/blob/main/Remove%20access%20to%20all%20users.png)


  Task 4: Limit Firewall Port Access
  
> I have created a new firewall rule named `limit-ports` that restricted SSH (TCP port 22) access by:
> 
> - Creating a new firewall rule named `limit-ports`.
> - Restricting *SSH (TCP port 22)* access.
> - Allowing access only from authorized IP addresses within the source network `35.235.240.0/20`.
> - Applying the rule to Compute Engine VM instances with the target tag `cc`.
>
>    ![Firewall rule](https://github.com/sunilryo/Images/blob/main/Firewall%20rule.png)
>   

 Task 5: Fix the Firewall configuration

 > - Delete the `default-allow-icmp`, `default-allow-rdp`, and `default-allow-ssh` firewall rules.
> - Enable logging for the newly created `limit-ports` firewall rule and the existing `default-allow-internal` firewall rule.
> - This will address the following firewall vulnerabilities:
>   - Open SSH port (Firewall rules should not permit connections from all IP addresses on TCP or SCTP port 22)
>   - Open RDP port (Firewall rules should not permit connections from all IP addresses on TCP or UDP port 3389)
>   - Firewall rule logging disabled (Firewall rule logging should be enabled to audit network access)
>  
>    ![Fix ports](https://github.com/sunilryo/Images/blob/main/fix%20ports.png)
>     

 Task 6: Verify Compliance

 > - I navigated to the Security Command Center.
> - I reviewed the details of the PCI DSS 3.2.1 compliance report.
> - I noticed that the percentage of controls passed had increased.
> - This increase indicated that the vulnerabilities had been effectively remediated.
>
>  ![Final Report](https://github.com/sunilryo/Images/blob/main/compliance%20final.png)

After completing the remediations, the final phase of the incident response, which is Post-Incident Activity, was carried out by creating a final report.

[View the PDF](https://github.com/sunilryo/Portfolio/blob/main/Final%20Incident%20Report-%20Capstone.pdf)

<h1> Security Blue Team Capstone Project</h1>
<h2> Threat Hunting</h2>
<h2> Scenario</h2>

*You are a Junior Threat Hunter working for an organisation. Your Threat Intelligence team has obtained two malware samples, but they’re too busy dealing with a data breach dump that includes employee credentials, so you’ll need to hunt for any presence of the malware in any systems. As you’re new to the role, the Senior Threat Hunter is using advanced tools to assess all systems company-wide, but he has given you permission to run a live hunt on one system. A disk image was taken, as the system is in a remote office. You have been told to gather your own IOCs from two malware samples, and conduct a hunt on the files using Mandiant IOC Editor and Mandiant Redline. You are to report on the findings generated by the IOC Reports.*
 
<h3> Step-1  Create IOC1 for malware 1 </h3>

>Use **Virustotal** to find md5, sha1, sha256, size details

![Virus Total Ioc1](https://github.com/sunilryo/Images/blob/main/virustotal%201.png)

> Right-click on the malware file and click on properties to know the file name

Collected IOC for sample 1

```plaintext
MD5: b315c590c3ad691604597ea41f8dd84e
SHA1: 6d15e7f0bb54df5b27a093f20186773ab0af7707
SHA256: 37ea273266aa2d28430194fca27849170d609d338abc9c6c43c4e6be1bcf51f9
Filename: 03fe93e6-a71c-11e6–8434–80e65024849a.file.exe
File size: 811260 bytes
```
<h3> Step-2  Create IOC2 for malware 2 </h3>

>Use **Virustotal** to find md5, sha1, sha256, size details

![Virus Total Ioc1](https://github.com/sunilryo/Images/blob/main/Virustotal2.png)

> Right-click on the malware file and click on properties to know the file name

Collected IOC for sample 1

```plaintext
MD5 - 0c4374d72e166f15acdfe44e9398d026
SHA1 - f8ac123e604137654759f2fbc4c5957d5881d3d1
SHA-256 - 240387329dee4f03f98a89a2feff9bf30dcba61fcf614cdac24129da54442762 
File name- myfile.exe
File size - 402330 bytes
```

<h3> Step-3 Create 2 IOC files in **Mandiant IOC** using above data</h3>

>*IOC1*

![Mandiant IOC](https://github.com/sunilryo/Images/blob/main/IOC1.png)

>*IOC2*

![Mandiant IOC](https://github.com/sunilryo/Images/blob/main/ioc2.png)

>Indicators of Compromise (IOCs) generated from known malware samples received from an external source.

<h3> Step-4 Create IOC collector using Mandiant RedLine </h3>

>Open Mandiant Redline and click on "**Create an IOC Search Collector**"

![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/redline%201.png)

>Browse the path where IOCs got stored

![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/redline%202.png)

> click on "Edit your script" for customization

![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/WhatsApp%20Image%202024-08-01%20at%2016.02.57_d8f6f573.jpg)

>Specify the file path to check for threats under the Disk tab.

![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/Redline.jpg)

> Select the blocks that specifies parameters to check

![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/redline%204.png)

>Create an empty folder named Testing, and add it by clicking on the Browse tab.

![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/redline%205.png)

>Run Command Prompt as an administrator and navigate to the directory named "temporary".

![CMD](https://github.com/sunilryo/Images/blob/main/redline%207.png)

>Run the batch file ./RunRedlineAudit.bat that creates new folders named Sessions, AnalysisSession1

![CMD](https://github.com/sunilryo/Images/blob/main/redline%208.png)

>Navigate to Sessions > AnalysisSession1 we will find the .mans file, which is analyzed through Redline

![CMD](https://github.com/sunilryo/Images/blob/main/Redline%209.png)

>Open Mandian Redline, click on "Open Previous Analysis>"

![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/redline%2010.png)

>Select the file with the .mans extension, and it will be loaded into Redline. Then, click on the IOC Reports tab located at the bottom.

>![Mandiant Redline](https://github.com/sunilryo/Images/blob/main/redline%2011.png)

>We have identified the same malware signatures within our organization by using IOCs from other sources.

--------------------------------------------------------------------------------------------------------------------------------------------------------

<h1> Elastic SIEM LAB</h1>
<h2> Scenario</h2>

*Developing a SIEM tool that detects alerts generated by Kali Linux when an adversary conducts an nmap scan on the network.*

**Step-1:** *Open Elastic Account* 

>I have opened Elastic website and logged into my account

![Elastic](https://github.com/sunilryo/Images/blob/main/Elastic.png)

**Step-2:** *Kali Linux to generate alerts*

>I opened Kali-Linux in VM virtual box

![Kali-Linux](https://github.com/sunilryo/Images/blob/main/KaliLinux.png)

**Step-3:** *Setting up Agent to collect logs*

An agent is a software program installed on a device, such as a server or endpoint, to gather and transmit data to a centralized system for analysis and monitoring. In the context of Elastic SIEM, an agent collects and forwards security-related events from your endpoints to your Elastic SIEM instance.

  >click on **integration** on top right

  >Select "Elastic Defend"

  ![Elastic Defend](https://github.com/sunilryo/Images/blob/main/s1.png)

  >click on "Add Elastic Defend"

  ![Add electic Defend](https://github.com/sunilryo/Images/blob/main/s2.png)

  >Now click on "Install Elastic Agent"

  ![Install](https://github.com/sunilryo/Images/blob/main/s3.png)
  
  >Scroll down to find the code below the Linux tab. We use kali Linux to generate events, select Linux, and copy the code available.

  ![Agent code](https://github.com/sunilryo/Images/blob/main/s4.png)
 
  >Paste the code into a bash script on Kali Linux and run the command to connect the agent to Elastic.

   ![Agent code](https://github.com/sunilryo/Images/blob/main/s5.png)

   ![Agent connected](https://github.com/sunilryo/Images/blob/main/s6.png)

  >It will automatically start collecting and forwarding logs to your Elastic SIEM instance, although it might take a few minutes for the logs to appear in the SIEM.

  >Now in elastic website, it is displayed as *agent enrolled*. Click on "Add the Integration"

   ![Integration added](https://github.com/sunilryo/Images/blob/main/s7.png)
   

   >You can confirm that the agent has been installed correctly by running the following command:
>
   ```plaintext
   sudo systemctl status elastic-agent.service.
   ```
   ![status check](https://github.com/sunilryo/Images/blob/main/s8.png)

 **Step-4:** *Generating Security Events on Kali VM*
 
 To verify that the agent was working correctly, I generated some security-related events on my Kali VM using a tool like Nmap. Nmap (Network Mapper) is a free and open-source utility used for network 
 exploration, management, and security auditing. It was designed to discover hosts and services on a computer network, thus creating a "map" of the network. Nmap was used to scan hosts for open ports, determine 
 the operating system and software running on the target system, and gather other information about the network.

   >insert following commands in VM

   ```plaintext
   nmap -p- localhost
   nmap -Ss localhost
   ```

   ![nmap](https://github.com/sunilryo/Images/blob/main/Nmap01.png)

**Step-5** *Searching for Security Events in Elastic SIEM*

Now that I have forwarded data from the Kali VM to the SIEM, I can start querying and analyzing the logs in the SIEM.

     >click on *logs* tab under Observability

   ![log](https://github.com/sunilryo/Images/blob/main/log1.png)

     >In the search bar enter the below log query

  ```plaintext
     process.args: "nmaps"
  ```

  ![log](https://github.com/sunilryo/Images/blob/main/log2.png)

    >click on view on any shown results to view the nmap encounter

  ![log](https://github.com/sunilryo/Images/blob/main/view.png)

  By generating and analyzing various types of security events in Elastic SIEM, such as the ones mentioned above or by creating authentication failures (e.g., entering the wrong password for a user or attempting 
  SSH logins with incorrect credentials), you can gain a deeper understanding of how security incidents are detected, investigated, and managed in real-world scenarios.

**Step-6** *Create Dashboards to visualize Events*

we can also utilize the visualizations and dashboards within the SIEM app to analyze logs and identify patterns or anomalies in the data. For instance, you could create a straightforward dashboard that 
displays a count of security events over time.

     >Click on *dashboard* that is under analytics

  ![dashboard](https://github.com/sunilryo/Images/blob/main/dashboard.png)

     >click on "Create Dashboard"

  ![dashboard2](https://github.com/sunilryo/Images/blob/main/dashboard2.png)

     >select on "create Visualization"

  ![Visualization](https://github.com/sunilryo/Images/blob/main/visualization.png)

     >Select "Area" as the Visualization type, "Count" as the Vertical Field, and "Timestamp" for horizontal field

     > We see the graph below that shows the Nmap counts

  ![metrics](https://github.com/sunilryo/Images/blob/main/metrics.png)

**Step-7** *Create an alert*

In a SIEM, alerts were a crucial feature for detecting security incidents and responding to them in a timely manner. Alerts were created based on predefined rules or custom queries and could be configured to trigger specific actions when certain conditions were met. In this task, I walked through the steps of creating an alert in the Elastic SIEM instance to detect Nmap scans.

      >Click on "Alerts" 
  
  ![Alerts](https://github.com/sunilryo/Images/blob/main/alerts.png)
  
      >Select "Manage rules"

![Alerts](https://github.com/sunilryo/Images/blob/main/alerts%202.png)

      >click on "Create rule"
      
![alerts](https://github.com/sunilryo/Images/blob/main/alert%203.png)

      >select "custom threshold"

![Alert](https://github.com/sunilryo/Images/blob/main/alert%204.png)

      >In the search enter the following command. And select email to get the notifications

  ```plaintext
      event.action: "nmap_scan"
```

![Alert](https://github.com/sunilryo/Images/blob/main/alert%205.png)

Whenever the SIEM detects an Nmap instance, it generates an alert and sends a notification via email.

<h1> Microsoft Azure Project</h1>

<h2> Create User and Groups</h2>


  

  
   
























