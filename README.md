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

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h1> Microsoft Azure Project</h1>

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h2> *Create User and Groups*</h2>

Open 
```plaintext
Entra.microsoft.com
```
Click on 

```plaintext 
All Users
```
![EntraOpenPage](https://github.com/sunilryo/Images/blob/main/1Entra.png)

click on

```plaintext
Create New User
```
![Create New User](https://github.com/sunilryo/Images/blob/main/1NewUser.png)

Create new user principal named 'gpuser1' and select

```plaintext
NextProperties
```
![continuation](https://github.com/sunilryo/Images/blob/main/1GPUser1.png)

Click on

```plaintext
Add Role
```
![AddRole](https://github.com/sunilryo/Images/blob/main/1AddRole.png)

Select

```plaintext
Application Administrator
```

![AdministratorRole](https://github.com/sunilryo/Images/blob/main/1AdministratorRole.png)

Click on

```plaintext
Next:Review + Create
```
![Create User](https://github.com/sunilryo/Images/blob/main/1Create.png)

click on

```plaintext
Create
```
![Create User](https://github.com/sunilryo/Images/blob/main/1Created.png)

Displays All users

![All users](https://github.com/sunilryo/Images/blob/main/1DisplayUsers.png)

Similarly, create another new user principal named 'gpuser2' and assign role 'Application developer'

![User 2](https://github.com/sunilryo/Images/blob/main/1User2AdminRole.png)

List of all users displayed

![listOfUsers](https://github.com/sunilryo/Images/blob/main/UserList.png)

Now we test the newly created user accounts by logging in

![testing](https://github.com/sunilryo/Images/blob/main/1User1Check.png)

![User1 account](https://github.com/sunilryo/Images/blob/main/1User1AccountOpened.png)

Now similarly user2 opened

![User2 account](https://github.com/sunilryo/Images/blob/main/1User2AccountOpened.png)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h2> *Assign Users to Groups*</h2>

There are two tyes of Groups that we can create which are "Security" Group and "Microsoft 365" Group

The steps for creating a group as follows

Open 

```plaintext
https://entra.microsoft.com/
```
Click on

```plaintext
Allgroups
```
![AllGroups](https://github.com/sunilryo/Images/blob/main/2AllGroups.png)

Select

```plaintext
New group
```
![NewGroup](https://github.com/sunilryo/Images/blob/main/2newGroup.png)

Now we create a Security Group type with the group name "GPSecurityGroup"
click on 

```plaintext
No members selected
```
![Selecting members](https://github.com/sunilryo/Images/blob/main/2NomembersSelected.png)

So that we can add the new members to this group.
Now select 'GPUser1' and 'GPUser2' 

![MemebersSelected](https://github.com/sunilryo/Images/blob/main/2SelectUsers.png)

Once the users are selected, click on Create to create GPSecurityGroup 

![GPSecurityGroup](https://github.com/sunilryo/Images/blob/main/2GroupCreated.png)

Once it is created, the group is displayed as

![GroupDisplay](https://github.com/sunilryo/Images/blob/main/2DisplayGroup.png)

Now, Create another new group of microsoft365 type with the Group name'GPM365Group' buy selecting users we wish to add

![GroupName2](https://github.com/sunilryo/Images/blob/main/2Group2Created.png)

The final group list we created displayed as 

![FinalGroups](https://github.com/sunilryo/Images/blob/main/2Grouplist.png)

<h2> *Configure Self-Service Password Reset*</h2>

Now, We provide self-service password reset access to users without the need of admin 

open 

```plaintext
https://entra.microsoft.comm
```
click on 

```plaintext
New group
```

![NewGroup](https://github.com/sunilryo/Images/blob/main/3AllGroups.png)

Add the Group name as 'GPSSPR' and select the users 'GP User1' and 'GP User2' to add by clicking on 'No Members Selected' and click on select

![GPSSPR](https://github.com/sunilryo/Images/blob/main/3CreatingGroup.png)

The group created is displayed as follows 

![Group Created](https://github.com/sunilryo/Images/blob/main/3Groupcreated.png)

Click on 

```plaintext
User settings
```

![User settings](https://github.com/sunilryo/Images/blob/main/3IDENTITY.png)

Now select

```plaintext
Password reset
```

![Password Reset](https://github.com/sunilryo/Images/blob/main/3ppasswordreset.png)

Select 'Selected' for self service password reset enabled

Click on 

```plaintext
No groups selected
```

![Nogroupselected](https://github.com/sunilryo/Images/blob/main/3NoGroupSelected.png)

Select the group 'GPSSPR' to assign the password reset functionality

![GroupSelection](https://github.com/sunilryo/Images/blob/main/3SelectGroup.png)

Now self-service password reset is enabled for the users in the group GPSSPR

We can check if it is 1 factor or 2 factor by clicking 

```plaintext
Authentication methods
```
![Authentication](https://github.com/sunilryo/Images/blob/main/3AuthentiicationMethod.png)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h2> *Configure Conditional Access*</h2>

Click on 

```plaintext
Conditional access
```

![Conditional Access](https://github.com/sunilryo/Images/blob/main/4ConditionalAccess.png)

Click on

```plaintext
Create new policy
```

![New Policy](https://github.com/sunilryo/Images/blob/main/4CreatingNewPolicy.png)

We have to disable the security defaults to provide more protection. To disable click on 

```plaintext
disable security defaults
```

![Security Defaults](https://github.com/sunilryo/Images/blob/main/4DisabblesecurityDefaults.png)

opt on 'Disabled' and select 'My organization is planning to use conditional access' and then save

![Disabled default](https://github.com/sunilryo/Images/blob/main/4Save.png)

now select disabled

![Disabled](https://github.com/sunilryo/Images/blob/main/4Disabled.png)

Enter the name as "GP CA Policy" 

![Users](https://github.com/sunilryo/Images/blob/main/4SelectuserandGroup.png)

Now select

```plaintext
0 users and groups selected
```

![Select users](https://github.com/sunilryo/Images/blob/main/4Users.png)

click on "GP User2"

![User2](https://github.com/sunilryo/Images/blob/main/4GPUser2.png)

click on 

```plaintext
target resource
```

and then select the app you want to take action on, I have chosen *Bing* to have conditional access on

![AppSelection](https://github.com/sunilryo/Images/blob/main/4Bong.png)

As you can see here, we have additional conditions like location and device platform to opt. For now I am keeping it as it is 

![Conditions](https://github.com/sunilryo/Images/blob/main/4Conditions.png)

Now click on 

```plaintext
0 controls selected
```

that is located under Grand tab and select 

```plaintext
Block access
```

![Block access](https://github.com/sunilryo/Images/blob/main/4Blockaccess.png)

Select "Enable policy" ON abd click on 

```plaintext
Create
```

![Enable policy](https://github.com/sunilryo/Images/blob/main/4EnablePolicy.png)

You will see the tab that shows how many enable policies exist as below 

![ViewList](https://github.com/sunilryo/Images/blob/main/4policy.png)

If you open the Azure account of user 2, try to access Bing services. It will show "You have no permission to access"

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h2> *Configure Priviliged Identity Management*</h2>

First p2 licenses to be assigned to users

Click on Billing > Licences and then select

```plaintext
All products
```

![License](https://github.com/sunilryo/Images/blob/main/5License.png)

click on

```plaintext
Microsoft Entra ID P2
```

![EntraID](https://github.com/sunilryo/Images/blob/main/5EntraIDLicense.png)

click on 

```plaintext
+Assign
```

![Assign](https://github.com/sunilryo/Images/blob/main/5Assign.png)

click on

```plaintext
+Add Users and groups
```

![AddUsers](https://github.com/sunilryo/Images/blob/main/5AddUser.png)

Select the user "Sunil Peela" and click on 

```plaintext
Select
```

![SelectUser](https://github.com/sunilryo/Images/blob/main/5addeduser.png)

Now select

```plaintext
Assign
```
![AssignUser](https://github.com/sunilryo/Images/blob/main/5Assignuser.png)

Once the license is assigned, we will verify the settings of Azure DevOps Administrator Role and allow GP User1 to request the Role assignment

Go to home page and select

```plaintext
Privileged Identity Management
```

![PIM](https://github.com/sunilryo/Images/blob/main/6IPM.png)

Select

```plaintext
Microsoft Entra Roles
```

![Entra Roles](https://github.com/sunilryo/Images/blob/main/6EntraRoles.png)

Select

```plaintext
Settings
```

![Settings](https://github.com/sunilryo/Images/blob/main/6Settings.png)

Search for "Azure DevOps Administrator" and click on it

![AzureDevOps](https://github.com/sunilryo/Images/blob/main/6AzureDevOps.png)

Click on 

```plaintext
Edit
```

![Editing](https://github.com/sunilryo/Images/blob/main/6Edit.png)

Check on "Require Approval to activate" and select

```plaintext
No approver selected
```
So this will add an option for the admin to approve requests

![Adding allow option for admin to approve requests](https://github.com/sunilryo/Images/blob/main/6Approval.png)

Select "sunil peela" admin user and click on select

![Admin user](https://github.com/sunilryo/Images/blob/main/6SelectUser.png)

click on

```plaintext
Update
```

![Update](https://github.com/sunilryo/Images/blob/main/6Updaterole.png)

We have successfully assigned admin user the permissions to approve or deny the requests sent by other users.

Now we add an assignment for the gpuser1 for the role to use temporarily

select 

```plaintext
Roles
```
under the Manage section.

![Roles](https://github.com/sunilryo/Images/blob/main/6Roless.png)

Click on 

```plaintext
+Add Assignment
```

![Assignment](https://github.com/sunilryo/Images/blob/main/6Assignments.png)

select Role as "Azure DevOps Administrator"

and click on 

```plaintext
No member selected
```

![Assignments to role](https://github.com/sunilryo/Images/blob/main/6assigning.png)

click on "GPUser1" and select

![Selected user](https://github.com/sunilryo/Images/blob/main/6selecteduser.png)

Now click on Next > Assign

![Assigned Role to Member](https://github.com/sunilryo/Images/blob/main/6Assignedroletomembr.png)

So we have created an assignment for gpuser1 for "Azure DevOps Administrator" role. 

Now switch to the gpuser1 account to view the assignment and click on 

```plaintext
Privileged Identity Management
```

![PIM in other account](https://github.com/sunilryo/Images/blob/main/6Otheraccount.png)

select

```plaintext
My roles
```

![My Roles](https://github.com/sunilryo/Images/blob/main/6Myroles.png)

Now you can see gpuser1 has the option to request for "Azure DevOps Administrator" role by *Activate* option

![Eligible](https://github.com/sunilryo/Images/blob/main/6Eligibleassignment.png)

Under *active assignment* we see the actual role of the user 

![SActualrole](https://github.com/sunilryo/Images/blob/main/6activeassignment.png)

click on

```plaintext
Activate
```

![Activate](https://github.com/sunilryo/Images/blob/main/6Activate.png)

Enter the reason as "Testing" and click on

```plaintext
Activate
```

![Activate with reason](https://github.com/sunilryo/Images/blob/main/6Activateit.png)

The request is pending for approval from the admin "Sunil Peela" 

Now we switch to the admin profile and click on 

```plaintext
Privileged Identity Management
```

![PIM Admin](https://github.com/sunilryo/Images/blob/main/6Loggedinaccountback.png)

Select

```plaintext
Approve requests
```

![Approve requests](https://github.com/sunilryo/Images/blob/main/6Request.png)

Select the request receive and click on 

```plaintext
"Approve
```

![Request Approved](https://github.com/sunilryo/Images/blob/main/6Approvedd.png)

Enter the justification as "Testing" and select

```plaintext
Confirm
```

![Confirm](https://github.com/sunilryo/Images/blob/main/6confiorm.png)

Now switch to gpuser1 to check the role assignment

![Role assigned](https://github.com/sunilryo/Images/blob/main/6roleassigned.png)

This is how privileged Identity Management is done in Microsoft Azure

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h2> *Monitoring Identity Secure Score* </h2>

Click on

```plaintext
Identity secure score
```

which is under the *Protection* section

![Protection](https://github.com/sunilryo/Images/blob/main/7Identityscore.png)

The secure score for identity will be displayed as shown below

![IdentityScore](https://github.com/sunilryo/Images/blob/main/7securescore.png)

Click on any Improvement actions to see the score impact and description

![Final](https://github.com/sunilryo/Images/blob/main/7assigned.png)

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h1> Azure Cyber Tools </h1>

<h2> *DDOS Protection Plan*</h2>

DDOS protection plan is used by various organizations to protect the network infrastructure from DDOS attacks. These are the following steps to set up a DDOS plan in Microsoft Azure.

    Click on "Create Resource"
    
  ![Resourcce](https://github.com/sunilryo/Images/blob/main/8CreateResource.png)

    Search "DDOSprotectionplan" and select it

  ![DDOSprotectionPlan](https://github.com/sunilryo/Images/blob/main/8DDOS%20protection.png)

    click on "Create"

  ![Create](https://github.com/sunilryo/Images/blob/main/8Creaate1.png)

     Enter the name as "plan1", select the Resource group as "RG_Web_Server" 

  ![Name](https://github.com/sunilryo/Images/blob/main/8Name.png)

     click on "Review and Create" and click on "Create"
  Now the DDOS protection plan has been created

  <h2> *Connecting DDOS protection plan to Virtual Network *</h2>

    We now create a virtual network by clicking on "Create Resources"

  ![CreateVirtualNetwork](https://github.com/sunilryo/Images/blob/main/88Createvirtual.png)

    Search Virtual Network and select "Virtual network"

  ![Selection](https://github.com/sunilryo/Images/blob/main/88VN.png)

    Click on "Create"

  ![Create](https://github.com/sunilryo/Images/blob/main/88Create.png)

    Select the Resource Group as "RG_Web_Server" and type the name as "MyVnet"

  ![Vnet](https://github.com/sunilryo/Images/blob/main/88donevn.png)

    Click on "Enable Azure DDoS protection" and select Plan1 in Dos Protection plan

  ![Ddos](https://github.com/sunilryo/Images/blob/main/88as.png)

    Click on create
  This will link DDoS Protection plan with the Virtual Network

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<h1> Create a Windows Virtual Machine in the Azure Portal </h1>

I am creating a Windows Virtual Machine to host a new website for Sam Scoops. I am deploying the virtual machine for the Sam’s Scoops web server using the virtual network Web_Server on a 172.16.1.0 subnet. This virtual machine is named "SamScoopsWeb".  

<h2>Create Network and Resource Group</h2>

>**Step 1**

  Sign in to the [Azure portal](https://portal.azure.com/) with your credentials.





























  
   
























