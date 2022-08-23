# Shihanah tool

<p><img align="left" src="https://github.com/amalsannat/Shihanah/blob/main/Shihanah.gif" width="500" height="320" /><p>
<br/><br/><br/><br/>
<br/><br/><br/><br/>
<br/><br/><br/><br/>
<br/><br/>

## What is it ? 
It is a Threat Intelligence tool. The main functionality of this tool is to help you in initial analysis of (Domains, IPs, and hashes). 
The primary purpose of the tool is to gather and provide you IOCs related to your inputs. However, the tool will provide related IOCs if they are available in Open Source Threat Intelligence services < currently only support Virus Total>.


## Features :

- Getting **reputation** of one/multiple Inputs. 
- Getting all IOCs that have been seen with your input(domain,hash, or IP). Moreover, you can get them with **full details for each related IOC** after extracting the results as an excel file.
However, you can get the related IoCs without full details when you don't export the results.
- **For each Input/IOC you will get the following:**
	- For Hashes (Imported Libraries, Imported functions, Threat Lable name, Size, Extension, Reputation score, Tags, and other hashes(MD5, Sha256, and Sha1)) 
	- For Domains (Reputation score, Creation Date, IP, Tags, and Threat Lable name)
	- For IPs (Reputation score, Subnet, Country, Tags, and Threat Lable name) 
 - This tool was designed to **help in the initial analysis**, when you want to check one/multiple Suspicious/Malicious IOCs and you want to get related IOCs if exist.



## Requirements: 
- python3 
- Libraries: 
  - openpyxl
  - requests
  - time
  - pandas 
  - numpy
  - xlsxwriter
  - tabulate 
- Virus Total API Key:
  - Create a free account https://www.virustotal.com/gui/join-us
  - Get your API Key https://youtu.be/9ftKViq71eQ

  ## Usage: 
 -> python3 main.py
