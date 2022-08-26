# Shihanah tool

<p><img align="left" src="https://github.com/amalsannat/Shihanah/blob/main/Shihanah.gif" width="500" height="320" /><p>
<br/><br/><br/><br/>
<br/><br/><br/><br/>
<br/><br/><br/><br/>
<br/><br/>

## What is it ? 
It is a threat intelligence tool. The main functionality of this tool is to help you in initial analysis of (Domains, IPs, and hashes). 
The primary purpose of the tool is to gather and provide you IOCs related to your inputs. However, the tool will provide related IOCs if they are available in open source threat intelligence services <currently only supports Virus Total>.


## Features :

- Getting **reputation** of one/multiple Inputs. 
- Getting all IOCs that have been seen with your input(domain,hash, or IP). Moreover, you can get them with **full details for each related IOC** after extracting the results as an excel file.
However, you can get the related IoCs without full details when you don't export the results.
- **For each Input/IOC you will get the following:**
	- For hashes (imported libraries, imported functions, threat lable name, size, extension, reputation score, tags, and other hashes(MD5, Sha256, and Sha1)) 
	- For domains (reputation score, creation date, IP, tags, and threat lable name)
	- For IPs (reputation score, subnet, country, tags, and threat lable name) 
 - This tool was designed to **help in the initial analysis**, when you want to check one/multiple suspicious/malicious IOCs and you want to get related IOCs if exist.



## Requirements:

- python3 
- Virus Total API Key:
  - Create a free account https://www.virustotal.com/gui/join-us
  - Get your API Key https://youtu.be/9ftKViq71eQ


## Installation: 
 -> pip3 install -r Requirements.txt


## Usage: 
 -> python3 main.py
