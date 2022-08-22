# Shihanah tool


## What is it? 
A Threat Intelligence tool. The main funcationalitiy of this tool is to help you in **intial analysis** of (Domains, IPs, Sha1, Sha256, and MD5). 
The main purposes of the tool is to gather and provide you **IoCs realted to your inputs**. However, the tool will provide the realted IoCs if they are availble in Open Source Threat Intelligence services < currently only support Virus Total>.


## Features :

- Get **repution** of one/multiple Inputs. 
- Get all IoCs that have been seen with your input(domain,hashe, or IP). Moreover, you can get them with **full details for each related IoC** after extracting the results as an excell file. 
However, you can get the related IoCs without full details when you don't export the rsults.
- **for each Input/IoC you will get the Folowing:**
	- For Hashes ( Imported Libraries, Imported funcations,Threat Lable name, size, extension, reputeaion score, other hashes(MD5, SHa256,Sha1), and Tags) 
	- For  Domains ( reputeaion score, creation Date, IP, Tags, and Threat Lable name)
	- For IPs ( reputeaion score, Subnet, country, Tags, and Threat Lable name) 
 - This tool was designed to **help in initial analysis**, when you want to check one/multiple Suspicious/Malicious IoCs and you want to get related IoCs if exist.



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
