# Daily auto-download script and report generation with the VirusTotal API and YARA

CowrieScan.py is built to run everyday either manually or automatically with something like a cronjob. It depends upon having a working VirusTotal API key and the SSH credentials to log into a Cowrie SSH honeypot to download the appropriate files/directories. The script is just one Python File that works in a 5 step process:

* First, the script warns the user that the script is designed to extract malware and that it will need a VirusTotal API key to work. If the user wants to auto download files from a Cowrie honeypot over SSH, they have to provide the credentials to do so.
* The script then attempts to connect to the Cowrie honeypot over SFTP using the paramiko library provided it has a hostname, port, username, and password from the user.
* The script also includes a switch option (1 or 2) where you can decide if you want to download all of the archives from the Cowrie honeypot or just the ones collected the day before. Either way, the script will organize the files by their modification time into individual directories.
* After doing so, the script will check if any archive files were successfully downloaded and extract them. If no archive files were found, the script will make a note of that and write the current day/directory to ``NoArchiveDays.txt".
* The script also checks for and downloads the log files for particular days if an associated directory is set up on the Cowrie server to backup and sort the log files with the proper naming conventions. More detail on this in the next script.
* Then the script will go into the directory created by the cowrie archives (/data/cowrie/downloads/), iterate through each file, checking for executables, obtaining their respective SHA256 hash, and checking them with the VirusTotal API.
* If the script is unable to find an executable in the VirusTotal database by using the SHA256 hash, it will be temporarily moved to a directory called "/newSamples/", be uploaded automatically, and the script will sleep while it is queued so that it can check VirusTotal again for the results. If there is a long wait time or the queue at VirusTotal is especially long, the built in sleep time in the script may not be long enough to retrieve the analysis result. In this case, you could reference the "Queued.md" file/report in the respective directory that keeps track of when or what files are uploaded.
* Finally, the script ends by checking any executable files found with the YARA tool using whatever rule(s) specified. While doing so, the script creates and/or updates an associated csv file with whatever family name the YARA script found. Also it capable of calculating the percentages of the family types. However, this was not very useful throughout the study because the general ruleset from GitHub failed to identify so many executables which I will dicuss more in the next section.

This script can be run every day indefinitely as long as there is sufficient hard drive space and the Cowrie SSH honeypot stays online.

# Malware identification with YARA

CowrieScan.py also works with the Yara tool designed to identify malware based on a set of rules. Yara rules can be created manually by the user to identify malware samples. For this study, I initially only used the rules found on Github (https://github.com/Yara-Rules/rules). The rule set claims it is designed to save security professionals and researchers time. However, in the case of identifying fresh malware samples from a honeypot I found it lacking. Additionally, this general ruleset did give me a good baseline for adding new rules as I create them with the AutoYara tool. Every rule from the GitHub repo can be compiled/referenced at once by using the "index.yar" file. See the following line of code as an example: 

```
rules = yara.compile(filepath='~/index.yar')
```

In addition to this, the script can also calculate the percentage of each malware type and display them in the terminal after running the script.

# Backing up the JSON Log Files

As mentioned in the previous section, the CowrieScan.py script also downloads the associated log files for a particular day. This is dependent upon a script and a cronjob being set up on the server that is running on the Cowrie honeypot. After creating and putting in place a script for copying the log files by their modification date, the following line was added to the honeypot server's crontab:

```
0 1 * * * /usr/bin/env python3 copyLogFiles.py
```

The script works by iterating through all of the log files collected by Cowrie on the server and organizing them by their last modification date into an individual directory. These individual directories can then be downloaded by the daily download script described in the previous section. They will be placed as a subdirectory within the associated directory for the day in a folder named "logFiles-date". By organizing the log files on the server-side instead of the client side with the daily download script, we save ourselves the trouble of having to figure out how to do something similar with the paramiko library in python.

# Working with the Shodan API

For a previous study, I prepared scripts that can find all of the unique IP addresses or commands from a given Cowrie JSON log file (See: https://noelpat.github.io/Filtering-commands-from-cowrie-logs.html). For this particular study, I updated the script (shodanAPIscan.py) used to filter results from cowrie logs so that it can iterate through multiple directories and log files together for analysis. By doing so, this enables you to only analyze log files for certain days since the daily download script organizes each day into its own directory. Additionally, feeding these IP addresses into the Shodan API allows you to find various information such as open port numbers, hostnames, and CVE's associated with particular IP addresses. The following are helpful references:
* https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/
* https://help.shodan.io/developer-fundamentals/looking-up-ip-info

I also created a Python script for finding the top ten most common IP addresses named toptenIP.py. 
