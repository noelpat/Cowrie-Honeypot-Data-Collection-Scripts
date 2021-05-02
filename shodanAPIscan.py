# Iterates through directories, reads from JSON log files,
# and feeds IP addresses to the Shodan API. Please provide Shodan API key line 107.
# By default this script gathers the hostname, ISP, and vulnerabilities associated
# with a given IP address and write them a file. More options could be added manually.
# It assumes a directory structure where each given directory checked will have a 
# subdirectory for log files in the following format: logFiles-Date
# Reference/credit: https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/

import shodan
import sys
import urllib.request
from urllib.request import urlopen
import json
import requests
from time import sleep
import csv
import os
import subprocess
import tarfile
import gzip

# Reference/credit: https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/
def remove_duplicates(seq, idfun=None):
	if idfun is None:
		def idfun(x): return x
	seen = {}
	result = []
	for item in seq:
		marker = idfun(item)
		if marker in seen: continue
		seen[marker] = 1
		result.append(item)
	return result

# Reference/credit: https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/
def get_lists(json_data, key):
	full_list = ""
	for x in range(0, len(json_data)):
		try:
			full_list += str(json_data[x] [key]) + "\n"
		except:
			pass
	deduped_list = remove_duplicates(full_list.split())
	#if (key == "src_ip"):
		#deduped_list.sort(key=lambda s: map(int, s.split('.')))

	return full_list, deduped_list

def extract_logs(newDir):
	for i in newDir:
		# Strip date off of directory
		currDate = i.strip("Cowrie-")
		# Extract all archives in folder
		directory = i+"/logFiles-"+currDate
		
		for file in os.listdir(directory):
			filename = os.fsdecode(file)
			realLocation = directory+"/"+filename
			# print(realLocation)
			
			out = subprocess.Popen(['file', realLocation],
				stdout=subprocess.PIPE,
				stderr=subprocess.STDOUT)
			stdout,stderr = out.communicate()
			# print("Value of stdout: ", stdout)
			if b'gzip' in stdout and "tty" not in filename:
				print("Extracting", realLocation)
				os.system("gunzip "+realLocation)
				"""
				my_tar = tarfile.open(realLocation)
				my_tar.extractall(directory)
				my_tar.close()
				"""			

def collect_data(newDir):
	data = []
	for j in newDir:
		data.clear()
		# Strip date off of directory
		currDate = j.strip("Cowrie-")
		# Extract all archives in folder
		directory = j+"/logFiles-"+currDate
		# Iterate through all log files in this directory
		
		for file in os.listdir(directory):
			filename = os.fsdecode(file)
			realLocation = directory+"/"+filename
			# print("collect_data realLocation:", realLocation)

			out = subprocess.Popen(['file', realLocation],
				stdout=subprocess.PIPE,
				stderr=subprocess.STDOUT)
			stdout,stderr = out.communicate()
			# print("Value of stdout: ", stdout)
			if b'JSON' in stdout:
				print("Collecting Data from", realLocation)
				
				## Get a list of all IP addresses that connected to the honeypot.
				## And a deduplicated list too.
				with open(realLocation) as f:
					for line in f:
						data.append(json.loads(line))
		
		# print("Value of data:", data)				
		ip_list, deduped_ip_list = get_lists(data, "src_ip")
		# print("Successfully created list of IP Addresses!", deduped_ip_list)
		# print("ip_list:", ip_list)
		## Print out IP addresses
		# print("\n".join(deduped_ip_list))
		# print(deduped_ip_list[0])

		# Request URL: https://api.shodan.io/shodan/host/{ip}?key=shodan-api-key
		api = shodan.Shodan('shodan-api-key')
		# Loop through list of IP addresses
		# info = api.host(deduped_ip_list) # forbidden without Corporate Plan
		# print(info)
		
		# write info to csv file (optional)
		"""
		with open('edges.csv', 'w', newline='') as csvfile:
			spamwriter = csv.writer(csvfile, delimiter=' ',
			quotechar='|', quoting=csv.QUOTE_MINIMAL)
			spamwriter.writerow(["IP", "Ports"])
		"""

		for i in deduped_ip_list:
			print("Value of i:", i)
			try:
				print("Checking IP:", i)
				info = api.host(i)
				print(info)
				print("Grabbing information...")
				# make sure hostnames exists before grabbing it
				hostnames = ""
				ISP = ""
				vulns = ""
				if 'hostnames' in info.keys():
					print("hostnames found in info.keys! \n")
					hostnames = info["hostnames"]
				if 'isp' in info.keys():
					print("ISP found in info.keys \n")
					ISP = info["isp"]
				if 'vulns' in info.keys():
					print("vulns found in info.keys \n")
					vulns = info["vulns"]
					
				ports = info["ports"]
				
				with open(j+"/"+"ShodanReport.md", "a") as fileObject:
					# Write info to file from Shodan API.
					fileObject.write("Data from " + i + "\n")
					fileObject.write("Hostnames found (if any): \n")
					fileObject.write(str(hostnames) + "\n")
					fileObject.write("ISP found: \n")
					fileObject.write(str(ISP) + "\n")
					fileObject.write("Vulnerabilites: \n")
					fileObject.write(str(vulns) + "\n")
					fileObject.write("Ports: \n")
					fileObject.write(str(ports) + "\n")
					fileObject.write("\n")
					fileObject.write("\n")
			except Exception:
				print("Could not retrieve info about IP Address", i)
				with open(j+"/"+"ShodanReport.md", "a") as fileObject:
					writeIP = "Could not retrieve info about IP Address " + i + "\n"
					fileObject.write(writeIP)
					fileObject.write("\n")
					fileObject.write("\n")

			# Rate-limited to 1 request/second See: https://help.shodan.io/developer-fundamentals/looking-up-ip-info
			sleep(2)

def main():
	newDir = [] # Keep track of new directories created for extraction/scanning
	# iterate through directory and add all of the directories to the newDir list
	
	totalFiles = 0
	for file in os.listdir('.'):
		if os.path.isdir(file):
			newDir.append(str(file))
		
	extract_logs(newDir)
	collect_data(newDir)

if __name__ == "__main__":
	main()
