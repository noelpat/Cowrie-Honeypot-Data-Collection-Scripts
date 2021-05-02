# This script is designed to find the intersection of the IP addresses
# from Cowrie JSON log files on particular days.
# Edit the newDir list in the main method to add or remove directories.

"""
-Python3 script for iterating through a json log file from a cowrie honeypot.
-Script will filter all unique IP addresses out of a json log file.
Reference/credit: https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/
"""

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
	uniqueIPlist = []
	
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
		# api = shodan.Shodan('shodan-api-key')
		# Loop through list of IP addresses
		# info = api.host(deduped_ip_list) # forbidden without Corporate Plan
		# print(info)
		uniqueIPlist.append(deduped_ip_list)
		# for i in deduped_ip_list:
			# print("Value of i:", i)
	
	# print(uniqueIPlist)
	result = set(uniqueIPlist[0]).intersection(*uniqueIPlist[1:])
	print(result)

def main():
  # Enter the names of the directories you would like to iterate through
  # in the newDir list. If the CowrieScan.py script was used they will be
  # in the following format:
	newDir = ["Cowrie-2021-03-05", "Cowrie-2021-02-23"]
  
  # this method will iterate through the directories and extract the logs
	extract_logs(newDir)
  # this method collects the data from the log files and finds the intersection
  # among the IP addresses (if any)
	collect_data(newDir)

if __name__ == "__main__":
	main()
