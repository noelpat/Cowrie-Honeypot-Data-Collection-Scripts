# This script is designed to find the most common IP addresses among multiple
# Cowrie JSON log files by iterating through all of them at once.
# It also intentionally ignores the Malware.Backups directory used for sorting malware
# by submission date.
# Python3 script for iterating through a json log file from a cowrie honeypot.
# Reference/credit: https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/

import sys
import json
from time import sleep
import csv
import os
import subprocess
import tarfile
import gzip
from urllib.request import urlopen
import json

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

# Reference/credit: https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/
def get_ip_location(ip):
    url = 'http://ipinfo.io/'+ip+'/json'
    response = urlopen(url)
    data = json.load(response)
    city = data['city']
    country=data['country']
 
    return country, city

# Reference/credit: https://zeroaptitude.com/zerodetail/analyzing-cowrie-honeypot-results/
def get_top_ten(full_list, deduped_list):
    count_dict = {}
    for item in deduped_list:
        count_dict[item] = full_list.count(item)
    top_ten = sorted(count_dict, key=count_dict.get, reverse=True)[:10]
     
    return top_ten, count_dict

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
		
	#print("Value of data:", data)				
	ip_list, deduped_ip_list = get_lists(data, "src_ip")
	top_ten_ips, ip_freq_dict = get_top_ten(ip_list, deduped_ip_list)
 
	print("\n\n\t\tHONEYPOT ANALYSIS\n\n")
	print("Total unique attacker IPS: {}".format(len(deduped_ip_list)))
	print("Top 10 attackers by IP:\n")
	print("\tIP\t\tConnections\tCountry\tCity")
	for x in top_ten_ips:
		print("\t{:15}\t{}".format(x, ip_freq_dict[x])),
		country, city = get_ip_location(x)
		print("\t\t{}\t{}".format(country, city))

def main():
	newDir = [] # Keep track of new directories created for extraction/scanning
	# iterate through directory and add all of the directories to the newDir list
	
	totalFiles = 0
	for file in os.listdir('.'):
		if os.path.isdir(file) and file != 'Malware.Backups':
			newDir.append(str(file))
		
	extract_logs(newDir)
	collect_data(newDir)

if __name__ == "__main__":
	main()
