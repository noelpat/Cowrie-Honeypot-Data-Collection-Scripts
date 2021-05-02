# This program will start by downloading the archive files and log files from a Cowrie honeypot via sftp
# It relies upon the paramiko library.
# This program will then iterate through files in the working directory and extract all archive files downloaded.
# The program will then scan all of the executable files inside the new directory "/data/cowrie/downloads/"
# using the VirusTotal API and the Yara malware identification unless commented out. See main method.

# Reference: https://www.youtube.com/watch?v=EgLNmG2LzTI
# Reference: https://stackoverflow.com/questions/10377998/how-can-i-iterate-over-files-in-a-given-directory
# Reference: https://cmdlinetips.com/2014/03/how-to-run-a-shell-command-from-python-and-get-the-output/
# Reference: https://www.geeksforgeeks.org/python-program-to-merge-two-files-into-a-third-file/

# You may have to make the bash scripts executable before running this script!

import subprocess
import os
import stat
import errno
import sys
from io import StringIO
import shutil
import requests
import hashlib
import time
from time import sleep
import tarfile
from ftplib import FTP
import pysftp
import paramiko
import datetime
from datetime import date
from datetime import timedelta
import yara
import csv
from collections import Counter

def Warn_user():
	print("WARNING: This script was created to download and extract malware!\n")
	print("It is recommended to only run this script in an isolated environment.\n")
	print("By default this script will only upload malware to VT smaller than 32 MB.\n")
	print("See: https://developers.virustotal.com/reference#file-scan\n")
	print("Please add your own API key to the script to access the Virus Total API. (Lines 271 & 419)")
	print("Please configure the SFTP settings in the main method with your honeypot login.")
	user_choice = input("Are you sure you want to continue? Enter y or n\n")

	if user_choice == "n":
		print("Exiting...")
		exit()
	else:
		print("Starting extraction...")

def sftp_download(hostname, port, u, pwd, switch, download, newDir):
	today = str(date.today())
	todaySplit = today.split('-') # Format: 2021-01-13
	year = todaySplit[0]
	
	# Calender for converting month into numerical date
	cal = {
	'Jan' : '01',
	'Feb' : '02',
	'Mar' : '03',
	'Apr' : '04',
	'May' : '05',
	'Jun' : '06',
	'Jul' : '07',
	'Aug' : '08',
	'Sep' : '09',
	'Oct' : '10',
	'Nov' : '11',
	'Dec' : '12',
	}

	try:
		transport = paramiko.Transport((hostname, port))
		transport.connect(username=u, password=pwd)
		sftp = paramiko.SFTPClient.from_transport(transport)
	except:
		print("Unable to connect or log into SFTP server. Please check configuration settings in main:")
		print("Hostname:", hostname)
		print("port:", port)
		print("user:", u)
		exit()
	# print(sftp.listdir()) # print statement to verify connection
	sftp.chdir(download) # move/drop to Cowrie data directory
	
	# Switch 1, we download all archives from the cowrie directory
	if switch == 1:
		print("Downloading all archives from:", download)

		# Check for and grab first archive "downloads.tgz"
		current = str(sftp.lstat('downloads.tgz'))
		x = current.split()
		directoryName = "Cowrie-"+year+"-"+cal[x[6]]+"-"+x[5]
		
		try:
			# Create target directory
			os.mkdir(directoryName)
			print("Created directory and adding file to:", directoryName)
			newDir.append(directoryName)
		except FileExistsError:
			print("Adding file to", directoryName)
		
		sftp.get('downloads.tgz', directoryName+"/"+'downloads.tgz')
		
		# iterate through directory and get all archives with the name 'downloads.tgz.*'
		# range 1 to 999 should be able to cover all files. Adjust if necessary.
		for i in range(1, 999):
			downloadMe="downloads.tgz."+str(i)
			print("Attempting to download", downloadMe)
			try:
				current = str(sftp.lstat(downloadMe))
				x = current.split()
				directoryName = "Cowrie-"+year+"-"+cal[x[6]]+"-"+x[5]
				
				try:
					# Create target directory
					os.mkdir(directoryName)
					print("Created directory and adding file to:", directoryName)
					newDir.append(directoryName)
				except FileExistsError:
					print("Adding file to", directoryName)
					
				sftp.get(downloadMe, directoryName+"/"+downloadMe)
			except:
				# You can modify this and get rid of the break
				# For example, downloads.tgz.1 may be missing.
				print("File does not exist! Breaking...")
				break
		
	# Switch 2, we only download the archive files from yesterday
	elif switch == 2:
		# Create directory for today (using yesterday's date) if it does not already exist
		yesterday = str(date.today() - timedelta(days = 1))
		workingDir = "Cowrie-"+yesterday
		exist = os.path.isdir(workingDir)
	
		if exist != True:
			try:
				os.mkdir(workingDir)
			except:
				print("Failed to create directory for", yesterday)
				print("Check your permissions? Does directory already exist?")
				print("Exiting...")
				exit()
	
		newDir.append(workingDir)
		# get yesterday's date.
		# Reference: https://www.geeksforgeeks.org/get-yesterdays-date-using-python/
		print("Downloading all files from: ", yesterday)
		yesDate = yesterday.split('-') # Format: 2021-01-13
		
		# Check if we need to download the first archive 'downloads.tgz'
		first = str(sftp.lstat('downloads.tgz'))
		
		# split first into array
		x = first.split()

		# Compare month and day. Warning: This does not check year!
		if yesDate[2] == x[5] and yesDate[1] == cal[x[6]]:
			print("File matches yesterdays date: downloads.tgz")
			sftp.get('downloads.tgz', workingDir+"/"+'downloads.tgz')
		
		# iterate through directory and get all archives with the name 'downloads.tgz.*'
		# range 1 to 999 should be able to cover all files. Adjust if necessary.
		for i in range(1, 999):
			downloadMe="downloads.tgz."+str(i)
			try:
				current = str(sftp.lstat(downloadMe))
				# check if yesterday's date matches before downloading
				x = current.split()
				if yesDate[2] == x[5] and yesDate[1] == cal[x[6]]:
					print("File matches yesterdays date:", downloadMe)
					sftp.get(downloadMe, workingDir+"/"+downloadMe)
			except:
				print("Checked all files! Moving to next step...")
				break

		# Grab the json log files that correspond with this day/date
		# Iterate through newDir list and check dates
		# print(sftp.listdir(path=logDir)) # print statement
		sftp.chdir("/mnt/zeus-share/CowrieLogs/") # move/drop to Cowrie data directory
		logDir = "logFiles-"+yesterday # Set directory name
		print(workingDir)
		print(logDir)
		exist = os.path.isdir(workingDir+"/"+logDir)
	
		if exist != True:
			try:
				os.mkdir(workingDir+"/"+logDir)
			except:
				print("Failed to create directory for", logDir)
				print("Check your permissions? Does directory already exist?")

		try:
			file_list = sftp.listdir(path=logDir) # grab file list
			for item in file_list:
				# download each file
				sftp.get(logDir+"/"+item, workingDir+"/"+logDir+"/"+item)
		except:
			print("Failed to grab log files for directory", logDir)

def Extract_malware(newDir, downloads):
	# Keep track of gzip files found and errors inside files
	total = 0
	errCnt = 0
	
	for i in newDir:	
		# Extract all archives in folder
		directory = i
		
		for file in os.listdir(directory):
				filename = os.fsdecode(file)
				realLocation = directory+"/"+filename
				# print(realLocation)
				out = subprocess.Popen(['file', realLocation],
				    stdout=subprocess.PIPE,
				    stderr=subprocess.STDOUT)

				stdout,stderr = out.communicate()
				# print("Value of stdout: ", stdout)
				if b'gzip' in stdout:
					print("Extracting", filename)
					my_tar = tarfile.open(realLocation)
					my_tar.extractall(directory)
					my_tar.close()
		directory = i+downloads
		# Check if downloads directory exist
		if not os.path.exists(directory):
			print("Downloads directory does not exist.")
			print("This likely means no archive files were downloaded.")
			print("Appending to NoArchiveDays.txt.")
			file1 = open("NoArchiveDays.txt", "a")  # append mode 
			file1.write(i+"\n") 
			file1.close() 
			print("Exiting...")
			exit()
		
		# Check the downloads directory for additional gZip files to extract.
		for file in os.listdir(directory):
			filename = os.fsdecode(file)
			realLocation = directory+filename
			# print(realLocation)
			
			out = subprocess.Popen(['file', realLocation],
			    stdout=subprocess.PIPE,
			    stderr=subprocess.STDOUT)

			stdout,stderr = out.communicate()
			# print("Value of stdout: ", stdout)
			if b'gzip' in stdout:
				total = total + 1
				print("gzip file found. Extracting...")
				try:
					my_tar = tarfile.open(realLocation)
					my_tar.extractall(directory)
					my_tar.close()
				except EOFError as error:
					errCnt = errCnt + 1
					print("End of file error with file: ", filename)
				except Exception as exception:
					errCnt = errCnt + 1
					print("Error extracting file: ", filename)
			
	print("Total gzip files found inside downloads directory/directories:", total)
	print("Errors while trying to extract gzip files:", errCnt)

def Check_malware(newDir, directory, destination):
	oldDir = directory
	oldDest = destination
	
	# Parameters for checking against virustotal API
	params = {'apikey': 'your-api-key', 'resource': 'hashGoesHere!'}
	headers = {
		"Accept-Encoding": "gzip, deflate"
	}
	
	for i in newDir:
		directory = i+oldDir
		print("Scanning files in directory:", directory)
		if directory is not destination:
			# Reference: http://deepix.github.io/2017/02/02/eexists.html
			destination = i+oldDest # Combine new directory name with destination name
			if not os.path.exists(destination):
				try:
					os.mkdir(destination)
				except OSError as e:
					if e.errno != errno.EEXIST:
						raise
			
			print("Destination for new malware samples (if any):", destination)

		# Check file hashes with the virus total API.
		print("Checking the executable files against virus total.")

		# Drop to data directory and check the files against virus total API
		exe = 0
		nonExe = 0
		total = 0

		open(i+"/Results.md", "a") # Creates file before or if no malware samples are found. (Optional)

		if directory == destination:
			with open(i+"/Results.md", "a") as fileObject:
				writeNew = """
				
				*** New Malware Samples ***
				
				"""
				fileObject.write(writeNew)

		with open(i+'/jsonErrors.txt', 'w') as outfile:
			for file in os.listdir(directory):
				total = total + 1
				filename = os.fsdecode(file)
				# print("Value of file:", file)
				print("Value of filename:", filename)
				# print("Value of directory:", directory)
				
				realLocation = directory+filename
				out = subprocess.Popen(['file', realLocation],
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT)

				stdout,stderr = out.communicate()

				if b'executable' in stdout:
					exe += 1
					# get md5sum of file
					
					sha256_returned = hashlib.sha256(open(realLocation,'rb').read()).hexdigest()
					print(sha256_returned)
					
					params['resource'] = sha256_returned

					response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
					
					json_response = ''
					if 'json' in response.headers.get('Content-Type'):
						json_response = response.json()
						print(json_response)

						if json_response['response_code'] == 0 and b'Python' not in stdout:
							print("File not found in VT db:", filename)
							if directory is not destination:
								print("Moving to directory for new malware samples...")
								# Make sure the directory exists before moving
								if os.path.exists(destination):
									try:
										shutil.move(realLocation, destination)
									except OSError as e:
										if e.errno != errno.EEXIST:
											raise						

						elif json_response['response_code'] == 1:
							md5 = json_response["md5"]
							sha256 = json_response["sha256"]
							sha1 = json_response["sha1"]
							scan_date = json_response["scan_date"]
							positives = json_response["positives"]
							total = json_response["total"]

							md = """
							# Scan Results for {filename}
							### MD5: {md5}
							### SHA256: {sha256}
							### SHA1: {sha1}
							""".format(filename=filename, md5=md5, sha256=sha256, sha1=sha1)

							scanners = json_response["scans"].keys()
							md += """
							| Scanner        | Detected           | Resulted  |
							| ------------- |:-------------:| -----:|
							"""
							for scanner in scanners:
								detected = json_response["scans"][scanner]["detected"]
								result = json_response["scans"][scanner]["result"]
								md += """|{scanner}| {detected}| {result}|\n""".format(scanner=scanner, detected=detected, result=result)

							with open(i+"/Results.md", "a") as fileObject:
								fileObject.write(md)
							
							# create 1 minute delay for virus total api
							if exe != 0 and exe % 3 == 0:
								print("sleeping for 60 seconds...")
								sleep(65)
						else:
							nonExe += 1
							#print(stdout)
					else:
						print('Response not in JSON format. Writing filename to jsonErrors.txt')
						outfile.write(sha256_returned + "\n")
						if exe != 0 and exe % 3 == 0:
							print("sleeping for 60 seconds...")
							sleep(65)
		print("Stats for directory", i)
		print("Executables found:", exe)
		print("Non-executable files found:", nonExe)
		print("Total files checked:", total)
		

# Upload and check the samples not found through Hash checking
def Upload_new(newDir, newsamples):
	print("Starting upload process for new malware samples!")
	with open(newDir+newsamples+'/jsonErrors.txt', 'w') as outfile:
		directory = newDir+newsamples
		# iterate through each file in target directory
		for file in os.listdir(directory):
			filename = os.fsdecode(file)
			realLocation = directory + filename
			print("Current filename:", realLocation)
			out = subprocess.Popen(['file', realLocation],
				stdout=subprocess.PIPE,
				stderr=subprocess.STDOUT)

			stdout,stderr = out.communicate()

			if b'executable' in stdout:
				# Upload all executable files from target directory
				url = 'https://www.virustotal.com/vtapi/v2/file/scan'
				params = {'apikey': 'your-api-key'}
				files = {'file': (realLocation, open(realLocation, 'rb'))}
				# we need to add jsonError checking here as well. Check if the response in json!
				
				response = requests.post(url, files=files, params=params)
				# print("Value of response:", response)
				
				# Check if response in json format, else write to jsonErrors.txt
				if 'json' in response.headers.get('Content-Type'):
					with open(newDir+"/Queued.md", "a") as fileObject:
						result = str(response.json())
						fileObject.write(result + "\n")
				else:
					print('Response not in JSON format. Writing filename to jsonErrors.txt')
					outfile.write(str(filename) + "\n")
					# Add sleep time between uploads to avoid errors and disconnects.
			sleep(1)

def Yara_check(newDir, data, newSamples):
	# iterate through every directory in newDir list
	for i in newDir:
		directory = i # Reset directory variable
		totalCounts = [] # Reset total count list
		countMatch = 0 # Reset countMatch variable
		# Make sure to check for 'newsamples' directory
		print("Scanning files in directory:", directory)
		unknown = 0
		exe = 0
		undetected = 0
		nonExe = 0
		total = 0
		rules = yara.compile(filepath='/home/test/rules-master/index.yar')
		exeFile = []
		malwareList = []
		uniqueMalware = []

		with open(directory+'/samples.csv', 'w', newline='') as csvfile:
			spamwriter = csv.writer(csvfile, delimiter=' ',
					quotechar='|', quoting=csv.QUOTE_MINIMAL)
			spamwriter.writerow(["Filename", "Malware Detected"])
		
			# Iterate through data/downloads directory
			directory = i + data
			for file in os.listdir(directory):
				total = total + 1
				filename = os.fsdecode(file)
				# print("Value of file:", file)
				realLocation = directory + filename
				out = subprocess.Popen(['file', realLocation],
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT)

				stdout,stderr = out.communicate()


				if b'executable' in stdout: # if file is executable
					# print("Executable file found:", file)
					# Add executable file to list
					exeFile.append(str(file))
					exe += 1
					# Check file/match with YARA
					matches = rules.match(realLocation, timeout=60)
					# print("Value of matches:", matches)
					if not matches:
						undetected += 1
						print("Undetected sample found!")						
						# Create directory for unidentified malware
						if not os.path.isdir(i+'/YARA.unid'):
							print("creating unidentified directory!")
							os.mkdir(i+'/YARA.unid')		
						
						shutil.move(realLocation, i+'/YARA.unid')
					else:
						# unique values
						result = checkIfDuplicate(uniqueMalware, matches)
						
						if not result:
							# add to unique values list
							uniqueMalware.append(matches)
						
						# add values to another list for calculating percentages
						malwareList.append(matches)
															
						# write this malware to csv file
						spamwriter.writerow([file, matches])
				else:
					unknown = unknown + 1
					for file in os.listdir(directory):
						total = total + 1
						filename = os.fsdecode(file)
						# print("Value of file:", file)
						realLocation = directory + filename
						out = subprocess.Popen(['file', realLocation],
							stdout=subprocess.PIPE,
							stderr=subprocess.STDOUT)

						stdout,stderr = out.communicate()


						if b'executable' in stdout: # if file is executable
							# print("Executable file found:", file)
							exe += 1
							# Check file/match with YARA
							matches = rules.match(realLocation, timeout=60)
							# print("Value of matches:", matches)
							if not matches:
								undetected += 1
								print("Undetected sample found!")						
								# Create directory for unidentified malware
								if not os.path.isdir(i+'/YARA.unid'):
									print("creating unidentified directory!")
									os.mkdir(i+'/YARA.unid')
									
								shutil.move(realLocation, i+'/YARA.unid')
							else:
								# unique values
								result = checkIfDuplicate(uniqueMalware, matches)
								
								if not result:
									# add to unique values list
									uniqueMalware.append(matches)
								
								# add values to another list for calculating percentages
								malwareList.append(matches)
																	
								# write this malware to csv file
								spamwriter.writerow([file, matches])
						else:
							unknown = unknown + 1
			
			# Check if directory for new samples exist
			directory = i + newSamples
			if os.path.isdir(directory):
				# Iterate through new samples directory next
				for file in os.listdir(directory):
					total = total + 1
					filename = os.fsdecode(file)
					# print("Value of file:", file)
					realLocation = directory + filename
					out = subprocess.Popen(['file', realLocation],
						stdout=subprocess.PIPE,
						stderr=subprocess.STDOUT)

					stdout,stderr = out.communicate()


					if b'executable' in stdout: # if file is executable
						# print("Executable file found:", file)
						# Add executable file to list
						exeFile.append(str(file))
						exe += 1
						# Check file/match with YARA
						matches = rules.match(realLocation, timeout=60)
						# print("Value of matches:", matches)
						if not matches:
							undetected += 1
							print("Undetected sample found!")						
							# Create directory for unidentified malware
							if not os.path.isdir(i+'/YARA.unid'):
								print("creating unidentified directory!")
								os.mkdir(i+'/YARA.unid')		
							
							shutil.move(realLocation, i+'/YARA.unid')
						else:
							# unique values
							result = checkIfDuplicate(uniqueMalware, matches)
							
							if not result:
								# add to unique values list
								uniqueMalware.append(matches)
							
							# add values to another list for calculating percentages
							malwareList.append(matches)
																
							# write this malware to csv file
							spamwriter.writerow([file, matches])
					else:
						unknown = unknown + 1
						for file in os.listdir(directory):
							total = total + 1
							filename = os.fsdecode(file)
							# print("Value of file:", file)
							realLocation = directory + filename
							out = subprocess.Popen(['file', realLocation],
								stdout=subprocess.PIPE,
								stderr=subprocess.STDOUT)

							stdout,stderr = out.communicate()


							if b'executable' in stdout: # if file is executable
								# print("Executable file found:", file)
								exe += 1
								# Check file/match with YARA
								matches = rules.match(realLocation, timeout=60)
								# print("Value of matches:", matches)
								if not matches:
									undetected += 1
									print("Undetected sample found!")						
									# Create directory for unidentified malware
									if not os.path.isdir(i+'/YARA.unid'):
										print("creating unidentified directory!")
										os.mkdir(i+'/YARA.unid')
										
									shutil.move(realLocation, i+'/YARA.unid')
								else:
									# unique values
									result = checkIfDuplicate(uniqueMalware, matches)
									
									if not result:
										# add to unique values list
										uniqueMalware.append(matches)
									
									# add values to another list for calculating percentages
									malwareList.append(matches)
																		
									# write this malware to csv file
									spamwriter.writerow([file, matches])
							else:
								unknown = unknown + 1

		with open(i+'/familyPercent.csv', 'w', newline='') as csvfile:
			spamwriter = csv.writer(csvfile, delimiter=' ',
					quotechar='|', quoting=csv.QUOTE_MINIMAL)
			spamwriter.writerow(["Variable", "Number/Percentage"])

			print("Writing values of malware percentages...")
			# print("Malware sets found:")
			# print(uniqueMalware)
			# print("Executables found:", exe)
			# print("Executable files undetected by Yara:", undetected)
			# print("Non-executable files found:", nonExe)
			# print("Total files checked:", total)
			spamwriter.writerow(["Date/directory", i])
			spamwriter.writerow(["Malware sets found", uniqueMalware])
			spamwriter.writerow(["Executables found", exe])
			spamwriter.writerow(["Executable files undetected by Yara", undetected])
			spamwriter.writerow(["Non-executable files found", nonExe])
			spamwriter.writerow(["Total files checked", total])
			
			# Count total occurences of each matched malware sample
			for x in uniqueMalware:
				for j in malwareList:
					if x == j:
						countMatch += 1
				totalCounts.append(countMatch)
				countMatch = 0
			
			print("Value of uniqueMalware", uniqueMalware)
			print("Value of malwareList", malwareList)
			print("Value of exeFile", exeFile)
			# calculate percentages
			track = 0
			for x in uniqueMalware:
				percent = calcPercentage(totalCounts[track], len(malwareList))
				# print("Percentage of", i)
				# print(percent)
				# print("count:", totalCounts[track])
				writePercent = str(x) + " " + str(percent)
				writeCounts = str(x) + " " + str(totalCounts[track])
				spamwriter.writerow(["Percentage", writePercent])
				spamwriter.writerow(["Total count", writeCounts])
				track += 1
		
		# Append new malware samples to the total MalwareTrackSheet.csv file if any
		with open('MalwareTrackSheet.csv', 'a', newline='') as csvfile:
			spamwriter = csv.writer(csvfile, delimiter=',',
					quotechar='|', quoting=csv.QUOTE_MINIMAL)

			print("Appending to Malware Track Sheet...")
			print("Value of unique malware:", uniqueMalware)
			# write to MalwareTrackSheet.csv
			track = 0
			for x in uniqueMalware:
				countTotal = str(totalCounts[track])+"/"+str(total)
				spamwriter.writerow([x, countTotal, i])
				track += 1
				print("Wrote the following to MalwareTrackSheet.csv")
				print("Value of countTotal:", countTotal)
				print("Value of x:", x)
				print("Value of i:", i)
				

		# Write unidentified malware samples to a spreedsheet.
		# Optional and incomplete feature.
		# To get this working you would need to calculate the difference between
		# Total malware/executables(exeFile list) - identified malware. Then add to csv file.
		"""
		print("Writing to unidentified malware sheet")
		with open('Unidentified.csv', 'w', newline='') as csvfile:
			spamwriter = csv.writer(csvfile, delimiter=',',
					quotechar='|', quoting=csv.QUOTE_MINIMAL)
			# write to Unidentified.csv
			spamwriter.writerow([x, countTotal, i])
		"""

# Reference: https://thispointer.com/python-3-ways-to-check-if-there-are-duplicates-in-a-list/
def checkIfDuplicate(malwareList, matches):
	# Check for duplicates in the list of malware found
	for i in malwareList:
		if i == matches:
			return True # duplicate found
	return False

def calcPercentage(count, total):
	# calculate percentages of each malware type
	percentage = 100 * float(count)/float(total)
	return percentage

def main():
	Warn_user() # comment this out to turn off warning at start of program.
	print("Starting script...")
  
	# sftp server connection settings
	hostname = "xx.xx.xx.xx"
	port = 64295
	user = "username"
	pwd = "password"
	# newDir = ["Cowrie-2021-02-09", "Cowrie-2021-02-08", "Cowrie-2021-02-07"] # DEBUG 
	newDir = [] # Keep track of new directories created for extraction/scanning

	# Set download directories for cowrie honeypot
	switch = 2 # decide whether to download entire directory or single file (1 or 2)
	download = "/data/cowrie/"

	# Set directory/locations for extracted files and new malware samples
	directory = "/data/cowrie/downloads/" # This is usually where Cowrie archives extrac
	destination = '/newSamples/' # This folder will be created for malware samples not in the VT database.
	
	# Check if MalwareTrackSheet.csv exist and if not create it!
	if not os.path.isfile('MalwareTrackSheet.csv'):
		print("Creating MalwareTrackSheet.csv file...")
		with open('MalwareTrackSheet.csv', 'a', newline='') as csvfile:
			spamwriter = csv.writer(csvfile, delimiter=',',
						quotechar='|', quoting=csv.QUOTE_MINIMAL)
			spamwriter.writerow(["Malware Family", "Count/Total", "Directory/Date"])
	
	sftp_download(hostname, port, user, pwd, switch, download, newDir)
	# print("Value of newDir before Extract_malware:", newDir)
	Extract_malware(newDir, directory)
	Check_malware(newDir, directory, destination)

	newMalware = [] # list for iterating through these directories for the second time
	for i in newDir:
		dir = os.listdir(i+destination)
		if len(dir) > 0: # if destination/newsamples directory not empty
			Upload_new(i, destination)
			newMalware.append(i)

	
	print("Values in newMalware", newMalware)
	if newMalware:
		# Wait a few minutes and check VT database again for new malware uploaded
		print("Waiting while Virus Total scans uploaded files...")
		sleep(60)
		Check_malware(newMalware, destination, destination)
	
	Yara_check(newDir, directory, destination) # check malware files with Yara

if __name__ == "__main__":
	main()
