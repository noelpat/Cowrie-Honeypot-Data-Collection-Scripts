#!/usr/bin/env python3

# A python script for renaming a file in a directory by its last
# modification date, copying it, and then moving it to another directory
# for storage.
# The script will also check for duplicate files before copying and moving.
# A incrementing number is used for each individual file name.
# The script is currently made to work within a cowrie honeypot but can easily be
# modified for similiar use cases.
# Warning: script will ignore directories unless modified
# Warning: metadata is not copied when this script creates copies using shutil

import shutil
import hashlib
import os
import os.path
from os import path
import platform
import stat
import time
import sys
import subprocess
from io import StringIO
from datetime import datetime
from datetime import date
from datetime import timedelta

def moveFile(workingDir, yesterday):
	# dictionary for converting each month of the year to a number for formatting
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
  
  yesDate = yesterday.split('-') # Format: 2021-01-13
	print("Value of yesDate:", yesDate)
	print("Checking modification dates...")

	for file in os.listdir("/data/cowrie/log"):
		filename = os.fsdecode(file) # grab filename
		# check modification time of file
		# check the current file type and send it to stdout
		out = subprocess.Popen(['file', file],
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT)
		stdout,stderr = out.communicate()
		# if statement to make sure we avoid directories and the script itself.
		# next three lines grab the last modification time of the file
		fileStatsObj = os.stat ("/data/cowrie/log/"+filename)
		modificationTime = time.ctime ( fileStatsObj [ stat.ST_MTIME ] )
		splitDate = modificationTime.split( )
		month = splitDate[1]
		day = splitDate[2]
		year = splitDate[4]
		grabmonth = ""

		if month in cal:
			#print(cal[month])
			grabmonth = cal[month]

		# print("Value of splitDate:", splitDate)
		# print("Value of month:", month)
		# print("Value of day:", day)
		# print("Value of year:", year)
		# Check if yesterday's date matches modification time

    # strip leading 0's here for consistency throughout any given day of a month.
		if str(yesDate[0]) == str(year) and str(yesDate[1]) == str(grabmonth) and str(yesDate[2].strip("0")) == str(day):
			print("Value of splitDate:", splitDate)
			print("Value of month:", month)
			print("Value of day:", day)
			print("Value of year:", year)
			print("copying and moving file", filename)
			# Copy file over to workingDir
			shutil.copyfile("/data/cowrie/log/"+filename, "/mnt/zeus-share/CowrieLogs/"+workingDir+"/"+filename)

def main():
	# Create directory for today (using yesterday's date) if it does not already exist
	yesterday = str(date.today() - timedelta(days = 1))
	workingDir = "logFiles-"+yesterday # Set directory name
	today = "/mnt/zeus-share/CowrieLogs/" + workingDir

	try:
		# Create target directory
		os.mkdir(today)
	except FileExistsError:
		print("Directory already exist for today.")

	moveFile(workingDir, yesterday) # Pass workingDir to moveFile
	print("Success.")

if __name__ == "__main__":
	main()
