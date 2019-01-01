import sys
import getopt
import requests
from tenable.io import TenableIO
from tenable_io.client import TenableIOClient
from tenable_io.api.scans import ScanCreateRequest
from tenable_io.api.models import ScanSettings
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import time
import re
from bs4 import BeautifulSoup
import datetime
import argparse
import sys
import os
from pathlib import Path
import base64

# Turn off certificate warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# parse method : fetches the command line parameters and passes them to the
# required variables
parser = argparse.ArgumentParser()

parser.add_argument('-a','--accessKey', required = True)
parser.add_argument('-s','--secretKey', required = True)

parser.add_argument('-t','--task', required = True) 
parser.add_argument('-z','--scanName', required = False)
parser.add_argument('-y','--templateName', required = False)
parser.add_argument('-x','--scannerName', required = False)
parser.add_argument('-w','--targetIP', required = False)
parser.add_argument('-v','--notificationEmail', required = False)
parser.add_argument('-q','--parentPath', required = False)
parser.add_argument('-n','--SystemName', required = False)
parser.add_argument('-k','--projectKey', required = True)
parser.add_argument('-g','--assigneeName', default = "VVignesh")
parser.add_argument('-u','--username', required = True)
parser.add_argument('-p','--password', required = True)
 
args = vars(parser.parse_args())


client = TenableIOClient(args['accessKey'], args['secretKey'])
tio=TenableIO(args['accessKey'], args['secretKey'])
headers   = {"Content-type": "application/json", "X-ApiKeys": "accessKey=" + args['accessKey'] + "; secretKey=" + args['secretKey']}

filenametimestamp = str(datetime.datetime.strftime(datetime.datetime.utcnow(),"%Y_%m_%d_T%H_%M_%S_UTC"))
pathname=''


#Creates the scan with all the parameters given , launches the scan and downloads the report.   
def create_scan(scanName,templateName,scannerName,targetIP,notificationEmail):
 
  print("creating scan")
  scanners = {scanner.name: scanner.id for scanner in client.scanners_api.list().scanners}
  template = client.scan_helper.template(templateName)
  scan_id = client.scans_api.create(ScanCreateRequest(template.uuid,ScanSettings(scanName,targetIP,emails=notificationEmail,scanner_id=scanners[scannerName])))
  
  #launching the scan created..
  launchScan(scan_id)
  print("Scan Completed.")
   

#Launches the scan with the scanID of the newly created scan and calls the download_report to download the report. 
def launchScan(scanID): 
 print('Launching Scan')
 scan = client.scan_helper.id(scanID)
 scan.launch()
 download_report(scanID) 

#Launches the scan with the scanName of already created scan before and calls the download_report to download the report.
def launchScan_Name(scanName): 
 #scanID_return=0
 print('Inside launch scan with name')
 for scan in tio.scans.list():
  #checking all the scans and retrieving the scanID for the scanName provided
  listA = (str('{name}'.format(**scan)))
  if scanName in listA:
   #print((str('{id}'.format(**scan))))
   scanID_return='{id}'.format(**scan)
 scanID_return=int(scanID_return)
 print(scanID_return)
 
 #Getting the scanID for the scanName provided and launching the scan
 scan = client.scan_helper.id(scanID_return)
 scan.launch()
 download_report(scanID_return)   

#Downloads the report in HTML format and puts it in the directory/path specified in the arguments along with the timestamp
def download_report(scanID):
   print('Inside download')
   targetIP=str(tio.scans.details(scanID)['settings']['text_targets'])
   print(targetIP)
   pathname=args['parentPath']+'\\'+targetIP
   DownloadDir=pathname+'\\'+filenametimestamp
   print("Downloading report")
   scan = client.scan_helper.id(scanID)
   
   #pathname=args['parentPath']+'\\'+args['SystemName']+'\\'+filenametimestamp
   #pathname=args['parentPath']+'\\'+filenametimestamp
   
   #Creates a directory with the targetIP , this directory will be common to all the scans for this target IP
   if not os.path.exists(pathname):
    os.mkdir(pathname)
   
   #Download Directory will be having the full report and the diff report along with the timestamp of each.
   if not os.path.exists(DownloadDir):
    os.mkdir(DownloadDir)	
   
   filename = DownloadDir+'\\'+"Full_report_"+ targetIP +".html"
   scan.download(filename,None,u'html',u'vuln_hosts_summary')
   Download_response(scanID)
 
#This gives the full content of the the report for a scan which will be fed to the create_diff method which in turn will parse this content. 
def Download_response(scanID):
 scanurl = 'https://cloud.tenable.com/scans/' + str(scanID) + '/export'
 #tio.scans.details(scanID)
#scanpld = {"format":"csv"}
 targetIP=str(tio.scans.details(scanID)['settings']['text_targets'])
 for asset in tio.assets.list():
  listA = (str('{ipv4}'.format(**asset)))
  if targetIP in listA:
   print((str('{id}'.format(**asset))))
   asset_id=str('{id}'.format(**asset))
 
 scanpld={
    "scan_id": str(scanID),
    "format": "csv",
    "chapters" : "vuln_by_plugin",
    "asset_id" : asset_id 
 } 
 results = requests.post(scanurl, headers=headers, data=json.dumps(scanpld), verify=False).json()
 scanreq = json.loads(json.dumps(results, indent=2, sort_keys=True))
 file_id=str(scanreq["file"])
 #print(file_id)
#print(json.dumps(scanreq["token"]))
 #print "Your report is being prepared..."

# Get the status of the file
 filestatus = requests.get(scanurl +'/'+ file_id + '/status', headers=headers,verify=False)
 print(filestatus.json())	
 resp=requests.get(scanurl +'/'+ file_id + "/download", headers=headers, verify=False)	
 print(resp.content)
 Create_diff(resp,scanID)

def vuln_sorter(text,scanID):

    #Separates the vulnerability scan into a tuple of lists of individual strings 
    lines = text.read().split('\n')
    pattern = re.compile("^\d{5,6}$")    
    IPpattern = re.compile("^(\d{1,3}\.){3}\d{1,3}$") 
    CVSSpattern = re.compile("^\d{1,2}\.\d$")
    vulnerabilities = []
    currLine = []
    words = []
    ip = ''
    count = 0

    targetIP=str(tio.scans.details(scanID)['settings']['text_targets'])
   
    pathname=args['parentPath']+'\\'+targetIP
    #creates a list of vulnerabilities, where each vulnerability begins with its Plugin ID
    for i, line in enumerate(lines):
	words = line.split()
	if words and not pattern.match(words[0]) and i > 0:
            for word in words:
	        currLine.append(word)
	elif words and i > 0:
	    vulnerabilities.append(currLine)
	    currLine = words
    vulnerabilities.append(currLine)
    
    words = tuple(words)

    #Obtains the old PIDs from the PID archive file. These PIDs are already known through previous scans
    with open(pathname+"\\"+'PID_archive.txt', 'a+') as myfile:
        myfile = myfile.read().splitlines()
        old_PID = []
        for line in myfile:
            if line and line[0].isdigit():
                old_PID.append(line)

    
    #Create a new PID array. These are the PIDs found in this current scan     
    new_PID = []
 
    newPIDs = False
    outputMessages = [["Critical"],["High"],["Medium"],["Low"],["Info"]]    
    priority = 0
    criticalCounterTotal = 0
    highCounterTotal = 0 
    mediumCounterTotal = 0
    lowCounterTotal = 0
    infoCounterTotal=0
    #Start of the main loop
    #Range starts with 1 since there is a line of titles from the csv file
    #Checks each line (x) in the scan file 
    for i in range(1, len(vulnerabilities)):
        line = vulnerabilities[i]
        if line == []:
            pass
	#Case where we found a valid PID
	elif line[0].isdigit() and len(line[0]) >= 5 :
	    CVSS = '0.0'
	    for word in line[0:3]:
		if CVSSpattern.match(word):
		    CVSS = word
		    break   
		         
	    #Case for if the PID exists in the previous test and no new PIDs found yet
            if not newPIDs and line[0] in old_PID:
		if float(CVSS) >= 9.0:
		    criticalCounterTotal += 1
		elif float(CVSS) >= 7.0:
		    highCounterTotal += 1
		elif float(CVSS) >= 4.0:
		    mediumCounterTotal += 1
		elif float(CVSS) > 0:
		    lowCounterTotal += 1
		else:
		    infoCounterTotal += 1
            		
	    #Case for if a new, unique, PID was found in this test.
            elif line[0] not in old_PID: 
	        #xcopy = ' '.join(repr(e) for e in xcopy).replace('[','').replace(']','').split(',')
	        #xcopy = ''.join(xcopy).replace("'","")
		try:
	            if float(CVSS) >= 9.0:
			priority = 0
	            elif float(CVSS) >= 7.0:
			priority = 1
	            elif float(CVSS) >= 4.0:
			priority = 2
	            elif float(CVSS) > 0:
			priority = 3
	    	    else:
			priority = 4
		    new_PID.append(line[0])
		    newPIDs = True 
		    
            	    line = ' '.join(str(word) for word in line)
		    outputMessages[priority].append(line)
	        except AttributeError:
	            pass

    #find the target ip address
    for line in vulnerabilities:
        for word in line:
            if IPpattern.match(word):
                ip = word
                break

    #extract the version number from the system parameter. This might need to be tweeked depending on the directory structure used. 
    # version = ""
    # if len(system) > 1:
    	# version = system.split('/')[len(version)-1]
    # else:
        # version = system


    emailBody = ''
    emailSubject = ' Scan  on '+ ip

    if not newPIDs:
	emailBody += 'There are no new vulnerabilities in this scan \n \n'
	emailBody += 'The following old vulnerabilities are still present:'
	emailBody += '\nCritical Priority: ' + str(criticalCounterTotal) 
	emailBody += '\nHigh Priority: ' + str(highCounterTotal) 
	emailBody += '\nMedium Priority: ' + str(mediumCounterTotal) 
	emailBody += '\nLow Priority: ' + str(lowCounterTotal) 
	emailBody += '\nInfo: ' + str(infoCounterTotal)
	emailSubject += ': No new vulnerabilities'
    
	#No new PID , so delList will have set of all the oldPID's 
	DelList= list(set(old_PID)) #kartik
	
	#No new PIDS are found so newPIDlist will be empty as we don't want to create any new JIRA Bug
	newPIDlist=''
	print('No new Vulnerabilities so, all the pids will be deleted in the diff report')
	#print(DelList)
        with open(pathname+"\\"+'DelArchive.txt', 'w+') as myfile:#kartik
            for PID in DelList:#kartik
                myfile.write(PID+"\n")#kartik
        with open(pathname+"\\"+'New_PID.txt', 'w+') as myfile:
		    for PID in newPIDlist:
		        myfile.write(PID+"\n")				
    elif new_PID==[]:
	print 'There is an empty list'
	return 'Probably an Error'

    else:
	emailBody += 'The following new vulnerabilities were found\n'
	#emailBody += 'Critical Priority: ' + len(outputMessages[0])-1 
	#emailBody += '\nHigh Priority: ' + len(outputMessages[1])-1
	#emailBody += '\nMedium Priority: ' + len(outputMessages[2])-1
	#emailBody += '\nLow Priority: ' + len(outputMessages[3])-1
	#emailBody += '\nInfo: ' + len(outputMessages[4])-1
	#emailBody +=  '\n'
	emailSubject += ': New Vulnerabilities: '
	#Parse the list of new vulnerabilities into a "emailBody" and a "emailSubject"
        #The list of new vulnerabilities is a list of lists in priority order, so that
        #highest risk vulns are always at the top of the email body
	for priority in outputMessages:
            if len(priority) > 1:
	        for i, message in enumerate(priority):
	            if i == 0:    
		        emailBody += '\n(' + str(len(priority)-1) + ') '+ message + '\n--------------------------------------------------'
			emailSubject+= ' '+str(priority[0])+': '+str(len(priority)-1)
	            else:
	                emailBody += '\n' + message + '...\n--------------------'
                    #countVul=countVul+1
        #re-write the PID_archive so that any new vulnerabilities are added to the archive kept for the 
        #current ip being scanned.
	PIDList = list(set(new_PID + old_PID))
	
	#New vulnerabilities are found , hence update the delList and the newPIDlist 
	DelList= list(set(new_PID +old_PID)-set(new_PID)) #kartik
	newPIDlist=list(set(new_PID))
	print('New vulnerabilities found, so delete all the old entries except these new for diff report')
	#print(DelList)
        with open(pathname+"\\"+'DelArchive.txt', 'w+') as myfile:#kartik
		 for PID in DelList:#kartik
		  myfile.write(PID+"\n")#kartik   	
        with open(pathname+"\\"+'PID_archive.txt', 'w+') as myfile:
		 for PID in PIDList:
		  myfile.write(PID+"\n")
        with open(pathname+"\\"+'New_PID.txt', 'w+') as myfile:
		 for PID in newPIDlist:
		  myfile.write(PID+"\n")
		
	#Return the 	
    return [emailBody,emailSubject,DelList,newPIDlist]

	
def Create_diff(resp,scanID):
	print('Diff Logic')
	text_list = []
	for line in resp:
		line = line.replace('"', '').replace(',', ' ')
		line = line.split(" ", 2)
		text_list.append(" ".join(line))
	
	#pathname=args['parentPath']+'\\'+args['SystemName']+'\\'+filenametimestamp	
	targetIP=str(tio.scans.details(scanID)['settings']['text_targets'])
	pathname=args['parentPath']+'\\'+targetIP
	filename = pathname+'\\'+filenametimestamp+'\\'+"Full_report_"+ targetIP +".html"
	
	with open(pathname+"\\"+'CSV_to_txt.txt', 'w+') as convert:
		for line in text_list:
			convert.write("" + line)
	with open(pathname+"\\"+'CSV_to_txt.txt', 'r') as f: 
		emailBody, emailSubject,DelList,newPIDlist = vuln_sorter(f,scanID)
	print(emailBody)
	#print(emailSubject)	
	#soup = BeautifulSoup(open("Scan_Node____108_swyznd.html"), "html.parser")

	#******************************************
	with open(filename) as in_file:
	  html_text = in_file.read()
	  soup2 = BeautifulSoup(html_text,"html.parser")
		
	info_count = -1 
	med_count = -1
	low_count = -1
	high_count = -1
	criti_count = -1
	total_count = -1
	for counter in soup2.find_all('span', {'class':'classtext'}):

	  if(str(counter.string) == "Info"):
		info_count += 1
	  if(str(counter.string) == "Medium"):
		med_count += 1
	  if(str(counter.string) == "Low"):
		low_count += 1
	  if(str(counter.string) == "High"):
		high_count += 1
	  if(str(counter.string) == "Critical"):
		criti_count += 1

	print(criti_count)
	print(high_count)
	print(med_count)
	print(low_count)
	print(info_count)

	total_count = criti_count + high_count + med_count + low_count + info_count
	print(total_count)	
	#*****************************************

	with open(filename) as in_file:
	  html_text = in_file.read()
	  soup = BeautifulSoup(html_text,"html.parser")

	  print(DelList)
	#pattern = r"(%s)" % "|".join(DelList)
	#for amend in soup.find_all(text=re.compile("42873")):
	count=0
	for item in DelList:
	 for amend in soup.find_all(text=re.compile(str(item))):

		amend.find_parent("tr").decompose()
		count=count+1
		#print(tr)
		#f.write(str(tr))
	#print(count)
	for heading in soup.find_all('h2', {'class' : 'classtitle'}):
		heading.string = "Tenable.io Differential Report"

	for timestamp in soup.find_all('h2',{'class':'date'}):
		timestamp.string = str(datetime.datetime.strftime(datetime.datetime.utcnow(),"%a, %d %b %Y %H:%M:%S UTC"))

	for footerinto in soup.find_all('div',{'id':'copyright'}):
		footerinto.string = "This is a differential report generated by Unisys Corp (C) 2018. For internal purposes only"

	#Diff_filename = "Diff_Report_"+ filenametimestamp +".html"
	Diff_filename = pathname+'\\'+filenametimestamp+"\\"+"Diff_Report_"+ targetIP +".html"
   
	# #****************************************
	info_countd = -1 
	med_countd = -1
	low_countd = -1
	high_countd = -1
	criti_countd = -1
	total_countd = -1
	for counter in soup.find_all('span', {'class':'classtext'}):

	  if(str(counter.string) == "Info"):
		info_countd += 1
	  if(str(counter.string) == "Medium"):
		med_countd += 1
	  if(str(counter.string) == "Low"):
		low_countd += 1
	  if(str(counter.string) == "High"):
		high_countd += 1
	  if(str(counter.string) == "Critical"):
		criti_countd += 1

	print(criti_countd)
	print(high_countd)
	print(med_countd)
	print(low_countd)
	print(info_countd)

	total_countd = criti_countd + high_countd + med_countd + low_countd + info_countd
	print(total_countd)
	if(total_countd==0):
	 for amend in soup.find_all(text=re.compile('Severity')):

	  amend.find_parent("tr").decompose()
	  
	 for amend in soup.find_all('h2',{'class':'classh1'}):
	  print(amend.text)	
	  if(amend.text=="Details"):
	   amend.decompose()
	for heading in soup.find_all('span',style="color: #263645; font-weight: bold !important;"):
	  if(heading.string==str(total_count)):
	   heading.string=str(total_countd)
	  print(heading)

	for heading in soup.find_all('span',style="color: #357abd; font-weight: bold !important;"):
	  #if(heading.string==str(total_count)):
	  heading.string=str(info_countd)
	  print(heading)

	for heading in soup.find_all('span',style="color: #4cae4c; font-weight: bold !important;"):
	  #if(heading.string==str(total_count)):
	  heading.string=str(low_countd)
	  print(heading)

	for heading in soup.find_all('span',style="color: #fdc431; font-weight: bold !important;"):
	  #if(heading.string==str(total_count)):
	  heading.string=str(med_countd)
	  print(heading)

	for heading in soup.find_all('span',style="color: #ee9336; font-weight: bold !important;"):
	  #if(heading.string==str(total_count)):
	  heading.string=str(high_countd)
	  print(heading)

	for heading in soup.find_all('span',style="color: #d43f3a; font-weight: bold !important;"):
	  #if(heading.string==str(total_count)):
	  heading.string=str(criti_countd)
	  print(heading)

	#**********************************************************  
	if not DelList:
	 print('First Scan , diff report same as full report, do not download the diff report.')
	 create_JIRA_issues(filename,newPIDlist)
	else:
	 with open(Diff_filename, "w+") as out_file:
	  out_file.write(str(soup))
	  create_JIRA_issues(Diff_filename,newPIDlist)

	
def assign_JIRA_priority(issue_priority_text):
   switcher = {
                "Critical": 1, 
                "High": 2, 
                "Medium": 3,
                "Low": 4, 
                "Info": 5  
               }
   return switcher.get(issue_priority_text,5)
	
def create_JIRA_issues(Diff_filename,newPIDlist):
  print('Creating JIRA bugs...')
  username_password = args['username'] + ":" + args['password']
  encoded_bytes = base64.b64encode(username_password.encode('utf-8'))
  base64Cred = encoded_bytes.decode('ASCII')
  encoded_output = "Basic " + base64Cred
  print(encoded_output)   
  api_head = { "Content-Type": "application/json", "Authorization": encoded_output}
  create_bug_URL = "https://ustr-erl-8260.na.uis.unisys.com:8443/rest/api/2/issue"

  with open(Diff_filename) as in_file:
    html_text = in_file.read()
    soup = BeautifulSoup(html_text,"html.parser")

  for issue in newPIDlist :

      for issue_tag in soup.find_all(text=re.compile(str(issue))):
        issue_row = issue_tag.find_parent("tr")
        issue_cells = issue_row.findChildren("td")

        issue_summary = issue_cells[2].string
        issue_priority_text = issue_cells[0].string
        #issue_pID = str(re.sub( '\s+', ' ', issue_cells[1].getText()).strip())

        issue_priority = assign_JIRA_priority(issue_priority_text)
        #issue_description = issue_summary+"\n"+"https://www.tenable.com/plugins/nessus/"+issue_pID
        issue_description = issue_summary+"\n"+"https://www.tenable.com/plugins/nessus/"+str(issue)
        input_contents = {
          "fields": {
            "project":
            {
            "key": args['projectKey']
            },
            "summary": issue_summary,
            "description": issue_description,
            "assignee":
             {
              "name": args['assigneeName']
             },
            "issuetype": 
            {
              "name": "Bug"
            },
            "priority": 
            {
              "id": str(issue_priority)
            }
          }
        }
        requests.post(create_bug_URL,data= json.dumps(input_contents), headers=api_head, verify=False)

 
# Main method : starting point of execution of the script
if __name__ == '__main__':
    
	#If task is create , Create a fresh scan , launch the scan and download the report. 
	if(args['task'] == "create"):
	 create_scan(args['scanName'],args['templateName'],args['scannerName'],args['targetIP'],args['notificationEmail'])
    
	#if task is launch , directly launch an already created scan by giving its name.
	elif(args['task'] == "launch"):
	 launchScan_Name(args['scanName'])
	