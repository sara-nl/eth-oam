#!/usr/bin/python

"""
Inciga and/or Nagios script for monitoring Ethernet OAM CCM status for Juniper EX (+MX) using Netconf
"""

import sys
import netsnmp
from optparse import OptionParser
from collections import defaultdict
from ncclient import manager
from ncclient.xml_ import *
from ncclient import transport
import xml.etree.ElementTree as ET

MEPAdminState = {'1' : 'disabled', '2' : 'enabled'}
MEPOperState = {'1' : 'disabled', '2' : 'enabled', '3' : 'hold', '4' : 'holdLocked'}

# Parse and check arguments
def buildParser():
	"""
	Prepare parsing of command line options
	"""

	parser = OptionParser("usage: %prog [options] hostname")

	parser.add_option("-P", "--port", 
		    	  dest="port", 
		  	  default='22',
                  	  help="NETconf port default = 22", 
		  	  metavar="PORT")
	parser.add_option("-u", "--username", 
		   	  dest="username", 
		  	  default='',
                  	  help="ssh username", 
		  	  metavar="USERNAME")
	parser.add_option("-p", "--password", 
		   	  dest="password", 
		  	  default='',
                  	  help="ssh password (can be ommited when using remote ssh key)", 
		  	  metavar="password")
	parser.add_option("-t", "--type",
		  	  type='choice', 
		  	  dest="type", 
		  	  choices=['CCM', 'DMM', 'LMM'],
		  	  default='CCM',
                  	  help="monitor packet type, can be CCM/DMM/LMM, default=CCM", 
		  	  metavar="TYPE")
	parser.add_option("-m", "--mep", 
		  	  dest="mep", 
			  default='',
                  	  help="comma separated list to specify remote MEPs to monitor, (all = all available MEPs)", 
		 	  metavar="LIST")
	return parser


  

def buildMEPDictionary(options,host):
	"""
	This function performs snmpwalks to generate a dictionary of the RemoteMEP table from the Ciena MIB.
	Some entries are parsed before the dictionary is returned.
	"""
	MEPlist= defaultdict(dict)

	# Try to connect to the remote host
	
	try:
		conn = manager.connect(host=host, port=options.port, username=options.username, password=options.password) 
	except transport.AuthenticationError:
		print "unable to connect, wrong username or password?"
		quit()
	except transport.SSHError:
		print "SSH unreachable"
		quit()
	

	# Get remote meps using netconf call
	
	cfminfo = new_ele('get-cfm-interface')
	sub_ele(cfminfo, 'detail').text=""
	result = conn.dispatch(cfminfo).tostring
	CFMInterfaceTree = ET.fromstring(result)
	for elem in CFMInterfaceTree.iter():
		if elem.tag == "cfm-remote-mep-identifier":
			MEPlist[elem.text].update({"ID":elem.text})
	
	#Retrieve detaild intformation about the remote MEPs and store them in the MEPlist		
	
	for mep in MEPlist:
		cfmdatabase = new_ele('get-cfm-mep-database-information')
		sub_ele(cfmdatabase,'remote-mep').text = mep
		mepresult = conn.dispatch(cfmdatabase).tostring
		MEPTree = ET.fromstring(mepresult)
		for elem in MEPTree.iter():
			if elem.tag == "cfm-maintenance-domain-name": MEPlist[mep].update({"Md":elem.text})
			if elem.tag == "cfm-maintenance-association-name": MEPlist[mep].update({"Ma":elem.text})
			if elem.tag == "cfm-level": MEPlist[mep].update({"MdLevel":elem.text})
			if elem.tag == "cfm-remote-mep-mac-address": MEPlist[mep].update({"MacAddr":elem.text})
			if elem.tag == "cfm-local-mep-identifier": MEPlist[mep].update({"localMEP":elem.text})
			if elem.tag == "cfm-remote-mep-state": MEPlist[mep].update({"FailureFlag":elem.text})
			
			if elem.tag == "cfm-remote-mep-rdi": MEPlist[mep].update({"RDIErrorFlag":elem.text})
			if elem.tag == "cfm-remote-mep-port-status-tlv": MEPlist[mep].update({"AdminState":elem.text})
			if elem.tag == "cfm-remote-mep-interface-status-tlv": MEPlist[mep].update({"OperState":elem.text})
			
		MEPlist[mep].update({"MAIDString":MEPlist[mep].get('Md')+"_"+ MEPlist[mep].get('Ma')})
		MEPlist[mep].update({"CCMErrorFlag":0})
		MEPlist[mep].update({"ErrorMessage":""})
	print MEPlist	 
	return MEPlist	
	
def checkMEP_CCM(mepEntry):
        """
        Checks a entry from the MEP Dictionary and returns 1 if there are any CCM errorflags detected.
        Output for Icinga / Nagios is generated and printed.
        """

        if mepEntry['FailureFlag'] <> 'ok': mepEntry['ErrorMessage'] += " -- Failure Error Detected!"
        if mepEntry['CCMErrorFlag'] == '1': mepEntry['ErrorMessage'] += " -- CCM Error Detected!"
        if mepEntry['RDIErrorFlag'] == 'true': mepEntry['ErrorMessage'] += " -- RDI Error Detected!"
        if ((int(mepEntry['AdminState']) == 1)) | ((int(mepEntry['OperState']) <> 0) & (int(mepEntry['OperState']) <> 2))  :
                mepEntry['ErrorMessage'] += " -- WARNING AdminState: " + MEPAdminState[mepEntry['AdminState']] + " OperState: " + MEPOperState[mepEntry['OperState']]
        if len(mepEntry['ErrorMessage']) > 0:
                ErrorState = 1
                mepEntry['IcingaState'] = "WARNING"
        else:
                ErrorState = 0
                mepEntry['IcingaState'] = "OK"

        print 'Remote MEP {0:<4} {1} - Level: {2} MAID: {3:<20} {4}'.format(
                                                                        mepEntry['ID'],
                                                                        mepEntry['IcingaState'],
                                                                        mepEntry['MdLevel'],
                                                                        mepEntry['MAIDString'],
                                                                        mepEntry['ErrorMessage'])
        return ErrorState


def main():
	"""
	Main function for check_cfm_state.py 
	"""
	
	ErrorState=0
	# Parse options and arguments

	parser = buildParser()
	(options, args) = parser.parse_args()
	
	if len(args) == 0:
        	print "No hostname specified --exiting"
        	quit()
	if len(options.mep) == 0:
		print "No remote MEP specified --exiting"		
		quit()
	if len(options.username) == 0:
		print "No username specified --exiting"		
		quit()
	
	# build a list of all meps to be monitored

	mepFilterList=[]
	if options.mep == 'all': mepFilterList.append('all')
	else :
		mepFilterList = options.mep.split(',')
	
	# retreive Remote MEP data

	MEPDict = buildMEPDictionary(options,args[0])

	
	# Perform CCM checks

	if mepFilterList[0] == 'all': 
		for i in MEPDict: 
			result = checkMEP_CCM(MEPDict[i])
			if result == 1 : ErrorState = 1
	else:	
		for i in mepFilterList:
			mepFound = False
			for var in MEPDict:
				if MEPDict[var].get('ID') == i:	
					mepFound = True
					result = checkMEP_CCM(MEPDict[var])
					if result == 1: ErrorState = 1
			if mepFound == False:
				print 'Remote MEP {0:<4} NO DATA'.format(i)
				ErrorState = 1
	
	# Exit with value to inform Nagios / Icinga

	sys.exit(ErrorState)

if __name__ == "__main__":
    main()
