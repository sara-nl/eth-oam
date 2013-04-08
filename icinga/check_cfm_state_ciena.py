#!/usr/bin/python

"""
Inciga and/or Nagios script for monitoring Ethernet OAM CCM status for Ciena 3960 using SNMP
"""

import sys
import netsnmp
from optparse import OptionParser
from collections import defaultdict

MEPAdminState = {'1' : 'disabled', '2' : 'enabled'}
MEPOperState = {'1' : 'disabled', '2' : 'enabled', '3' : 'hold', '4' : 'holdLocked'}

# Parse and check arguments
def buildParser():
	"""
	Prepare parsing of command line options
	"""

	parser = OptionParser("usage: %prog [options] hostname")

	parser.add_option("-v", "--version", 
			  type='choice',
		      	  dest="version",
		 	  choices=['1','2'],
		  	  default='1',
                  	  help="Use specific SNMP version default = 1",
		  	  metavar="SNMP_VERSION")
	parser.add_option("-p", "--port", 
		    	  dest="port", 
		  	  default='161',
                  	  help="SNMP port default = 161", 
		  	  metavar="PORT")
	parser.add_option("-c", "--community", 
		  	  dest="community",
                  	  help="SNMP community", 
		  	  metavar="COMMUNITY")
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

def snmp_walk(options,host,oid):
	"""
	Does a snmp walk and returns the results
	"""

	var = netsnmp.VarList(netsnmp.Varbind(oid)) 
	res = netsnmp.snmpwalk( var,
				Version = int(options.version),
				RemotePort=int(options.port),
				DestHost=host,
				Retries=5,
				Timeout=400000,
 				Community=options.community)
	return var 


def buildMEPDictionary(options,host):
	"""
	This function performs snmpwalks to generate a dictionary of the RemoteMEP table from the Ciena MIB.
	Some entries are parsed before the dictionary is returned.
	"""

        # Retreive CFM Service data

        Servicelist = defaultdict(dict)
        ServiceEntry = snmp_walk(options, host, 'wwpLeosCfmServiceEntry')
        for var in ServiceEntry:
                Servicelist[var.iid].update({var.tag.replace("wwpLeosCfmService", "") : var.val})

        # Retreive Remote MEP data

        MEPlist= defaultdict(dict)
        MEPEntry = snmp_walk(options, host, 'wwpLeosCfmRemoteMEPEntry')
        for var in MEPEntry:
                MEPlist[var.iid].update({var.tag.replace("wwpLeosCfmRemoteMEP", ""):var.val})

        # Merge required Service data into the MEPlist dictionary, and do parsing for some elements     

        for var in MEPlist:
                serviceIndex=var[:var.find('.')]
                CFMMaid = Servicelist[serviceIndex].get('CfmMAID')
                MdStrLen = ord(CFMMaid[1])
                MEPlist[var]['MAIDString'] = CFMMaid[2:MdStrLen+2] + "_" + Servicelist[serviceIndex].get('CfmMaintAssocName')
                MEPlist[var]['MdLevel'] = Servicelist[serviceIndex].get('MdLevel')
                MEPlist[var]['ErrorMessage']=""
                MEPlist[var]['AdminState'] = MEPAdminState[MEPlist[var]['AdminState']]
                MEPlist[var]['OperState'] = MEPOperState[MEPlist[var]['OperState']]
		MEPlist[var]['IcingaState']=""

	return MEPlist


def checkMEP_CCM(mepEntry):
        """
        Checks a entry from the MEP Dictionary and returns 1 if there are any CCM errorflags detected.
        Output for Icinga / Nagios is generated and printed.
        """

        if mepEntry['FailureFlag'] == '1': mepEntry['ErrorMessage'] += " -- Failure Error Detected!"
        if mepEntry['CCMErrorFlag'] == '1': mepEntry['ErrorMessage'] += " -- CCM Error Detected!"
        if mepEntry['RDIErrorFlag'] == '1': mepEntry['ErrorMessage'] += " -- RDI Error Detected!"
        if (mepEntry['AdminState'] <> 'enabled') | (mepEntry['OperState'] <> 'enabled') :
                mepEntry['ErrorMessage'] += " -- WARNING AdminState: " + mepEntry['AdminState'] + " OperState: " + mepEntry['OperState']
        if len(mepEntry['ErrorMessage']) > 0:
                ErrorState = 1
                mepEntry['IcingaState'] = "WARNING"
        else:
                ErrorState = 0
                mepEntry['IcingaState'] = "OK"

        print 'MEP {0:<4} {1} - Level: {2} MAID: {3:<20} {4}'.format(
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
				print 'MEP {0:<4} NO DATA'.format(i)
				ErrorState = 1
	
	# Exit with value to inform Nagios / Icinga

	sys.exit(ErrorState)

if __name__ == "__main__":
    main()
