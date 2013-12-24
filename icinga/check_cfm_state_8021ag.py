#!/usr/bin/python

# Copyright (c) 2013, Erik Ruiter, SURFsara BV, Amsterdam, The Netherlands
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions 
# and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions 
# and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR 
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
# OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Inciga and/or Nagios script for monitoring Ethernet OAM CCM status 
using standardized 802.1ag IEEE8021-CFM-MIB.
This has been tested for Overture ISG24.
"""

import sys
import netsnmp
from optparse import OptionParser
from collections import defaultdict

MEPPortStatus = {'0' : 'psNoPortStateTLV', '1' : 'psBlocked', '2' : 'psUp'}
MEPInterfaceStatus = {'0' : '0', '1' : 'isUp', '2' : 'isDown', '3' : 'isTesting', '4' : 'isUnknown', '5' : 'isDormant', '6' : 'isNotPresent', '7' : 'isLowerLayerDown'}


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

        # Retreive CFM MD data

        Mdlist = defaultdict(dict)
        MdEntry = snmp_walk(options, host, 'dot1agCfmMd')
        for var in MdEntry:
                Mdlist[var.iid].update({var.tag.replace("dot1agCfmMd", "") : var.val})

        # Retreive CFM MA data

        Malist = defaultdict(dict)
        MaEntry = snmp_walk(options, host, 'dot1agCfmMa')
        for var in MaEntry:
                Malist[var.iid].update({var.tag.replace("dot1agCfmMa", "") : var.val})

        # Retreive Remote MEP data

        MEPlist= defaultdict(dict)
        MEPEntry = snmp_walk(options, host, 'dot1agCfmMepDbTable')
        for var in MEPEntry:
                MEPlist[var.iid].update({var.tag.replace("dot1agCfmMepDb", ""):var.val})
	
        # Merge required MD and MA data into the MEPlist dictionary, and do parsing for some elements     

        for var in MEPlist:
		leafindexes = var.split('.')
                MdIndex = leafindexes[0]
		MaIndex = leafindexes[1]
		MEPlist[var]['Id'] = leafindexes[3]
		MEPlist[var]['MdLevel'] = Mdlist[MdIndex].get('MdLevel')
                MEPlist[var]['MdName'] = Mdlist[MdIndex].get('Name')
        	MEPlist[var]['NetName'] = Malist[MdIndex + '.' + MaIndex].get('NetName').strip()
                MEPlist[var]['MAIDString'] = "{0}_{1}".format(MEPlist[var]['MdName'] , MEPlist[var]['NetName'])
		MEPlist[var]['MAIDString'] = MEPlist[var]['MAIDString'].replace('\x00',"")
                #MEPlist[var]['PortStatusTlv'] = MEPPortStatus[MEPlist[var]['PortStatusTlv']]
                #MEPlist[var]['InterfaceStatusTlv'] = MEPInterfaceStatus[MEPlist[var]['InterfaceStatusTlv']]
		MEPlist[var]['ErrorMessage']=""
		MEPlist[var]['IcingaState']=""

	return MEPlist


def checkMEP_CCM(mepEntry):
        """
        Checks a entry from the MEP Dictionary and returns 1 if there are any CCM errors detected. 
        Output for Icinga / Nagios is generated and printed. 
        """

        if mepEntry['Rdi'] <> '2': mepEntry['ErrorMessage'] += " -- RDI Error Detected!"
        if mepEntry['RMepState'] <> '4': mepEntry['ErrorMessage'] += " -- Remote MEP State Error Detected!"
        if (int(mepEntry['PortStatusTlv']) == 1) | (int(mepEntry['InterfaceStatusTlv']) > 1) :
                mepEntry['ErrorMessage'] += " -- PortStatus: " + MEPPortStatus[mepEntry['PortStatusTlv']] + " InterfaceStatusTlv: " + MEPInterfaceStatus[mepEntry['InterfaceStatusTlv']]
        
	if len(mepEntry['ErrorMessage']) > 0:
                ErrorState = 1
                mepEntry['IcingaState'] = "WARNING"
        else:
                ErrorState = 0
                mepEntry['IcingaState'] = "OK"

        print 'Remote MEP {0:<4} {1} - Level {2} MAID: {3:<20} {4}'.format(
                                                                        mepEntry['Id'],
                                                                        mepEntry['IcingaState'],
                                                                        mepEntry['MdLevel'],
                                                                        mepEntry['MAIDString'],
                                                                        mepEntry['ErrorMessage'])
        return ErrorState


def main():
	"""
	Main function for check_cfm_state_8021ag.py 
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
				if MEPDict[var].get('Id') == i:	
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
