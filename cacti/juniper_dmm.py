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
Python script used for retrieving eth-oam data from Junos devices using netconf
"""

import sys
from optparse import OptionParser
from collections import defaultdict
from ncclient import manager
from ncclient.xml_ import *
from ncclient import transport
import xml.etree.ElementTree as ET

# Location of NETconf Authentication file:
netconf_auth="/usr/share/cacti/resource/script_queries/netconf_auth"

def buildDMMDictionary(host,port,username,password):
	"""
	This function performs Netconf calls to generate a dictionary of the RemoteMEP table from the Ciena MIB.
	Some entries are parsed before the dictionary is returned.
	"""
	DMMlist= defaultdict(dict)

	# Try to connect to the remote host
	# Warning: Host keys in known_host file are not verfied by default! (adjust hostkey_verify=True to override)
	try:
		conn = manager.connect(host=host, port=port, username=username, password=password,hostkey_verify=False) 
	except transport.AuthenticationError:
		print "unable to connect [" + host + "], wrong username or password?"
		quit()
	except transport.SSHUnknownHostError:
		print "Unknown host key for [" + host + "]"
		quit()
	except transport.SSHError:
		print "SSH unreachable for [" + host + "]"
		quit()
	

	# Get CFM related information using netconf call
	root_filter = new_ele('filter')
 	config_filter = sub_ele(root_filter, 'configuration')
 	protocol_filter = sub_ele(config_filter, 'protocols')
	oam_filter = sub_ele(protocol_filter, 'oam')
	ethernet_filter = sub_ele(oam_filter, 'ethernet')
	cfm_filter = sub_ele(ethernet_filter, 'connectivity-fault-management')
	filtered_result = conn.get_config('running', filter=root_filter)
	iterators = filtered_result.xpath('data/configuration/protocols/oam/ethernet/connectivity-fault-management/performance-monitoring/sla-iterator-profiles')
	for i in iterators:
		if i.tag == "sla-iterator-profiles":
			itername = i.xpath('name')[0].text
			itertype = i.xpath('measurement-type')[0].text
			
	domains = filtered_result.xpath('data/configuration/protocols/oam/ethernet/connectivity-fault-management/maintenance-domain')	
	
	# Retrieve all Ethernet OAM configuration settings by iterating through the configuration tree
	for i in domains:
		remotemepid=""
		remotemepiter=""
		mdname=""
		maname=""
		mepid=""

		if i.tag == "maintenance-domain":					# Find Maintenance Domains
			mdname = i.xpath('name')[0].text				
			matree = i.xpath('maintenance-association')
			for ma in matree:	
				if len(ma.xpath('name')) > 0 :				# Find Maintenance Associations
					maname = ma.xpath('name')[0].text
				meptree = ma.xpath('mep')					
				for mep in meptree:							
					if len(mep.xpath('name')) > 0:			# Find Local MEPs
						mepid = mep.xpath('name')[0].text	
					if len(mep.xpath('remote-mep/name')) > 0 :			# Find Remote MEPs
						remotemepid = mep.xpath('remote-mep/name')[0].text
					if len(mep.xpath('remote-mep/sla-iterator-profile/name')) > 0 :	# Find SLA iterators
						remotemepiter = mep.xpath('remote-mep/sla-iterator-profile/name')[0].text
						DMMlist[mepid].update({"local-mep":mepid})					# Only add CFM information to the list when there is a sla-iterator profile
						DMMlist[mepid].update({"remote-mep":remotemepid})
						DMMlist[mepid].update({"md":mdname})
						DMMlist[mepid].update({"ma":maname})
						DMMlist[mepid].update({"sla-iterator":remotemepiter})

	# Iterate through the list of MEPs with DMM monitoring configured, and retrieve the DMM statistics using a netconf call. 
	for dmm in DMMlist:

		dmmstats = new_ele('get-cfm-iterator-statistics')
		sub_ele(dmmstats,'sla-iterator').text = DMMlist[dmm].get('sla-iterator')
		sub_ele(dmmstats,'maintenance-domain').text = DMMlist[dmm].get('md')
		sub_ele(dmmstats,'maintenance-association').text = DMMlist[dmm].get('ma')
		sub_ele(dmmstats,'local-mep').text = DMMlist[dmm].get('local-mep')
		sub_ele(dmmstats,'remote-mep').text = DMMlist[dmm].get('remote-mep')
		dmmresult = conn.dispatch(dmmstats).tostring
		DMMTree = ET.fromstring(dmmresult)
		
		# Add the results to the list entry.
		for elem in DMMTree.iter():
			if elem.tag == "cfm-average-twoway-delay": DMMlist[dmm].update({"delay":elem.text})
			if elem.tag == "cfm-average-twoway-delay-variation": DMMlist[dmm].update({"jitter":elem.text})
		 
	return DMMlist	
	
def main():
	"""
	Main function for juniper_dmm.py 
	"""
	# Define Cacti output delimeter
	output_delimeter = "!"	

	# Read and parse the netconf_auth file
	hostfound = False
	hostname = sys.argv[1]
	hosts=[]
	with open(netconf_auth, 'r') as f:
		read_data = f.read()
	f.closed
	
	logininfo = read_data.split('\n')
	for line in logininfo:
		login = line.split(':')
		hosts.append(login)
	
	for host in hosts: 
		if host[0] == hostname:
			hostfound = True
			user=host[1]
			passwd=host[2]
			if len(host[3]) == 0: port = 22
			if len(host[3]) > 0: port = host[3]

	if hostfound == False:
		print "No NETconf authentication info found for [" + hostname + "]"
		quit()

	
	#Build teh dictionary of DDM statistics, making use of the command line options
	DMMDict = buildDMMDictionary(sys.argv[1],port,user,passwd)

	# Cacti requires index, query and get commands to be implemented as command line options, to be able to retrieve data from scripts
	
	# Implement index command
	if sys.argv[2] == 'index':
		for dmm in DMMDict:
			print dmm

	# Implement query command
	if sys.argv[2] == 'query' and sys.argv[3] == 'index':
		for dmm in DMMDict:
			print dmm + output_delimeter + DMMDict[dmm].get('local-mep')

	if sys.argv[2] == 'query' and sys.argv[3] == 'delay':
		for dmm in DMMDict:
			print dmm + output_delimeter + DMMDict[dmm].get('delay')

	if sys.argv[2] == 'query' and sys.argv[3] == 'jitter':
		for dmm in DMMDict:
			print dmm + output_delimeter + DMMDict[dmm].get('jitter')

	if sys.argv[2] == 'query' and sys.argv[3] == 'mepinfo':
		for dmm in DMMDict:
			print dmm + output_delimeter + DMMDict[dmm].get('md') + "_" + DMMDict[dmm].get('ma') + "_" + DMMDict[dmm].get('local-mep') + "_" + DMMDict[dmm].get('remote-mep')

	# Implement get command
	if sys.argv[2] == 'get' and sys.argv[3] == 'delay':
		index = sys.argv[4]
		if index in DMMDict.keys():
			print DMMDict[index].get('delay')
	
	if sys.argv[2] == 'get' and sys.argv[3] == 'jitter':
		index = sys.argv[4]
		if index in DMMDict.keys():
			print DMMDict[index].get('jitter')

if __name__ == "__main__":
    main()
