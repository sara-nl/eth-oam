#!/usr/bin/python

"""
Inciga and/or Nagios script for monitoring Ethernet OAM LTR / LTM messages 
Example: sudo ./check_ethtrace.py -i em1.1235 -l 7 -v 1235 --hops 1:2  b0a8.6e0d.2f03
"""

import sys
import subprocess
import string
from optparse import OptionParser

ErrorStateString = { 0: "OK", 1: "WARNING", 2: "CRITICAL"}

# Parse and check arguments
def buildParser():
	"""
	Prepare parsing of command line options
	"""

	parser = OptionParser("usage: %prog [options] destination_MAC")

	parser.add_option("-i", "--interface", 
						dest="interface",
						help="interface to use",
						default="",
						metavar="INTERFACE")
	parser.add_option("-v", "--vlan", 
						dest="vlan", 
						default="",
						help="vlan to query", 
						metavar="VLAN")
	parser.add_option("-l", "--mdlevel", 
						dest="mdlevel",
						default="",
						help="OAM Maintenance Level", 
						metavar="MDLEVEL")
	parser.add_option( "--hops", 
						dest="hops", 
						default='',
						help="Allowed number of hops (number or range eg. 2:3)", 
						metavar="HOPS")
	parser.add_option("--mac_path",
						dest="mac_path",
						default='',
						help="Specified trace path (use comma separated mac addresses)",
						metavar="MACPATH")
	return parser

def main():
	"""
	Main function for check_ethtrace.py 
	"""
	
	ErrorState=0
	ErrorMsg=""
	minmaxhopsused = False

	# Parse options and arguments
	parser = buildParser()
	(options, args) = parser.parse_args()
	
	if len(args) == 0:				
		print "No destination MAC specified --exiting"
		quit()
	if len(options.interface) == 0:
		print "No interface specified --exiting"		
		quit()
	if len(options.hops) > 0 and options.hops.count(":") > 0:
		minhopcount = options.hops.split(":")[0]
		maxhopcount = options.hops.split(":")[1]
		minmaxhopsused = True
		if minhopcount.isdigit() == False or maxhopcount.isdigit() == False:
			print "Unable to parse hops option"
			quit()
	else:
		if len(options.hops) > 0 and options.hops.isdigit() == False:
			print "Unable to parse hops option"
			quit()
	
	# prepare and generate system call for executing ethping
	call = ["/usr/local/bin/ethtrace","-i",options.interface]
	if len(options.vlan) > 0:			# append vlan option
		call.append("-v")
		call.append(options.vlan)
	if len(options.mdlevel) > 0:		# append mdlevel option
		call.append("-l")
		call.append(options.mdlevel)

	call.append(args[0])				# append destination MAC address
	
	ret = ""
	try:								# execute trace call, and report execution problems
		ret = subprocess.check_output(call)
	except subprocess.CalledProcessError:
		ErrorState=1
		ErrorMsg="-- Execution problem "

	# parse mac address, trace id and mac address, and determine the highest trace id, because this id contains the only interesting results
	maxid = 0
	hops = 0
	tracedata = []
	tracepathstring = ""

	result = ret.split('\n')
	for i in result:
		if i.count('reply from') > 0:
			idIndex = i.find('id=') + 3			
			id = i[idIndex:idIndex+10]				# Find ID of the trace
			ttlIndex = i.find('ttl=') +4
			ttl = i[ttlIndex:ttlIndex+1]			# find ttl number of hop
			macIndex = i.find('reply from') + 11
			mac = i[macIndex:macIndex+17]			# find MAC address of hop
			if maxid < id: maxid = id 				# Find the highest ID of the trace, its the only interesting one
			tracedata.append([id, ttl, mac])		# append trace results to a list
			
	if len(tracedata) == 0:	
		ErrorState = 1
		ErrorMsg = ErrorMsg + "-- No replies received "

	else:				# Build a string out of the trace data list
		for data in tracedata:
			if data[0] == maxid:
				hops = hops + 1
				tracepathstring = tracepathstring + data[2] + ","
		tracepathstring = tracepathstring[:-1]
		
		# Check MAC path option
		if len(options.mac_path) > 0:
			if  tracepathstring <> options.mac_path:
				ErrorState = 1
				ErrorMsg = ErrorMsg + "-- Wrong path detected (configured: " + options.mac_path + "  detected: " + tracepathstring + ")"

		# check the hop count option
		if len(options.hops) > 0 and minmaxhopsused == True:
			if hops < int(minhopcount) or hops > int(maxhopcount):
				ErrorState = 1
				ErrorMsg = ErrorMsg + "-- Invalid hop count (configured: " + options.hops + "  detected: " + str(hops) + ")"
		else:
			if len(options.hops) > 0  and hops <> int(options.hops):
				ErrorState = 1
				ErrorMsg = ErrorMsg + "-- Invalid hop count (configured: " + options.hops + " detected: " + str(hops) + ")"


	# print output			
	print "ETHTRACE {0} {1} - hops = {2} {3}".format(args[0], ErrorStateString[ErrorState], hops, ErrorMsg)
 
	# Exit with value to inform Nagios / Icinga
	sys.exit(ErrorState)
	

if __name__ == "__main__":
    main()
