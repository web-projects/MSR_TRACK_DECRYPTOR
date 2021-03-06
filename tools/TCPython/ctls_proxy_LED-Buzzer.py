#!/usr/bin/python3

'''
Created on 15-11-2012

@author: Tomasz_S1
'''

import binascii
import time

from testharness import *
from testharness.tlvparser import TLVParser,tagStorage
from sys import exit
from testharness.syslog import getSyslog

from testharness.tlvparser import TLVPrepare


def Tags2Array(tags):
	tlvp = TLVPrepare()
	arr = tlvp.prepare_packet_from_tags(tags)
	del arr[0]
	return arr

def SendPassThruPacket(conn, cmd, tags):
	tlvp = TLVPrepare()
	packet = tlvp.prepare_packet_from_tags(tags)
	packet[0] = cmd		# cmd code


	passThruTags = [
		[ (0xdf, 0x1f), [0x30] ],		# POS timeout		
		[ (0xdf, 0xc0, 0x59), packet ]
	]		
	passThruTmpl = ( 0xe0, passThruTags )

	# send pass thru packet
	conn.send([0xc0, 0xf8, 0x03, 0x00], passThruTmpl)


def transtest_function():
	log = getSyslog()
	conn = connection.Connection();
	
	#
	# !!! NOTE: Now you can set connection parameters from command line!
	#
	#Create ssl server
	#conn.connect_serial('COM1', 57600, timeout=2 );
	
	req_unsolicited = conn.connect()
	if req_unsolicited:
		#Receive unsolicited
		status, buf, uns = conn.receive()
		if status != 0x9000:
			log.logerr('Unsolicited fail')
			exit(-1)
		log.log('Unsolicited', TLVParser(buf) )

	#Send INIT contactless
	conn.send([0xc0, 0x01, 0x00, 0x00])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('ctls init fail')
		exit(-1)


	#####################################################
	# Get handle
	conn.send([0xc0, 0xf8, 0x01, 0x00])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Get handle fail', hex(status), buf)
		exit(-1)

	tlv = TLVParser(buf)
	cicappHandle = tlv.getTag((0xdf,0xc0,0x01), TLVParser.CONVERT_INT)[0]
	log.log('Handle=', hex(cicappHandle))

	#####################################################
	# Force proxy mode
	conn.send([0xc0, 0xf8, 0x02, 0x01])
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Control proxy mode fail', hex(status), buf)
		exit(-1)


	#####################################################
	# Send 'PassThruEnable'
	passThruCtlTags = [
		[ (0xdf, 0xc0, 0x01), [cicappHandle] ],
		[ (0xdf, 0x1f), [0x30] ],		# POS timeout
		[ (0xdf, 0xc0, 0x40), [0x01] ]
	]
	SendPassThruPacket(conn, 220, passThruCtlTags)
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Send pass-thru fail', hex(status), buf)
		exit(-1)


	#####################################################
	# Send 'ControlUI'
	log.log('Enable LEDs')
	
	controlUI = [
		[ (0xdf, 0xc0, 0x01), [cicappHandle] ],
		[ (0xdf, 0x1f), [0x30] ],		# POS timeout
		[ (0xdf, 0xc0, 0x18), [0xff] ],	# All LED's on
		[ (0xdf, 0x0c), [0x01] ]	# Buzzer - success/single beep
	]

	# 222=ControlUI
	SendPassThruPacket(conn, 222, controlUI)
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Send pass-thru fail', hex(status), buf)
		exit(-1)
	
	
	time.sleep(1)
	
	#####################################################
	# Send 'ControlUI'
	log.log('Change LEDs')
	
	controlUI = [
		[ (0xdf, 0xc0, 0x01), [cicappHandle] ],
		[ (0xdf, 0x1f), [0x30] ],		# POS timeout
		[ (0xdf, 0xc0, 0x18), [0x04] ]	# 3rd LED on
	]
		
	# 222=ControlUI
	SendPassThruPacket(conn, 222, controlUI)
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Send pass-thru fail', hex(status), buf)
		exit(-1)
		
		
	time.sleep(1)
			
	#####################################################
	# Send 'ControlUI'
	log.log('Change LEDs')
	
	controlUI = [
		[ (0xdf, 0xc0, 0x01), [cicappHandle] ],
		[ (0xdf, 0x1f), [0x30] ],		# POS timeout
		[ (0xdf, 0xc0, 0x18), [0x0a] ],	# 2nd & 4th LED on
		[ (0xdf, 0x0c), [0x02] ]	# Buzzer - error/double beep
	]
		
	# 222=ControlUI
	SendPassThruPacket(conn, 222, controlUI)
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Send pass-thru fail', hex(status), buf)
		exit(-1)
			
			
	time.sleep(1)
					
			
	#####################################################
	# Send 'ControlUI'
	log.log('Disable LEDs')
	
	controlUI = [
		[ (0xdf, 0xc0, 0x01), [cicappHandle] ],
		[ (0xdf, 0x1f), [0x30] ],		# POS timeout
		[ (0xdf, 0xc0, 0x18), [0x00] ]	# All LED's off
	]
		
	# 222=ControlUI
	SendPassThruPacket(conn, 222, controlUI)
	status, buf, uns = conn.receive()
	if status != 0x9000:
		log.logerr('Send pass-thru fail', hex(status), buf)
		exit(-1)
			


if __name__ == '__main__':
	utility.register_testharness_script(transtest_function)
	utility.do_testharness()
