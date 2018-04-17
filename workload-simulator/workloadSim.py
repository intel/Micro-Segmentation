##############################################################################
#  Copyright (c) 2018 Intel Corporation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##############################################################################
#    Author: Patrick Kutch
##############################################################################
#    Abstract: 
#    This utility sends data to other instances of this same application.  Design
#    is such that there is an 'originator' and 1 or more links in a chain.  UDP 
#    packets are sent along the chain until the last link, then sent back along
#    the chain to the original originator.  The links along the way know nothing
#    about the next hop, rather when you run this application as originator you
#    specify the ip:port of each link in the chain and that info is sent in the payload.
#
#    originator-->hop 1 --> hop 2 --> ... --> hop n --> hop n-1 --> ... --> hop 2 --> hop 1 --> originator
#    when the packet reaches back to the orginator, the time taken for each hop is printed.
#
#    You can specify an input file to be inserted as the payload.  This payload
#    will remain along the whole chain, unless a link along the chain specifies
#    a new file.  Could be useful for some interesting tests/demos.
#
#    You can also 'mirror' at any link, send a copy of the packets to an additional
#    destination.
#
#   Should work for both python3 and python2
#
#   example usage: workloadSim.py 10.10.10.1:1000 10.10.10.2:1000 10.10.10.3:1001 10.10.10.1:1000 10.10.10.3:1001 -i 10.10.10.200:4000
#   this sends from 'this' instance on the local IP of 10.10.10.200 port 4000 to 10.10.10.1 port 1000 then to 10.10.10.2
#   then to 10.10.10.3 then back to 10.10.10.1 and then back to 10.10.10.3 at which point it traverses the same route, just backwards
#
##############################################################################
from __future__ import print_function
from  pprint import pprint
import argparse
import threading
from socket import *
import socket
import os
import logging
import time
import signal
import sys


## how to encode the header data ####
dataTokenStr=","
timestampTokenStr="@"
portTokenStr=":"
TCP_PACKET_DELIMITER_START=chr(2)
TCP_PACKET_DELIMITER_END=chr(3)
PayloadFillChar='*'
maxBufferSize=15000 #
MAX_RECV_SIZE=4096
SOCKET_TIMEOUT=0.01
CONFIG_SOCKET_NODELAY=True
CONFIG_SOCKET_RCV_BUFFER_SIZE=1024
MAX_INACTIVITY_TIME=10000 # 10 secs before closing TCP sockets
minBufferSize=10
verbose=False
delayTime=10
outputFrequency=500
ZERO_TIME_STR="0000000000000000"
resolution_ms=True
minDelayTime=.0001
cpuBurnerDelay=None
cpuBurnerThreadCount=1

BaseVersionStr="1.0"
RelDate="[18.03.29]"
VersionStr= BaseVersionStr + "-" + RelDate

currentID=1
sendErrorCount=0
droppedCount=0
packetsSent=0
packetsRecvd=0
packetsSentCounter=0
packetsRecvCounter=0
stopThreads=False
staticPayload=True
staticPayloadData=None
prefixBuffer=None
postfixBuffer=None
lastOutputTime=0
accumulatedTimes=[]
UseUDP = True
sendFn = None
recvFn = None
sendFnUDP = None
g_receiveSocket = None
g_sendSocket = None
g_mirrorSocket = None
batch=False
batchNumber=0
batchTimeout=0
batchPacketReceived = False
usingFloatingIP = False
floatingInterface = None
interface = None
startTime = None
g_targetMap={}

##########################################################################
#
# wrapper function to sleep
#
def _Sleep(seconds):
    try:
        time.sleep(seconds)
        
    except BaseException as Ex:
        pass

##########################################################################
#
# sleeps for the specified # of milliseconds
#
def SleepMs(milliseconds):
    _Sleep(float(float(milliseconds)/1000.0))

def GetRunningUs():
    global startTime
    if None == startTime:
        startTime = GetCurrUS()
        return 0

    t = GetCurrUS()
    returnVal =  t - startTime
    startTime = t
    return returnVal

##########################################################################
#
# wrapper function to sleep
#
def signal_handler(signal, frame):
    print("Caught Ctrl+C")
    import sys
    global stopThreads
    stopThreads = True
    SleepMs(500)
    g_sendSocket.close()
    g_receiveSocket.close()
    sys.exit()

##########################################################################
#
# Creates the payload to send to the 1st hop - only used if this is the
# originator instance
#
def CreateInitialPayload(localInterface,connections,payloadFile):
    global currentID,maxBufferSize,minBufferSize,maxBufferSize,staticPayload,staticPayloadData,PayloadFillChar

    buffer = format(currentID,'08') + dataTokenStr

    lengthOfLengthStr = 5
    
    currentID += 1
    #print("tx: {0} @{1}".format(currentID,GetRunningUs()))
    

    if None == prefixBuffer:
        CreateInitialPayloadParts(localInterface,connections,payloadFile)

    timeStamp = GetCurrUS()

    if sys.version_info[0] < 3:
        timestampStr=str(long(timeStamp))
    else:
        timestampStr=str(int(timeStamp))
    
    if payloadFile != None and existFile(payloadFile):
        if staticPayload and None != staticPayloadData:
            payload = staticPayloadData

        else:
            file = open(payloadFile,'r')
            payload = str(file.read())
            file.close()
            otherLen = len(prefixBuffer) + len(postfixBuffer) + len(timestampStr) + len(buffer) + lengthOfLengthStr

            while len(payload) + otherLen < minBufferSize:
                payload += PayloadFillChar

            if staticPayload:
                staticPayloadData = payload

    else: #default payload
        if staticPayload and None != staticPayloadData:
            payload = staticPayloadData
        else:
            payload = "Default Good Data Default Good Data Default Good Data Default Good Data Default Good Data Default Good Data END"
            
            otherLen = len(prefixBuffer) + len(postfixBuffer) + len(timestampStr) + len(buffer) + lengthOfLengthStr
            while len(payload) + otherLen < minBufferSize:
                payload += PayloadFillChar
                if staticPayload:
                    staticPayloadData = payload

    mostOfIt = prefixBuffer + timestampStr + postfixBuffer + payload
    
    pktLen = len(buffer) +  len(mostOfIt)
    pktLength ="{0:0>5}".format(pktLen + lengthOfLengthStr)
    pktLen+= len(pktLength)
    if pktLen > maxBufferSize:
        mostOfIt =  mostOfIt[:maxBufferSize -len(buffer) - len(prefixBuffer) - len(str(maxBufferSize))]
        pktLen = len(buffer)  + len(mostOfIt) + len(str(maxBufferSize))
        pktLength = str(pktLen)


    buffer += pktLength + mostOfIt
    
    return buffer

##########################################################################
#
# Lots of the payload from originator doesnt' change, so initialize it
#
def CreateInitialPayloadParts(localInterface,connections,payloadFile):
	global prefixBuffer,postfixBuffer

	prefixBuffer = dataTokenStr + str(len(connections)) + dataTokenStr
	prefixBuffer += 'forward' + dataTokenStr
	prefixBuffer += str(len(connections) ) + dataTokenStr #Hops Left
	prefixBuffer += localInterface + timestampTokenStr 
	
	postfixBuffer = timestampTokenStr + ZERO_TIME_STR + dataTokenStr
	
	for connection in connections: 
		postfixBuffer += connection + timestampTokenStr + ZERO_TIME_STR + timestampTokenStr + ZERO_TIME_STR + dataTokenStr

##########################################################################
#
# Helper routine to check if a file exists
#
def existFile(filename):
    if not os.path.exists(filename):
        print("Specified file: " + str(filename) + " does not exist.")
        return False
    return True

##########################################################################
#
# checks ip:port combinations for legality
#
def ValidateConnections(connectionList):
    global g_sendSocket    
    for index,connection in enumerate(connectionList):
        try:
            ip,port = connection.split(portTokenStr)
            port=int(port)
        except:
            print("Invalid connection point: " + str(connection))
            return False

        try:
            #sendSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            #sendSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            
            if sys.version_info < (3, 0): #python 2
                g_sendSocket.send("")
            else: #python 3
                g_sendSocket.send(bytes("",'utf-8'))

            if False == ip[0].isdigit(): # if passed DNS name, do a DNS resolution and use it in payload rather than DNS name
                try:
                    TargetIP = socket.gethostbyname(ip)
                    connection = TargetIP +":" + str(port)
                    connectionList[index] = connection
                
                except Exception as Ex:
                    pass # was likely a bad bad dns name, or was an IP address to start with

        except Exception as Ex:
            print("Invalid connection point: " + str(connection) + " [" + str(Ex) +"]")
            return False

    return True

##########################################################################
#
# Parses the command line args
#
def HandleCommandlineArguments(description="Workload Simulator - version " + VersionStr):
    global maxBufferSize,minBufferSize,UseUDP,cpuBurnerDelay,cpuBurnerThreadCount,batch,batchNumber,batchTimeout
    global floatingInterface, usingFloatingIP, interface

    parser = argparse.ArgumentParser()
    parser.add_argument("connections",nargs="*")
    parser.add_argument("-p","--payload",help='specifies payload file',type=str)
    parser.add_argument("-s","--size",help='pads payload to make it this size',type=int)
    parser.add_argument("-i","--interface",help='specifies local ip and port to use ip:port',type=str,required=True)
    parser.add_argument("-e","--external",help='specifies floating ip and port to use ip:port, still must have -i for non-floating',type=str,required=False)
    parser.add_argument("-r","--resolution",help='u for microseconds, m for milliseconds, default is m.  only for initiator',type=str)
    parser.add_argument("-f","--frequency",help='specifies the frequency (in ms) the times should be printed (default is 500)',type=str)
    parser.add_argument("-m","--mirror",help='specifies mirror target ip and port to send a copy of the incoming packets to',type=str)
    parser.add_argument("-v","--verbose",help='prints the payload received at last hop',action='store_true')
    parser.add_argument("-d","--delay",help='time (in ms) to wait between sending to 1st hop (only valid for 1st sender)',type=str)
    parser.add_argument("-t","--threads",help='number of processing threads to run (default is 1).  Only vadlid if not 1st sender)',type=int)
    parser.add_argument("-b","--burncpu",help='time (in ms) to wait between cycles in endless loop ',type=str)
    ## Not using batch anymore, and haven't tested since I made a lot of changes, so removing for now
    #parser.add_argument("-a","--batch",help="send data in batches, waiting for response, uses -d as interval in batch. #to-send:timeout",type=str)
    parser.add_argument("-c","--conntype",help='TCP or UDP UDP is Default',type=str)
    
    try:
        args = parser.parse_args()
#           Experiment, need to get back to it
#        if None != args.connections:
#            if False == ValidateConnections(args.connections):
#                return (None,None,None,None)

        #ValidateConnections expects a list
        mirrorList=[args.mirror]
        interfaceList=[args.interface]
        interface = args.interface
        threadCount = 1

        if None != args.external:
            parts = args.external.split(":")
            if len(parts) == 2:
                floatingPort=int(parts[1])
                usingFloatingIP = True
                floatingInterface = args.external
            else:
                print("--external: " + args.external +" is invalid combo form is ip:port")
                return (None,None,None,None,threadCount)

        if None != args.size:
            minBufferSize = args.size
            if maxBufferSize < minBufferSize:
                maxBufferSize = minBufferSize

#        if None != args.batch:
#            parts = args.batch.split(":")
#            try:
#                batchNumber = int(parts[0])
#                batchTimeout = float(parts[1])
#                batch = True
#            except Exception as Ex:
#                print("Invalid Batch parameters: " + args.batch)
#                return (None,None,None,None,threadCount)

        if None != args.threads:
            if args.threads < 1:
                print("Minimum of 1 thread required")
                return (None,None,None,None,threadCount)
            
            threadCount = args.threads

        if None != args.conntype:
            if args.conntype.lower() == 'udp':
                UseUDP = True

            elif args.conntype.lower() == 'tcp':
                UseUDP = False

            else:
                print("Invalid Connection Type specified: " + args.conntype)
                return (None,None,None,None,threadCount)

        #if None != args.mirror:
        #    if False == ValidateConnections(mirrorList):
        #        return (None,None,None,None,threadCount)

        #if False == ValidateConnections(interfaceList):
        #        return (None,None,None,None,threadCount)

        global resolution_ms
        if None == args.resolution or args.resolution=='m':
            resolution_ms=True

        elif args.resolution=='u':
            resolution_ms=False

        else:
            print("resolution option: " + args.resolution +" is invalid, must be m (ms) or u (us)")
            return (None,None,None,None,threadCount)

        global verbose
        verbose = args.verbose

        if None != args.delay:
            global delayTime
            delayTime=float(args.delay)

        if None != args.burncpu:
            if ":" in args.burncpu:
                parts = args.burncpu.split(":")
                if len(parts) == 2:
                    cpuBurnerThreadCount = int(parts[0])
                    cpuBurnerDelay=float(parts[1])
                else:
                    print("cpuburner: " + args.resolution +" is invalid combo form is #threads:delay per thread")
                    return (None,None,None,None,threadCount)

            else:
                cpuBurnerDelay=float(args.burncpu)

        if None != args.frequency: 
            global outputFrequency
            outputFrequency=int(args.frequency)

        if None != args.payload:
            if existFile(args.payload):
                file = open(args.payload,'r')
                payload = str(file.read())
            else:
                print("Error: Payload file " + args.payload + " does not exist.")
                return (None,None,None,None,threadCount)
        else:
            payload=None

        if False == UseUDP and threadCount > 1:
            threadCount = 1
            print("Can't use multiple threads with TCP traffic.  Ignoring")


        return (interfaceList[0],args.connections,args.payload,mirrorList[0],threadCount)
 
    except Exception as ex:
        print(str(ex))

    return (None,None,None,None,threadCount)


##########################################################################
#
# from the dictionary, it creates a byte array
#
def CreatePacket(infoDict,payloadFile):
        pktBuffer=str(infoDict['ID']) + dataTokenStr
        pktBuffer+=str(infoDict['InitialSize']) + dataTokenStr
        pktBuffer+=str(len(infoDict['Connections'])-1)+dataTokenStr
        pktBuffer+=str(infoDict['Direction'])+dataTokenStr
        pktBuffer+=str(infoDict['HopsLeft'])+dataTokenStr
        for connection in infoDict['Connections']:
            pktBuffer+=str(connection) + dataTokenStr

        if None != payloadFile and existFile(payloadFile):
            file = open(payloadFile,'r')
            payload = str(file.read())
            file.close()
            infoDict['Payload'] = payload

        pktBuffer+=infoDict['Payload']

        pktLen = len(pktBuffer)

        return pktBuffer
            
##########################################################################
#
# parses a string into a dictionary
#
def DecodePacket(dataBuffer):
    dataParts = dataBuffer.split(dataTokenStr) 
    partCount = len(dataParts)
    if partCount < 8 :
        Msg = "Bad Buffer: --" + str(dataBuffer) + "--"
        print(Msg)
        return None

    ID = dataParts[0]
    #print("Rx: {0} @{1}".format(ID,GetRunningUs()))
    
    InitialSendSize = dataParts[1]
    HopCount = int(dataParts[2])
    Direction = dataParts[3]
    HopsLeft = int(dataParts[4])
    connections=dataParts[5:HopCount+1+5]
    
    nextIndex=HopCount+1+5

    payload=""

    for chunk in dataParts[nextIndex:]:
        payload += chunk
        nextIndex +=1
        if nextIndex < partCount:
            payload += dataTokenStr # must have been a token in the 'payload' part, so add it back in

    returnDict={}
    returnDict['ID'] = ID
    returnDict['InitialSize'] = InitialSendSize
    returnDict['HopsLeft'] = HopsLeft
    returnDict['HopCount'] = HopCount
    returnDict['Direction'] = Direction
    returnDict['Connections'] = connections
    returnDict['Payload'] = payload

    return returnDict

##########################################################################
#
#  gets current MS since epoch
def GetCurrMS():
    return  round(time.time() *1000.0) # Gives you float secs since epoch, so make it ms and chop

##########################################################################
#
#  gets current MS since epoch
def GetCurrUS():
    return round(time.time() * 1000000.0) # Gives you float secs since epoch, so make it us and chop
##########################################################################
#
# Sets the time the packet was received
#
def SetReceivedTime(connection,direction,timeStamp):
    parts=connection.split(timestampTokenStr)
    target=parts[0]
    timeForward=parts[1]
    timeReturn=parts[2]

    ## Nasty issue - Python2 converts str(int) into 1.2342E notation
    if sys.version_info[0] < 3:
        timestampStr=str(long(timeStamp))
    else:
        timestampStr=str(int(timeStamp))

    if direction=='forward':
        timeForward=timestampStr
    else:
        timeReturn=timestampStr

    return target+timestampTokenStr+timeForward+timestampTokenStr+timeReturn

##########################################################################
#
# processes the incoming packet, decrementing hops, figuring out next hop, etc.
#
def ProcessPacket(recvTime,rcvPacket):
    dataDict = DecodePacket(rcvPacket)
    if None == dataDict:
        return None

    hopsLeft = int(dataDict['HopsLeft'])
    direction = dataDict['Direction']

    connectionCount = int(dataDict['HopCount'])

    if direction == 'forward':
        thisConnectionIndex = connectionCount - hopsLeft + 1 # 1st entry is the originator
        newConnInfo = SetReceivedTime(dataDict['Connections'][thisConnectionIndex],'forward',recvTime)
    else:
        thisConnectionIndex = hopsLeft-1
        newConnInfo = SetReceivedTime(dataDict['Connections'][thisConnectionIndex],'return',recvTime)

    dataDict['Connections'][thisConnectionIndex] = newConnInfo

    hopsLeft -= 1
    if hopsLeft == 0:
       if direction == 'forward':
           direction = 'return ' #pad a space to make same length
           dataDict['Direction']=direction
           newConnInfo = SetReceivedTime(dataDict['Connections'][thisConnectionIndex],'return',recvTime)
           dataDict['Connections'][thisConnectionIndex] = newConnInfo
           hopsLeft = connectionCount
           dataDict['Done'] = False
       else:
          dataDict['Done'] = True

    else:
        dataDict['Done'] = False

    if direction == 'forward':
        nextConnectionIndex = connectionCount - hopsLeft + 1
    else:
        nextConnectionIndex = hopsLeft-1

    nextTargetParts = dataDict['Connections'][nextConnectionIndex].split(timestampTokenStr)
    dataDict['NextTarget']=nextTargetParts[0]

    dataDict['HopsLeft'] = hopsLeft

    return dataDict

##########################################################################
#
# If this is the last hop (goes back to orginator for final time) prints
# the time for the various hops
#
def CalcTripTimes(dataDict,recvLength,verbose=True):
    global accumulatedTimes,outputFrequency,lastOutputTime,resolution_ms

#    if GetCurrMS() - lastOutputTime < outputFrequency:
#       return None	
    roundTripTime=[]
    connections = dataDict['Connections']
    for index,connection in enumerate(connections[:-1]):
        parts = parts=connection.split(timestampTokenStr)
        target=parts[0]
        ## Nasty issue - Python2 converts str(int) into 1.2342E notation
        if sys.version_info[0] < 3:
            timeForward=long(parts[1])
            timeReturn=long(parts[2])
        else:
            timeForward=int(parts[1])
            timeReturn=int(parts[2])
        
        tripTime = timeReturn - timeForward

        if True == resolution_ms:
            tripTime = round(tripTime /1000.0)

        accumulatedTimes[index+1] += tripTime
   
    accumulatedTimes[0] +=1

    if GetCurrMS() - lastOutputTime > outputFrequency:
        accumulatedTimesCount = accumulatedTimes[0]
        infoStr = str(len(connections) -1) +","
        infoStr += format("{0},{1}".format(int(dataDict['InitialSize']),recvLength))
        for hopTime in accumulatedTimes[1:] :
            infoStr += "," 
            if hopTime > 0:
                infoStr +=  str(int(hopTime/accumulatedTimesCount))
                
            else:
                infoStr += '0'

        for index,dummyCon in enumerate(connections):
            accumulatedTimes[index]=0

        lastOutputTime = GetCurrMS()


        #infoStr = str(len(connections) -1) + "," + str(roundTripTime[0]) # num connections,time nop1, hop2,etc.
        #for tripTime in roundTripTime[1:]:
        #    infoStr += "," + str(tripTime) 
    else:
        infoStr = None

    return infoStr

##########################################################################
#
# Simple wrapper to send packet
#
def SendToNextHop(target,dataBuffer):
    return SendPacket(target,dataBuffer)

def SendUDP_Python2(connectionPoint,Packet):
    return SendUDP_Python3(connectionPoint,Packet,False)

def SendUDP_Python3(connectionPoint,Packet,Python3=True):
    if None == connectionPoint:
        return False

    try:
        ip,port = g_targetMap[connectionPoint]
        if True == Python3:
            g_sendSocket.sendto(bytes(Packet,'utf-8'),(ip,port))
        else:
            g_sendSocket.sendto(Packet,(ip,port))

        return True

    except Exception as Ex:
        if not connectionPoint in g_targetMap:
            ip,port = connectionPoint.split(portTokenStr) 
            port=int(port)
            g_targetMap[connectionPoint] = (ip,port)
            return SendUDP_Python3(connectionPoint,Packet,Python3)

        global sendErrorCount
        sendErrorCount += 1

    return False

def SendTCP_Python2(connectionPoint,Packet):
    return SendTCP_Python3(connectionPoint,Packet,False)

def SendTCP_Python3(connectionPoint,Packet,Python3=True):
    if None == connectionPoint:
        return False
    sentSize = 0

    try:
        sendSocket = g_targetMap[connectionPoint]
        Packet = TCP_PACKET_DELIMITER_START + Packet + TCP_PACKET_DELIMITER_END
        try:
            if Python3:
                while sentSize < len(Packet):
                    sentSize += sendSocket.send(bytes(Packet[sentSize:],'utf-8'))
            else: 
                while sentSize < len(Packet):
                    sentSize += sendSocket.send(Packet[sentSize:])

        except socket.error: #likely other end closed
            del(g_targetMap[connectionPoint])
            return False

        return True

    except Exception as Ex:
        if not connectionPoint in g_targetMap:
            ip,port = connectionPoint.split(portTokenStr) 
            port=int(port)
            sendSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sendSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sendSocket.connect((ip,port))
                g_targetMap[connectionPoint] = sendSocket
                return SendTCP_Python3(connectionPoint,Packet,Python3)

            except socket.error as Ex:
                #print("Can't Connect to " + str((ip,port)))
                return False

    except Exception as Ex:
        global sendErrorCount
        sendErrorCount += 1

    return False


    
##########################################################################
#
# wrapper fn to send a packet to an IP:PORT destination
#
def SendPacket(connectionPoint,Packet,count=True):
    global packetsSent,sendFn, g_targetMap
    if None == connectionPoint:
        return

    if len(Packet) > maxBufferSize:
        Packet = Packet[:maxBufferSize] # Truncate if too large

    if True == sendFn(connectionPoint,Packet) and True == count:
        packetsSent += 1
        return True

    return False


##########################################################################
#
# 'Mirrors' the packet to another location - for demo purposes
#
def Mirror(connectionPoint,Packet):
    global g_mirrorSocket
    Python3 = sys.version_info[0] > 2

    if None == connectionPoint:
        return False

    try:
        ip,port = g_targetMap[connectionPoint]
        try:
            if True == Python3:
                g_mirrorSocket.sendto(bytes(Packet,'utf-8'),(ip,port))
            else:
                g_mirrorSocket.sendto(Packet,(ip,port))
        except:
            pass

        return True

    except Exception as Ex:
        if not connectionPoint in g_targetMap:
            ip,port = connectionPoint.split(portTokenStr) 
            port=int(port)
            g_targetMap[connectionPoint] = (ip,port)
            return Mirror(connectionPoint,Packet)

        global sendErrorCount
        sendErrorCount += 1

    return False
    global sendFnUDP
    sendFnUDP(connection,packet)
    

def PrintPacketCount():
    global packetsRecvd,packetsSent,sendErrorCount,packetsSentCounter,packetsRecvCounter,lastOutputTime,droppedCount

    received = packetsRecvd
    sent = packetsSent
    currTime = GetCurrMS()

    tDelta = currTime - lastOutputTime
    pDelta = received - packetsRecvCounter
    if pDelta < 1:
        pDelta = 1

    try:
        rxPPs = int(pDelta / (tDelta/1000.0))
        packetsRecvCounter = received

        pDelta = sent - packetsSentCounter
        if pDelta < 1:
            pDelta = 1
        txPPs = int(pDelta / (tDelta/1000.0))
        packetsSentCounter = sent

        lastOutputTime = currTime

        print("Packets: Rx-" + str(packetsRecvd) +"[" + str(rxPPs)+"] Tx-"+str(packetsSent)  +"[" + str(txPPs) + "] Errors: " + str(sendErrorCount) + " AltSent: " + str(droppedCount) + "\r")

    except Exception as Ex:
        print(str(Ex))
        packetsSentCounter = packetsSent
        packetsRecvCounter = packetsRecvd
        pass

#Debug Routine
def MakeTestString(preString,postString):
    length= len(preString) + len(postString)
    length += len(str(length))
    
    string = preString+str(length)+postString
    return string


def TCP_ReaderProc(recvSocket,payloadFile,mirrorTarget):
    global g_targetMap
    
    currPacket=None

    if sys.version_info[0] < 3:
        python3 = False
    else:
        python3 = True

    recvTime = GetCurrUS()


    # data for testing
    tData=[]
    tData.append(TCP_PACKET_DELIMITER_START+"Data test1" + TCP_PACKET_DELIMITER_END)
    tData.append(None)
    tData.append(TCP_PACKET_DELIMITER_START+"Data test1"+TCP_PACKET_DELIMITER_START+"da")
    tData.append("ta2"+TCP_PACKET_DELIMITER_END)
    tData.append(TCP_PACKET_DELIMITER_START+"Data test3"+TCP_PACKET_DELIMITER_END+TCP_PACKET_DELIMITER_START+"data4"+TCP_PACKET_DELIMITER_END+TCP_PACKET_DELIMITER_START+"dat")
    tData.append("a5"+TCP_PACKET_DELIMITER_END+TCP_PACKET_DELIMITER_START+"data6"+TCP_PACKET_DELIMITER_END)

    lastFragmentTime = GetCurrUS()
    readLoop = 0
    while True and False == stopThreads:
      #for rawData in tData:
        rawData = ReadTCP(recvSocket,MAX_RECV_SIZE,python3)

        if None == rawData: #Simple timeout, no biggie
            if recvTime + MAX_INACTIVITY_TIME*1000 < GetCurrUS():
                recvSocket.close()
                print("Closing Socket due to Inactivity")
                return False


        elif False == rawData: #remote socket closed or errored
            print("Other End Closed Socket")
            return False
 
        else: # have data       
            recvTime = GetCurrUS()
            readLoop += 1
            #print("Loop:{0} Time: {1} Size: {2}".format(readLoop,recvTime - lastFragmentTime,len(rawData)))
            lastFragmentTime = recvTime
            for dataByte in rawData:
                if dataByte == TCP_PACKET_DELIMITER_START:
                    if None != currPacket:
                        print("Received Start of Packet before an End Of Packet Delimeter")
                        currPacket = None
                    else:
                        currPacket =""

                elif dataByte == TCP_PACKET_DELIMITER_END:
                    ProcessSinglePacket(currPacket,recvTime,payloadFile,mirrorTarget)
                    currPacket = None

                else:
                    currPacket += dataByte
                



def ReadTCP(recvSocket,bytesToRead,python3):
    try:
        rawData = recvSocket.recv(bytesToRead)

        if python3:
            rawData = rawData.decode("utf-8")
        else:
            rawData = rawData

        if len(rawData) == 0:
            return False #Indicates other sised shut down

        return rawData

    except socket.timeout:
        return None

    except Exception as Ex:
        #print("Read TCP: " + str(Ex))
        try:
            recvSocket.close()
        except:
            pass
        return False
                  

def ReadTCP_Python3(recvSocket,python3=True):
    # Not used aymore
    return None
def ReadTCP_Python2(recvSocket):
    return ReadTCP_Python3(recvSocket,False)

def ReadUDP_Python3(recvSocket):
    try:
        rawData,address = recvSocket.recvfrom(maxBufferSize)
        rawData = rawData.strip().decode("utf-8")
        return rawData

    except Exception as Ex:
        return None

def ReadUDP_Python2(recvSocket):
    try:
        rawData,address = recvSocket.recvfrom(maxBufferSize)
        rawData = rawData.strip()
        return rawData

    except Exception as Ex:
        return None

def ProcessSinglePacket(rawData,recvTime,payloadFile,mirrorTarget,isMasterThread=True):
    global stopThreads
    global verbose
    global packetsRecvd,outputFrequency,lastOutputTime,recvFn,g_targetMap

    packetsRecvd += 1
    batchPacketReceived = True
    
    processedDataDict=ProcessPacket(recvTime,rawData)
    if None == processedDataDict:
        return

    if processedDataDict['Done'] == False:
        newRawData = CreatePacket(processedDataDict, payloadFile)
        
        SendToNextHop(processedDataDict['NextTarget'], newRawData)
                
        if None != mirrorTarget:
            Mirror( mirrorTarget, processedDataDict['Payload']) # Send copy of payload to somebody else - simulate data being stolen

        if True == verbose and True == isMasterThread and  GetCurrMS() - lastOutputTime > outputFrequency:  # don't print on every packet
            PrintPacketCount()
                
    else: # all done, packet went out and came back, and this is the originator
        strTimes = CalcTripTimes(processedDataDict,len(rawData)) 
        if None == strTimes: #don't print EVERY packet time, only at intervals
            return
    
        if True == verbose:
            strTimes += "," + processedDataDict['Payload']

        if None != mirrorTarget:
            Mirror(mirrorTarget,strTimes)

        print(strTimes)

def HandlePacketsUDP(recvSocket,payloadFile,mirrorTarget,isMasterThread=False):
    global stopThreads
    global verbose
    global packetsRecvd,outputFrequency,lastOutputTime,recvFn

    noDataCount=0
    lastID=0
    index=0
    while False == stopThreads:
        if False == UseUDP:
            recvTime,rawData = recvFn(None)

        else:
            rawData = recvFn(recvSocket)
            recvTime = GetCurrUS()

        if None == rawData:
            continue

        elif False == rawData:
            continue

        else: 
            ProcessSinglePacket(rawData,recvTime,payloadFile,mirrorTarget,isMasterThread)
        
def SetupVersionSpecificGoodies():
    global UseUDP,sendFn,recvFn,g_receiveSocket,sendFnUDP,g_sendSocket,g_mirrorSocket,CONFIG_SOCKET_NODELAY,CONFIG_SOCKET_RCV_BUFFER_SIZE

    print("Running with Python " + str(sys.version_info[0]) + "." + str(sys.version_info[1]) )

    g_mirrorSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    if sys.version_info[0] < 3:
        sendFnTCP = SendTCP_Python2
        readFnTCP = ReadTCP_Python2

        sendFnUDP = SendUDP_Python2
        readFnUDP = ReadUDP_Python2

    else:
        sendFnTCP = SendTCP_Python3
        readFnTCP = ReadTCP_Python3
        sendFnUDP = SendUDP_Python3
        readFnUDP = ReadUDP_Python3

    if True == UseUDP:
        sendFn = sendFnUDP
        recvFn = readFnUDP
        g_receiveSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        g_receiveSocket.setblocking(True) 
        g_receiveSocket.settimeout(SOCKET_TIMEOUT)

        g_sendSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

        print("Using UDP Sockets")

    else:
        sendFn = sendFnTCP
        recvFn = readFnTCP
        g_receiveSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        g_receiveSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        g_receiveSocket.setblocking(True) 
        g_receiveSocket.settimeout(SOCKET_TIMEOUT)
        g_receiveSocket.setsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF, CONFIG_SOCKET_RCV_BUFFER_SIZE )

        g_sendSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        g_sendSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        g_sendSocket.setblocking(True) 
        g_sendSocket.settimeout(SOCKET_TIMEOUT) 
        g_sendSocket.setsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF, CONFIG_SOCKET_RCV_BUFFER_SIZE )

        if True == CONFIG_SOCKET_NODELAY:
            g_receiveSocket.setsockopt( socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 )
            g_sendSocket.setsockopt( socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 )

        print("Using TCP Sockets")

def CpuBurnerThread(delayTime): 
    global stopThreads

    while False == stopThreads:
         SleepMs(delayTime)


def GetNewTCP_Connections(listenSocket,payloadFile,mirrorTarget):
    global stopThreads, CONFIG_SOCKET_NODELAY,CONFIG_SOCKET_RCV_BUFFER_SIZE


    listenSocket.listen(5) 
    
    while False == stopThreads:
        try:
            connSock,addr = listenSocket.accept()
            connSock.setblocking(True) 
            connSock.settimeout(SOCKET_TIMEOUT) # set small timeout, so we can timeout when a complete packet has arrived
            connSock.setsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF, CONFIG_SOCKET_RCV_BUFFER_SIZE)

            if True == CONFIG_SOCKET_NODELAY:
                connSock.setsockopt( socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 )

            if False:
                print("Adding Connection: " + str(addr))
                print("New Connection Family " + str(int(connSock.family)) )
                print("New Connection Type " + str(int(connSock.type)))
                print("New Connection File " + str(connSock.fileno()))
                print("New Connection Timeout " + str(connSock.gettimeout()))

            connectionThread = threading.Thread(target=TCP_ReaderProc,args=(connSock,payloadFile,mirrorTarget))
            connectionThread.start()

        except socket.timeout:
            SleepMs(1)

        except Exception as Ex:
            print("--" + str(Ex))


##########################################################################
#
# app entry point
#
def main():
    global g_receiveSocket,cpuBurnerDelay,cpuBurnerThreadCount,UseUDP
    global batchNumber, batchTimeout, batch, batchPacketReceived,g_sendSocket
    signal.signal(signal.SIGINT, signal_handler) # make my own Ctrl+C handler now

    interface,connections,payload,MirrorTarget,threadCount = HandleCommandlineArguments()
    g_sendSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    SetupVersionSpecificGoodies()

    if None == interface:
        return

    global stopThreads, delayTime,accumulatedTimes,minDelayTim
            
    stopThreads=False
    print("Workload Simulator - version " + VersionStr)
    #setup socket to listen on
    listenIP,listenPort = interface.split(portTokenStr)
    try:
        listenPort=int(listenPort)
        g_receiveSocket.bind((listenIP,listenPort))

    except:
        print("Specified local IP:Port combination of ["+listenIP +":"+str(listenPort)+"] appears to be invalid.")
        return

    if False:
        print("g_Rx Family " + str(int(g_receiveSocket.family)) )
        print("g_Rx Type " + str(int(g_receiveSocket.type)))
        print("g_Rx File " + str(g_receiveSocket.fileno()))
        print("g_Rx Timeout " + str(g_receiveSocket.gettimeout()))

        print("g_Rx Family " + str(int(g_sendSocket.family)) )
        print("g_Rx Type "  + str(int(g_sendSocket.type)))
        print("g_Rx File " + str(g_sendSocket.fileno()))
        print("g_Rx Timeout "+ str(g_sendSocket.gettimeout()))


    if usingFloatingIP: 
       print("Exchaning external IP " + floatingInterface + " for " + interface)

    if None != cpuBurnerDelay:
        print("Starting CPU Burner " + str(cpuBurnerThreadCount) +" threads with delay of " + str(cpuBurnerDelay))
        for loop in range(cpuBurnerThreadCount):
            cpuBurnerThread = threading.Thread(target=CpuBurnerThread,args=(cpuBurnerDelay,))
            cpuBurnerThread.start()
    
    if len(connections) > 0: #is the 1st in the chain, then do reading in a thread
        for dummyCon in connections:
            accumulatedTimes.append(0)
        accumulatedTimes.append(0) # need an extra for the cound

        if True == UseUDP:
            processThread = threading.Thread(target=HandlePacketsUDP,args=(g_receiveSocket,payload,MirrorTarget))
            processThread.start()

        else: #TP
            processThread = threading.Thread(target=GetNewTCP_Connections,args=(g_receiveSocket,payload,MirrorTarget))
            processThread.start()

        if delayTime < minDelayTime:
            delayTime = minDelayTime

        if usingFloatingIP:
            sendTarget = floatingInterface
        else:
            sendTarget=connections[0]

        if True == batch:
            while False == stopThreads:
                for loop in range(0,batchNumber):
                    SleepMs(delayTime) #little sleep between blasts
                    sendBuffer = CreateInitialPayload(interface,connections,payload)
                    SendToNextHop(sendTarget,sendBuffer)
                    batchPacketReceived = False

                count = 100
                restTime = batchTimeout/100
                while False == batchPacketReceived:
                    SleepMs(restTime)
                    count -= 1
                    if count < 1:
                         batchPacketReceived = True   					
        
        else: # Non-Batch mode, just send,sleep,send,sleep repeat - normal op
            while False == stopThreads:
                sendBuffer = CreateInitialPayload(interface,connections,payload)
                SendToNextHop(sendTarget,sendBuffer)

                SleepMs(delayTime) #little sleep between blasts
            
    else: ## is not the 1st in the chain, is a link so just go listen, process and forward
        if True == UseUDP:
            threadList=[]
            print("Starting " + str(threadCount) + " receive threads.")
            for threadNumber in range(1,threadCount):
                readThread2 = threading.Thread(target=HandlePacketsUDP,args=(g_receiveSocket,payload,MirrorTarget))
                readThread2.start()
                threadList.append(readThread2)

            HandlePacketsUDP(g_receiveSocket,payload,MirrorTarget,True)

        else:
            GetNewTCP_Connections(g_receiveSocket,payload,MirrorTarget)



if __name__ == '__main__':
    try:
        main()
    except Exception as Ex:
        stopThreads = True        
        print("Catastrophic error: " + str(Ex))

