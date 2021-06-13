#!/usr/bin/python3

import subprocess
import os
import sys
from datetime import datetime as dt

#
# MUST BE IMPROVED.
#  - Cannot use ssh-key now.
#  - Must input password, passphrase any time? Not good.
#  - Pattern1. Create cron manually, and execute.(Same as initial script)
#              Collect data late by hand. 
#  - [NG] Pattern2. Use non passphrase key to access.
#         (But not good. dander from security view.)
#  - [NG] Pattern3. Write password in script, too bad, bad security.
# 

#
# pre-requirement:
# Controller - Target Servers
# Controller Exec this script(via python3)
# -> Targer server(execute command via ssh, netstat or ss)
#
# Please execute this command on the controller server via cron, e.g. */1 (1 minute interval)
#

if len(sys.argv)!=3:
  print("Usage: outputFilePath hostlist")
  sys.exit(0)
(COUNTFILE_BASE,USERHOSTLISTFILE) = (sys.argv[1:])
RECORDTIME_BASE = COUNTFILE_BASE + ".date"

#---------------------------------------------------------------
# Sub routines
#---------------------------------------------------------------
def localexec(cmd):
  proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  result = proc.communicate()
  return [result[0].decode().strip(),result[1].decode().strip()]

def remoteexec(userhost,cmd):
  LOCALHOSTS=["localhost","::1","127.0.0.1"]
  sps=userhost.split("@")
  # LocalExec
  if ( len(sps)>=2 and sps[1] in LOCALHOSTS ) or ( len(sps)==1 and sps[0] in LOCALHOSTS ):
    return localexec(cmd)
  else:
    return localexec("ssh " + userhost +" \"" + cmd + "\"")

def ping(host):
  num = 3
  (stdout,stderr)=localexec("ping -c "+str(num)+" "+host)
  if stdout.find(str(num)+" packets received"):
    return True
  else:
    return False

#---------------------------------------------------------------
# Main
#---------------------------------------------------------------
userhosts=[]
with open(USERHOSTLISTFILE) as f:
  for line in f.readlines():
    line=line.strip()
    userhosts.append(line)

for userhost in userhosts:
  COUNTFILE=userhost+"_"+COUNTFILE_BASE
  RECORDTIME=userhost+"_"+RECORDTIME_BASE

  # 0. Host Check
  if not ping(userhost):
    print("[Error] Can not access to the host: " + userhost)
    continue

  # 1. Command check ss or netstat to select
  commands = ["ss","netstat"]
  isCommandFound = False
  for command in commands:
    (stdout,stderr)=remoteexec(userhost,"which "+command)
    if stdout=="":
      continue
    else:
      isCommandFound = True
      break
  if not isCommandFound:
    print("[Error] Can not find ss or netstat on this machine: "+userhost)
    continue

  # 2.Inspection
  cmd = command+" -an | egrep 'tcp|udp|icmp'"
  (stdout,stderr)=remoteexec(userhost,cmd)

  # Ports>=THRESPORT and not in EXCLUDE_HIGHPORTS are summerized as "HIGH", since high ports are normally a kind of ports assigned randomly for one time transmission.
  THRESPORT=10000  # Dynamic Private Port Number(49152-65535) -> no. ssh uses 3xxxx.
  EXCLUDE_HIGHPORTS = [""]
  # ----------------------------------------------------------------------------------------------------------
  # Sampl      [0]       [1]   [2] [3]                         [4]                         [5]         [6]
  # ----------------------------------------------------------------------------------------------------------
  # Ignored tcp        0      0 0.0.0.0:16909               0.0.0.0:*                   LISTEN      -
  # Ignored tcp        0      0 0.0.0.0:16910               0.0.0.0:*                   LISTEN      -
  # USE     tcp        0      0 x.x.x.x:514                 x.x.x.x:60145          ESTABLISHED -
  # USE     tcp        0      0 x.x.x.x:3389                x.x.x.x:39636         TIME_WAIT   -
  # USE     tcp        0      0 x.x.x.x:39190               x.x.x.x:10022          ESTABLISHED -
  # USE     tcp        0      0 x.x.x.x:22                  x.x.x.x:37564         ESTABLISHED -
  # ----------------------------------------------------------------------------------------------------------
  # Output data format
  # SourceIP:SourcePort,DestIP:DestPort,count
  #

  data = {}
  # 3. Read Process Count file
  # *Each line
  #  cmd,count
  if os.path.isfile(COUNTFILE):
    with open(COUNTFILE) as f:
      for line in f.readlines():
        line = line.strip()
        sps=line.split(",")
        data[",".join(sps[0:len(sps)-1])] = int(sps[len(sps)-1])
  
  source = ""
  dest = ""
  proto = ""
  
  # 4. Read and merge processes
  for line in stdout.split("\n"):
    sps = line.split()

    if command=="netstat":  
      source = sps[3]
      dest = sps[4]
    elif command=="ss":
      source = sps[4]
      dest = sps[5]
    else:
      print("[Error] Unexpected error at getting information from output of commands")
      sys.exit(1)

    proto = sps[0]
  
    ## Improved for IPv6
    div=source.split(":")
    (sourceIP,sourcePort)=(":".join(div[0:len(div)-1]),div[-1])
    div=dest.split(":")
    (destIP,destPort)=(":".join(div[0:len(div)-1]),div[-1])
  
    if sourcePort.find("*")!=-1 or destPort.find("*")!=-1:
      continue

    if int(sourcePort)>=THRESPORT and sourcePort not in EXCLUDE_HIGHPORTS:
      source=":".join([sourceIP,"HIGH"])
    if int(destPort)>=THRESPORT and destPort not in EXCLUDE_HIGHPORTS:
      dest=":".join([destIP,"HIGH"])
  
    key = ",".join([proto,source,dest])
    if key not in data.keys():
      data[key]=0
    data[key] = data[key]+1
  
  with open(COUNTFILE,"w") as f:
    for key in sorted(data.keys()):
      f.write(",".join([key,str(data[key])]))
      f.write("\n")
  
  with open(RECORDTIME,"a") as f:
      f.write(dt.now().strftime('%Y/%m/%d %H:%M:%S'))
      f.write("\n")
