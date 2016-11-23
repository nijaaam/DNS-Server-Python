#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."   
ROOTNS_IN_ADDR = "192.5.5.241"

class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
    self._srtt = srtt
    self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))

class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)

class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)

# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."), 
            OrderedDict([(DomainName(ROOTNS_DN), 
                   CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))]) 

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])


def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

cache = {}
def getNS(data,offset):
  header = Header.fromData(data)
  nscount = header._nscount
  nsarray = []
  for x in range (0,nscount):
    rr = RR.fromData(data, offset)
    offset = offset + rr[1]
    nsarray.append(rr)
  return nsarray,offset #This function gets the Nameserver RR in the provided payload and returns an array

def getAR(data,offset):
  #Returns A Records only
  header = Header.fromData(data)
  count = header._arcount
  ararray = []
  for x in range (0,count-1):
    rr = RR.fromData(data, offset)
    offset = offset + rr[1]
    if rr[0]._type == 1:
      ararray.append(rr)
    if (offset + rr[1] > len(data)):
      break
  return ararray,offset#This function gets the Additional RR in the provided payload and returns an array

def performRecursiveQuery(data,dict,nsarray): #This function iterates the ip address in the dict and sends them to the sendDNSQuery function
  dict_len = len(dict)
  for x in range (0, dict_len):
    try:
      ip_address = dict[nsarray[x][0]._nsdn]
      return sendDNSQuery(data,ip_address)
    except timeout:
      logger.info("Server Timed Out, Trying different server")     
    except KeyError:
      logger.info("Key Not Found")

def getIP(nsdn, ararray):
  arlen = len(ararray)
  for x in range(0,arlen):
    rr = ararray[x]
    if rr[0]._dn == nsdn:
      ip_address = inet_ntoa(rr[0]._inaddr)
      return ip_address# This function returns the ip address of a nameserver by looking up the additional RR array

def mapValues(nsarray,ararray): #This function returns a dictionary where the key is the name server domain and the value is its ip address
  dic = {}
  nslen = len(nsarray)
  for x in range(0,nslen):
    nsdn = nsarray[x][0]._nsdn
    ip_address = getIP(nsdn,ararray)
    if ip_address != None:
      dic[nsdn] = ip_address
  return dic 

def parseDNS(data,reply): #This function parses the DNS payload and converts them into a nameserver, ip address dictionary and nameserver array
  header = Header.fromData(data)
  qe = QE.fromData(data,len(header))
  (nsarray,offset) = getNS(reply,len(header) + len(qe))
  (ararray,offset) = getAR(reply,offset)
  nsIPdict = mapValues(nsarray,ararray)
  return nsIPdict,nsarray

def parseHeader(reply):
    header = Header.fromData(reply)
    return header._ancount, header._nscount, header._arcount

def constructQuestion(id,dn):
  newHeader = Header(id,Header.OPCODE_QUERY, Header.RCODE_NOERR,
                    qdcount = 1,ancount=0, nscount=0, arcount=0, qr = 0, aa = 0,
                    tc = 0, rd = 0, ra = 0)
  neQE = QE(type=QE.TYPE_A,dn=dn)
  return  "{0}{1}".format(newHeader.pack(),neQE.pack())

def queryCNAME(data,reply,cname): #This function takes a CNAME to query its IP address
  header = Header.fromData(data)
  data_2 = constructQuestion(header._id,cname)
  reply = sendDNSQuery(data_2,ROOTNS_IN_ADDR)
  return packReply(data,reply)

def packReply(data,reply): #This function packs the response payload by first change the header variables, question variables and individulaly packing the RR
  replyheader = Header.fromData(reply)
  replyqe = QE.fromData(reply,len(replyheader))
  count = replyheader._ancount + replyheader._nscount + replyheader._arcount
  offset = len(replyheader) + len (replyqe)
  rr_entries = []
  for x in range (count):
    rr = RR.fromData(reply,offset)
    rr_entries.append(rr)
    offset = offset + rr[1]
  dataHeader = Header.fromData(data)  
  replyheader._id = dataHeader._id
  dataqe = QE.fromData(data,len(dataHeader))
  replyqe._type = dataqe._type
  replyqe._dn = dataqe._dn #check this
  rr_entries[0][0]._dn = dataqe._dn
  packed_rr = ""
  for x in range(0,len(rr_entries)):
    packed_rr = packed_rr + rr_entries[x][0].pack()
  return  "{0}{1}{2}".format(replyheader.pack(),replyqe.pack(),packed_rr)

def getAnswers(reply): #This function takes a payload and returns an array that has the answer records
  header = Header.fromData(reply)
  qe = QE.fromData(reply, len(header))
  offset = len(header) + len(qe)
  answerCount = header._ancount
  answers = []
  #print answerCount
  for x in range (answerCount):
    rr = RR.fromData(reply,offset)
    answers.append(rr)
    offset = offset + rr[1]
  return answers

def printQuestion(data,address):
  header = Header.fromData(data)
  qe = QE.fromData(data, len(header))
  print "Looking up "
  print qe._dn
  print address

def sendDNSQuery(data,address): #This function takes a payload and an address and sends them
  printQuestion(data,address)
  cs.sendto(data,(address,53))
  (reply, temp_address,) = cs.recvfrom(512) 
  header = Header.fromData(reply)
  if (header._ancount > 0): #Checks if the response has answers
    qe = QE.fromData(data,len(header))
    rr = RR.fromData(reply,len(header)+len(qe))
    if rr[0]._type == 5:
      return queryCNAME(data,reply,rr[0]._cname) #If CNAME is in the answer then it is converted into IP address
    else:
      return reply
  else:
    try:
      (nsIPdict,nsarray) = parseDNS(data,reply)
    except AttributeError:
      qe = QE.fromData(reply,len(header))
      rr = RR.fromData(reply,len(header)+len(qe))
      if rr[0]._type == 6:
        return reply
    if bool(nsIPdict) == False: #If a nameserver didnt respond with any IP we create a new question and send in to the root server
      for x in range(len(nsarray)):
        #print nsarray[x][0]._nsdn
        newData = constructQuestion(header._id,nsarray[x][0]._nsdn)
        newReply = sendDNSQuery(newData,ROOTNS_IN_ADDR)
        anarray = getAnswers(newReply)
        for y in range(len(anarray)):
          ip = inet_ntoa(anarray[y][0]._inaddr)
          return sendDNSQuery(data,ip)
    return performRecursiveQuery(data,nsIPdict,nsarray) #If no answers in response then a recursive query is made 

def insertRRStoCache(reply,offset,header): #This function takes a payload and inserts them into the CACHE
  ans = {}
  ns = {}
  addit = {}
  nsarray = []
  ararray = []
  anarray = []
  header = Header.fromData(reply)
  qe = QE.fromData(reply,len(header))
  for x in range (header._ancount):
    rr = RR.fromData(reply,offset)
    cache    = CacheEntry(expiration= int(time()) + rr[0]._ttl, authoritative=False)
    ans[x] = rr,cache
    offset = offset + rr[1]
  anarray.append(ans)
  for x in range (header._nscount):
    rr = RR.fromData(reply,offset)
    cache    = CacheEntry(expiration= int(time()) + rr[0]._ttl, authoritative=True)
    ns[x] = rr,cache
    offset = offset + rr[1]
  nsarray.append(ns)
  for x in range (header._arcount):
    rr = RR.fromData(reply,offset)
    cache    = CacheEntry(expiration= int(time()) + rr[0]._ttl, authoritative=False)
    addit[x] = rr,cache
    offset = offset + rr[1]
  ararray.append(addit)
  return ans,ns,addit

def storeInCache(reply):
  header = Header.fromData(reply)
  qe = QE.fromData(reply, len(header))
  count = header._ancount + header._nscount + header._arcount
  offset = len(header) + len(qe)
  (ans,ns,addit) = insertRRStoCache(reply,offset,header)
  cache[qe._dn] = ans,ns,addit
  

def check_cache(data): #This function checks if the question from the client is in the cache
  header = Header.fromData(data)
  id = header._id
  qe = QE.fromData(data, len(header))
  domain = qe._dn
  if domain in cache: #Checks if the question is in the cache dictionary else queries the root server as normal
    ans = cache[qe._dn][0]
    ns = cache[qe._dn][1]
    addit = cache[qe._dn][2]
    keys = ans.keys()
    values = ans.values()
    anarray = []
    nsarray = []
    ararray = []
    packed_rr = ""
    for x in range(len(ans)): #These for loops gets the RR from cache and updates the expiry time
      rr = ans.values()[x][0][0]
      cac =  ans.values()[x][1]
      expiry = cac._expiration - int(time())
      rr._ttl = expiry
      if expiry > 0:
        anarray.append(rr)
        packed_rr = packed_rr + rr.pack()
    #print len(anarray)
    if len(anarray) > 0:
      for x in range(len(ns)):
        rr = ns.values()[x][0][0]
        cac =  ns.values()[x][1]
        expiry = cac._expiration - int(time())
        rr._ttl = expiry
        if expiry > 0:
          nsarray.append(rr)
          packed_rr = packed_rr + rr.pack()
      for x in range(len(addit)):
        rr = addit.values()[x][0][0]
        cac =  addit.values()[x][1]
        expiry = cac._expiration - int(time())
        rr._ttl = expiry
        if expiry > 0:
          ararray.append(rr)
          packed_rr = packed_rr + rr.pack()
      newHeader = Header(id,Header.OPCODE_QUERY, Header.RCODE_NOERR,
                    qdcount = 1,ancount=len(anarray), nscount=len(nsarray), arcount=len(ararray), qr = 0, aa = 0,
                    tc = 0, rd = 0, ra = 0)
      return  "{0}{1}{2}".format(newHeader.pack(),qe.pack(),packed_rr)
    else:
      return sendDNSQuery(data,ROOTNS_IN_ADDR)
  else:
    return sendDNSQuery(data,ROOTNS_IN_ADDR)
  
timeout_count = 0

def constructErrorHeader(data): #Constructs a server fail response
  header = Header.fromData(data)
  id = header._id
  qe = QE.fromData(data,len(header))
  newHeader = Header(id,Header.OPCODE_QUERY, Header.RCODE_SRVFAIL,
                    qdcount = 1,ancount=0, nscount=0, arcount=0, qr = 0, aa = 0,
                    tc = 0, rd = 0, ra = 0)
  return  "{0}{1}".format(newHeader.pack(),qe.pack())

while 1:
  try:
    (data, address,) = ss.recvfrom(512)
  except timeout:
    logger.info("Socket timeout Error in receiving packet from client")
  if not data:
    log.error("client provided no data")
    continue
  try:
    reply = check_cache(data)
    storeInCache(reply)
    logger.log(DEBUG2, "our reply in full:") 
    logger.log(DEBUG2, hexdump(reply))
    ss.sendto(reply, address)
  except timeout:
    logger.info("Socket timeout Error in receiving packet from client")
    timeout_count = timeout_count + 1
    if timeout_count == 2:
      data2 = constructErrorHeader(data)
      ss.sendto(data2,address)
  except:
    data2 = constructErrorHeader(data)
    ss.sendto(data2,address)