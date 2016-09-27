try:
    from threading import Thread
    from Queue import Queue
    import logging
    import pymongo
    from optparse import OptionParser
    import nmap
    from collections import OrderedDict
    import datetime
    import os, sys
    import io
    from IPy import IP
    import time
    import random
except ImportError, e :
    print "Missing important dependencies, you might want to install them using pip (Eg:pip install %s)", e


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

today=str(datetime.date.today())
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh = logging.FileHandler(today+'-infra_assessment_logfile.txt')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)
all_ports=[]

nm = nmap.PortScanner()

logfile=today+"-nmap_hosts_up.txt"
nmapFullTCP='-sS -T4 --max-retries 2 -p 1-65535'
nmapUDPCommon='-sU -T4 --max-retries 1'
nmapConvertFromCIDRtoSingleIP='-n -sn -sL'

def main():

    usage = "usage %prog [options] [IP ADDRESS] [IP ADDRESS/CIDR]"
    parser = OptionParser(usage)
    parser.add_option("-t", "--threads", dest="threads", default="5", help="How many threads you want to use (Default: 5")
    parser.add_option("-s", "--single_ip", dest="singleip", default=False, help="Single IP address Eg: 88.33.44.55")
    parser.add_option("-f", "--file",dest="ipfile",default=False,help="You can pass a file to be used to scan the networks it can be single hosts or networks")
    parser.add_option("-c","--convert",dest="cidrconvert",default=False,help="With this option you can provide a list of netblocks Eg: 192.168.1.0/24 and will return converted in single ip address list one per line")
    (options, args) = parser.parse_args()

    if options.threads == None:
        options.threads = 5

    cidr=nmapCIDRconvert(options.singleip)
    res=nmapHostsUp(options.singleip)

    hostsup=open(logfile,"w")
    for host, status in res:
        if 'up' in status:
    	    hostsup.write(host+"\n")
    hostsup.close()

    logger.info("Host in queue to scan: "+str(len(open(logfile,"r").readlines())))
    logger.info("Starting portscan against live hosts with "+options.threads+" threads")
    startIng(logfile,options.threads)


#def callback_result(host, scan_result):
#    logger.info('------------------')
#    logger.info(host, scan_result)

def nmapCIDRconvert(targets):
    nm.scan(hosts=targets,arguments='-n -sn -sL')
    outputFile=open(today+"-converted-ip-nmap.txt","wb")
    logger.info("Converting command line ip provided: "+targets+" to single ip address per line list")
    logger.info("File written to: "+today+"-converted-ip-nmap.txt")
    time.sleep(1)
    for i in nm.all_hosts():
        outputFile.write(i+"\n")

def nmapHostsUp(targets):
    logger.info("Starting the discovery of alive hosts scan...")
    nm.scan(hosts=targets,arguments='-n --min-hostgroup=20 -sP -PE -PP -PM -PS21,22,23,25,80,113,443,3389,8080,3128,8081,88,10000 -PA21,22,23,25,80,113,443,3389,8080,3128,8081,88,10000 -PU 53,123,88,111,123,135,137,138,139,161,427,445,500 --max-retries 1 -T4')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    logger.info("nmap discovery for finished "+targets)
    logger.info("List of hosts identified alive can be found in file: "+logfile)
    if hosts_list == '':
        logger.critical("Nmap didn't find any alive host on this network segment")
        sys.exit(0)
    else:

        return hosts_list

def nmapPortscanner(targets):

    time.sleep(2)
    directory=today+"-nmap-scans"

    if not os.path.exists(directory):
        os.makedirs(directory)

    logger.info("scan started against target: "+targets)

    try:
        nm.scan(hosts=targets, arguments="-v -n -sS -Pn -p 1-65535 -T4 -r --max-retries 1 --host-timeout 30m --initial-rtt-timeout 100ms --max-rtt-timeout 200ms")
        loggedScanOutput=open(directory+"/"+targets+"-nmap-tcp.xml","w")
        loggedScanOutput.write(directory+nm.get_nmap_last_output())
        loggedScanOutput.close()
        logger.debug("Scan for "+targets+" logged in "+directory+"/"+targets+"-nmap-tcp.xml")
    except (nmap.PortScannerError,KeyboardInterrupt,TypeError) as e:
        logger.critical("There's been a problem during the scanner: ",e)
        return 0

    temp_ports=[]

    try:

        for i in nm[targets]['tcp'].keys():
            if nm[targets]['tcp'][i]['state'] == 'open':
                temp_ports.append(i)
                all_ports.append(i)
        if temp_ports != []:
            logger.info("Ports found open against "+targets+": "+str(temp_ports)[1:-1])
        else:
            logger.warn("No ports found open for: "+targets)

    except (KeyError,TypeError) as e:
        logger.warn("No ports found open on: "+targets)
        return 0

    return 1

def startIng(logfile,threads):
    global q
    concurrent=int(threads)
    q = Queue(concurrent)
    a=open(logfile,"r").readlines()

    lines=a[:-1]

    for i in range(concurrent):
        t = Thread(target=HostList)
        t.daemon = True
        t.start()
    for ips in a:
        q.put(ips.rstrip("\n"))
    q.join()

def HostList():
    while True:

        try:
            time.sleep(10)
            host = q.get(block=True)
            nmapPortscanner(host)
            q.task_done()

        except (TypeError,NameError,AttributeError,KeyboardInterrupt) as e:

            logger.critical("Scan for host: "+host+" resulted in unknown problem:"+str(e))

''' TODO Adding storage for mongodb?
def mongoStore():
    try:
        client=pymongo.MongoClient('192.168.254.151',27017)
        db = client['nmapScan']
        logger.info("Successfully connected to MongoD")

    except pymongo.errors.ConnectionFailure, e:
        logger.info("Couldn't connet to MongoD, check if the daemon is running : %s" , e)
'''

if __name__ == "__main__" :

    if os.getuid() == 0:
        try:
            main()
            UniqueIP=sorted(list(OrderedDict.fromkeys(all_ports)))
            if not UniqueIP == []:

                logger.info("Stats:\t\t\tHost Alive: "+str(len(logfile)))
                logger.info("Stats:\t\t\tTotal Unique Ports Open: "+str(len(UniqueIP)))
                logger.info("Stats:\t\t\tTotal Ports Discovered Open On All Hosts: "+str(len(all_ports)))
                time.sleep(3)
                logger.info("Now you can simply paste in Nessus the following ports : "+",".join([str(i) for i in UniqueIP]))
            else:
                logger.warn("Errors detected in ports conversion please read again the ports...")

        except KeyboardInterrupt as e:
            logger.info("Shutting down the script")
            time.sleep(2)
    else:
        print("This program is not supposed to be launched as normal user, try sudo.")
        sys.exit(0)
