import nmap.nmap
import os
import sys
import base64
#sys.argv[1]-->id
#sys.argv[2]-->hosts
#sys.argv[3]-->argumentsValidation
#sys.argv[4]-->arguments

args3 = base64.b64decode(sys.argv[3])
args4 = base64.b64decode(sys.argv[4])
print(sys.argv[1])
print(sys.argv[2])
#print(sys.argv[3])
print(args3)
#print(sys.argv[4])
print(args4)

#db.nmapConfig.update_or_insert(db.nmapConfig.id==sys.argv[1], scanRunning='T')

try:
    nm = nmap.PortScanner()
except:
    redirect(URL('default','index', vars=dict(msg='To use HOST SCAN, you should install NMAP https://nmap.org/')))

result = nm.scan(hosts=sys.argv[2], arguments=args3)
#result = nm.scan(hosts='127.0.0.1')
#print(result)
#argumentsParser = str(str(request.get_vars.arguments).replace(' ',',')).split(',')
argumentsParser = str(str(args4).replace(' ',',')).split(',')

db.nmapConfig.update_or_insert(db.nmapConfig.id==sys.argv[1], scanInfo=nm.scaninfo(), command_line=nm.command_line(), scanstats=nm.scanstats(), scanRunning='F')

#argumentsParser = str(str(args4).replace(' ',',')).split(',')

for host in nm.all_hosts():
    if nm[host].state()=='up':
        for proto in nm[host].all_protocols(): #tcp/udp
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state']=='open':
                    try:
                        if "-O" in argumentsParser or "--osscan-limit" in argumentsParser or "--osscan-guess" in argumentsParser:
                            #db.nmapResults.update_or_insert( ( (db.nmapResults.nmapConfigId==request.args(0)) & (db.nmapResults.scanHostName==host) & (db.nmapResults.protocol==proto) & (db.nmapResults.port==port) ),      nmapConfigId=request.args(0), scanHostName=host, protocol=proto, port=port, product=result['scan'][host][proto][port]['product'], protocolState=result['scan'][host][proto][port]['state'], protocolVersion=result['scan'][host][proto][port]['version'], name=result['scan'][host][proto][port]['name'], conf=result['scan'][host][proto][port]['conf'], extrainfo=result['scan'][host][proto][port]['extrainfo'], reason=result['scan'][host][proto][port]['reason'], cpe=result['scan'][host][proto][port]['cpe'], statusState=result['scan'][host]['status']['state'], statusReason=result['scan'][host]['status']['reason'], hostnames=result['scan'][host]['hostnames'], vendor=result['scan'][host]['vendor'], addresses=result['scan'][host]['addresses'], osMatch=result['scan'][host]['osmatch'] )
                            db.nmapResults.update_or_insert( ( (db.nmapResults.nmapConfigId==sys.argv[1]) & (db.nmapResults.scanHostName==host) & (db.nmapResults.protocol==proto) & (db.nmapResults.port==port) ),      nmapConfigId=sys.argv[1], scanHostName=host, protocol=proto, port=port, product=result['scan'][host][proto][port]['product'], protocolState=result['scan'][host][proto][port]['state'], protocolVersion=result['scan'][host][proto][port]['version'], name=result['scan'][host][proto][port]['name'], conf=result['scan'][host][proto][port]['conf'], extrainfo=result['scan'][host][proto][port]['extrainfo'], reason=result['scan'][host][proto][port]['reason'], cpe=result['scan'][host][proto][port]['cpe'], statusState=result['scan'][host]['status']['state'], statusReason=result['scan'][host]['status']['reason'], hostnames=result['scan'][host]['hostnames'], vendor=result['scan'][host]['vendor'], addresses=result['scan'][host]['addresses'], osMatch=result['scan'][host]['osmatch'] )
                        else:
                            db.nmapResults.update_or_insert( ( (db.nmapResults.nmapConfigId==sys.argv[1]) & (db.nmapResults.scanHostName==host) & (db.nmapResults.protocol==proto) & (db.nmapResults.port==port) ),      nmapConfigId=sys.argv[1], scanHostName=host, protocol=proto, port=port, product=result['scan'][host][proto][port]['product'], protocolState=result['scan'][host][proto][port]['state'], protocolVersion=result['scan'][host][proto][port]['version'], name=result['scan'][host][proto][port]['name'], conf=result['scan'][host][proto][port]['conf'], extrainfo=result['scan'][host][proto][port]['extrainfo'], reason=result['scan'][host][proto][port]['reason'], cpe=result['scan'][host][proto][port]['cpe'], statusState=result['scan'][host]['status']['state'], statusReason=result['scan'][host]['status']['reason'], hostnames=result['scan'][host]['hostnames'], vendor=result['scan'][host]['vendor'], addresses=result['scan'][host]['addresses'], osMatch='')
                    except:
                        pass
#redirect(URL('default', 'hostScan'))
