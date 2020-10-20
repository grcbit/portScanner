# -*- coding: utf-8 -*-
import os
import shutil
import subprocess
import signal
import base64
demo = True

@auth.requires_login()
def hostScan():
    #-------------------------------------------------------------------------------------
    if demo == False:
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------
    import nmap.nmap
    try:
        nm = nmap.PortScanner()
    except:
        redirect(URL('default','index', vars=dict(msg='To use HOST SCAN, you should install NMAP https://nmap.org/')))

    #db.nmapConfig.id.readable = False
    db.nmapConfig.scanInfo.writable = False
    db.nmapConfig.command_line.writable = False
    db.nmapConfig.scanstats.writable = False
    db.nmapConfig.scanRunning.writable = False

    fields = (db.nmapConfig.id, db.nmapConfig.scanHostName, db.nmapConfig.scanHostNetwork, db.nmapConfig.scanDate, db.nmapConfig.scanArguments, db.nmapConfig.scanRunning)
    links = [lambda row: A(T('Scan'),_class='button btn btn-danger',_href=URL("portScanner","executeScan", args=[row.id, row.scanDate ], vars=dict(hosts=row.scanHostNetwork, arguments=row.scanArguments) )), lambda row: A(T('Stats'),_class='button btn btn-primary',_href=URL("portScanner","hostScan", vars=dict(idRow=row.id) ))]
    form = SQLFORM.grid(db.nmapConfig, fields=fields, user_signature=False, searchable=True, create=True, editable=True, deletable=True, links=links, maxtextlength=500, paginate=10)

    if request.get_vars.idRow != 'None':    
        idRow = request.get_vars.idRow
    else:
        idRow = 0

    if request.get_vars.idRow:
        scanHostsCount = db.nmapResults.id.count()
        rScan2= db( db.nmapResults.nmapConfigId==idRow).select(db.nmapResults.ALL)
        scanHosts = db(db.nmapResults.nmapConfigId==idRow).select(db.nmapResults.scanHostName, db.nmapResults.port, db.nmapResults.protocolState, db.nmapResults.statusState, scanHostsCount, db.nmapResults.nmapConfigId, groupby=db.nmapResults.scanHostName)
        scanPorts = db(db.nmapResults.nmapConfigId==idRow).select(db.nmapResults.scanHostName, db.nmapResults.port, db.nmapResults.protocolState, db.nmapResults.statusState, scanHostsCount, groupby=db.nmapResults.port)
    else:
        rScan2 = ''
        scanHosts=''
        scanPorts =''
    return dict(form = form, rScan2=rScan2, scanHosts=scanHosts, scanPorts=scanPorts)

@auth.requires_login()
def executeScan():
    #-------------------------------------------------------------------------------------
    if demo == False: 
        if (auth.has_membership(role='admin') or auth.has_membership(role='riskManager')):
            pass
        else:
            redirect(URL('default','index'))
    #-------------------------------------------------------------------------------------

    #import nmap.nmap
    #try:
    #    nm = nmap.PortScanner()
    #except:
    #    redirect(URL('default','index', vars=dict(msg='To use HOST SCAN, you should install NMAP https://nmap.org/')))

    db(db.nmapConfig.id==request.args(0)).update(scanRunning='T')
    argumentsValidation = str(request.get_vars.arguments).strip('°!"#$%&/()=?¡*[_:;.,}{+')

    #db(db.nmapConfig.id==request.args(0)).update(scanStatus='T')
    #----------------------------------------------------
    #-S app tells web2py to run "myscript.py" as "app", 
    #-M tells web2py to execute models
    #-A a b c passes optional command line arguments
    #----------------------------------------------------
    script = os.path.join(request.folder, 'modules', 'scanExecution.py')
    hosts = request.get_vars.hosts
    #arguments = argumentsValidation
    argsVal = base64.b64encode(argumentsValidation)
    argsText = base64.b64encode(request.get_vars.arguments)
    #av = argumentsValidation
    #scanExec = "python %s/web2py.py -S %s -M -R %s -A %s %s %s %s" % (os.getcwd(), request.application, script, request.args(0), hosts, av, request.get_vars.arguments)
    scanExec = "python %s/web2py.py -S %s -M -R %s -A %s %s %s %s" % (os.getcwd(), request.application, script, request.args(0), hosts, argsVal, argsText)
    proxyPs = subprocess.Popen(scanExec, shell=True,  preexec_fn=os.setsid)
    #result, err = proxyPs.communicate()
    #result = nm.scan(hosts=request.get_vars.hosts, arguments=argumentsValidation)
    #nm.scan(hosts=request.get_vars.hosts, arguments=argumentsValidation)
    redirect(URL('portScanner', 'hostScan'))
