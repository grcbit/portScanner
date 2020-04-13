#Copyright (C) 2019 Rodolfo Lopez 
#contacto@grcbit.com
# -*- coding: utf-8 -*-

import os
import shutil
import subprocess
import signal
import base64

def index():
    return dict()

def licencia():
    return dict()

# ---- Action for login/register/etc (required for auth) -----
def user():
    """
    exposes:
    http://..../[app]/default/user/login
    http://..../[app]/default/user/logout
    http://..../[app]/default/user/register
    http://..../[app]/default/user/profile
    http://..../[app]/default/user/retrieve_password
    http://..../[app]/default/user/change_password
    http://..../[app]/default/user/bulk_register
    use @auth.requires_login()
        @auth.requires_membership('group name')
        @auth.requires_permission('read','table name',record_id)
    to decorate functions that need access control
    also notice there is http://..../[app]/appadmin/manage/auth to allow administrator to manage users
    """
    return dict(form=auth())

# ---- action to server uploaded static content (required) ---
@cache.action()
def download():
    """
    allows downloading of uploaded files
    http://..../[app]/default/download/[filename]
    """
    return response.download(request, db)

@auth.requires_login()
def hostScan():
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
    links = [lambda row: A(T('Scan'),_class='button btn btn-danger',_href=URL("default","executeScan", args=[row.id, row.scanDate ], vars=dict(hosts=row.scanHostNetwork, arguments=row.scanArguments) )), lambda row: A(T('Stats'),_class='button btn btn-primary',_href=URL("default","hostScan", vars=dict(idRow=row.id) ))]
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
    redirect(URL('default', 'hostScan'))
