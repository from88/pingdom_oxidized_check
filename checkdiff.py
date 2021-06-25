import re
import requests
import smtplib
import socket
from settings import verysecretuser, muchsecretpass
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def realdict():
    deviceslist = ['PTGNCS01', "SCCNS01"]
    """Get /32 ip addresses from device and create dict of lists"""
    dicts = {}
    for i in deviceslist:
        response = requests.get('https://oxidized.company.zone/node/fetch/defaultgroup/'+i, verify=False,auth=(verysecretuser, muchsecretpass))
        content = response.content.decode("utf-8")
        print("Scanning "+ i + "....")
        deviceips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/32\b', content)
        if len(dicts) > 0:
            d1 = {}
            d1[i] = deviceips
            dicts.update(d1)
        else:
            dicts[i] = deviceips
    return dicts

def pingdom(urlpingdom):
    """Get ip addresses from pingdom, add /32 prefix and make a list"""
    response = requests.get(urlpingdom)
    content = response.content.decode("utf-8").splitlines()
    pingdomlist = []
    for ip in content:
        if ip:
            pingdomlist.append(ip + "/32")
    return pingdomlist

def finddiff(urlpingdom = 'https://my.pingdom.com/probes/ipv4'):
    """ find differences between list and dict of lists and mke new dict of lists """
    pingdomlist = pingdom(urlpingdom)
    dict =  realdict()
    dictdone = {}
    for k, v in dict.items():
        l = []
        for d in pingdomlist:
            if d not in v:
                """ make new dict of lists """
                l.append(d)
                t = {}
                t[k] = l
                dictdone.update(t)
    return dictdone

def main():
    hostname = socket.gethostname()
    dictdone = finddiff(urlpingdom = 'https://my.pingdom.com/probes/ipv4')
    if len(dictdone) > 0:
        message = ''
        for k, v in dictdone.items():
            message += ("\n" + "add the following lines to " + k + ":" + "\n" + "\n")
            for d in v:
                message += ("object-group network ipv4 External_Monitoring " + d + '\n')
        with smtplib.SMTP('smtp.company.com') as server:
            server.sendmail(hostname, 'networks@company.com',
                            'Subject: New Pingdom probes found.\nNew probes found, please update the devices access-list\n\n' + message)
        print("\n" + "New probes found")
    else:
        print("\n" + "No new probes found")

if __name__ == "__main__":
        main()
