import re
import requests
import smtplib
import socket
from settings import verysecretuser, muchsecretpass
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def realdict():
    deviceslist = ['NCS01', "NCS02"]
    """Get all /32 and /128 ip addresses from device and create dict of lists"""
    dicts = {}
    for i in deviceslist:
        response = requests.get('https://oxidized.company.zone/node/fetch/defaultgroup/'+i, verify=False,auth=(verysecretuser, muchsecretpass))
        content = response.content.decode("utf-8")
        print("Scanning "+ i + "....")
        deviceips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/32\b|\b.*/128\b', content)
        #print(deviceips)
        if len(dicts) > 0:
            d1 = {}
            d1[i] = deviceips
            dicts.update(d1)
        else:
            dicts[i] = deviceips
    return dicts

def pingdom():
    """Get ip addresses from pingdom URLS, add /32 or /128 prefix and make a list"""
    response_v4 = requests.get('https://my.pingdom.com/probes/ipv4')
    content_v4 = response_v4.content.decode("utf-8").splitlines()
    response_v6 = requests.get('https://my.pingdom.com/probes/ipv6')
    content_v6 = response_v6.content.decode("utf-8").splitlines()
    content_both = content_v4 + content_v6
    pingdomlist = []
    for ip in content_both:
        if "." in ip:
            pingdomlist.append(ip + "/32")
        else:
            pingdomlist.append(ip + "/128")
    return pingdomlist


def finddiff():
    """ find differences between pingdom list and devices dict of lists and mke new dict of lists """
    pingdomlist = pingdom()
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
    dictdone = finddiff()
    if len(dictdone) > 0:
        message = ''
        for k, v in dictdone.items():
            message += ("\n" + "add the following lines to " + k + ":" + "\n" + "\n")
            for d in v:
                if "." in d:
                    message += ("object-group network ipv4 External_Monitoring " + d + '\n')
                else:
                    message += ("object-group network ipv6 External_Monitoring_IPv6 " + d + '\n')
        with smtplib.SMTP('smtp.company.com') as server:
            server.sendmail(hostname, 'hmm@company.com',
                            'Subject: New Pingdom probes found.\nNew probes found, please update the devices access-list\n\n' + message)
        print("\n" + "New probes found")
    else:
        print("\n" + "No new probes found")

if __name__ == "__main__":
        main()
