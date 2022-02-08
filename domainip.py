import whois
import socket
import ipwhois
from pprint import pprint
import PySimpleGUI as sg
import requests
import time
from contextlib import suppress
from virus_total_apis import PublicApi as VirusTotalPublicApi

# Enter your API key from virus total
API_KEY = ''

vt = VirusTotalPublicApi(API_KEY)


def main():
    while True:
        # Setup Pop Up Window
        sg.theme('DefaultNoMoreNagging')  # Add a touch of color
        # All the stuff inside your window.
        layout = [[sg.Text('What is the Domain Name?')],
              [sg.Text('Please Enter Here:'), sg.InputText()],
              [sg.Button('Ok', focus=True), sg.Button('Cancel')]]

        # Create the Window
        window = sg.Window('Domain Info Finder', layout)
        # Event Loop to process "events" and get the "values" of the inputs
        event, values = window.read()

        if event == sg.WIN_CLOSED or event == 'Exit':
            break

        # Read value of domain entry from pop up
        domain = values[0]

        window.close()

        # Strip white space at end
        domainstripped = domain.strip()

        print(domainstripped)

        sg.OneLineProgressMeter('Loading Info...', 0, 100, '_M_', 'Loading Virus Total IP Report', orientation='h')
        time.sleep(1)

        # Get ip of domain address and put it in a variable
        ipaddress = socket.gethostbyname(domainstripped)

        responsevtip = vt.get_ip_report(ipaddress)

        sg.OneLineProgressMeter('Loading Info...', 20, 100, '_M_', 'Loading Virus Total Domain Report')
        time.sleep(1)

        responsevtdomain = vt.get_domain_report(domainstripped)

        sg.OneLineProgressMeter('Loading Info...', 40, 100, '_M_', 'Running HTTP Get')
        time.sleep(1)

        # Run a HTTP get request against domain
        with suppress(Exception):
            httpinfo = requests.get("http://" + domainstripped)

        sg.OneLineProgressMeter('Loading Info...', 50, 100, '_M_', 'Running HTTPS Get')
        time.sleep(1)

        # Run a HTTPS get request against domain
        with suppress(Exception):
            httpsinfo = requests.get("https://" + domainstripped, verify=False)

        sg.OneLineProgressMeter('Loading Info...', 60, 100, '_M_', 'Gathering Domain whois')
        time.sleep(1)

        # Get whois data store in variable w
        w = whois.whois(domainstripped)

        sg.OneLineProgressMeter('Loading Info...', 70, 100, '_M_', 'Gather IP whois')
        time.sleep(1)

        # Get ip whois store in variable
        ipwhoislookup = ipwhois.IPWhois(ipaddress)

        sg.OneLineProgressMeter('Loading Info...', 80, 100, '_M_', 'Storing ip whois info')
        time.sleep(1)

        # Store results in variable of ip whois
        res = ipwhoislookup.lookup_whois()

        sg.OneLineProgressMeter('Loading Info...', 90, 100, '_M_', 'Cleaning up')
        time.sleep(1)

        sg.OneLineProgressMeter('Loading Info...', 100, 100, '_M_', 'Displaying Results')
        time.sleep(1)

        layout = [[sg.Output(size=(60, 40))],
                  [sg.Button('Display'), sg.Button('Exit')]]

        # Create the window
        window = sg.Window(("Domain Whois Lookup: " + domainstripped), layout)

        while True:  # Event Loop
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == 'Exit':
                break
            if event == 'Display':
                print(w)
        window.close()

        layout = [[sg.Output(size=(60, 40))],
                  [sg.Button('Display'), sg.Button('Exit')]]

        # Create the window
        window = sg.Window(("IP Whois Lookup: " + ipaddress), layout)

        while True:  # Event Loop
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == 'Exit':
                break
            if event == 'Display':
                pprint(res)
        window.close()

        layout = [[sg.Output(size=(60, 40))],
                  [sg.Button('Display'), sg.Button('Exit')]]

        # Create the window
        window = sg.Window(("Virus Total IP Lookup: " + ipaddress), layout)

        while True:  # Event Loop
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == 'Exit':
                break
            if event == 'Display':
                pprint(responsevtip)
        window.close()

        layout = [[sg.Output(size=(60, 40))],
                  [sg.Button('Display'), sg.Button('Exit')]]

        # Create the window
        window = sg.Window(("Virus Total Domain Lookup: " + domainstripped), layout)

        while True:  # Event Loop
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == 'Exit':
                break
            if event == 'Display':
                pprint(responsevtdomain)
        window.close()

        layout = [[sg.Output(size=(60, 40))],
                  [sg.Button('Cookies'), sg.Button('Headers'), sg.Button('Content'), sg.Button('Raw'), sg.Button('Exit')]]

        # Create the window
        window = sg.Window(("HTTP Info: " + ipaddress), layout)

        while True:  # Event Loop
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == 'Exit':
                break
            if event == 'Cookies':
                pprint(httpinfo.cookies)
            if event == 'Headers':
                pprint(httpinfo.headers)
            if event == 'Content':
                try:
                    pprint(httpinfo.content)
                except:
                    pprint("error")
            if event == 'Raw':
                pprint(httpinfo.raw)
        window.close()

        layout = [[sg.Output(size=(60, 40))],
                  [sg.Button('Cookies'), sg.Button('Headers'), sg.Button('Content'), sg.Button('Raw'), sg.Button('Exit')]]

        # Create the window
        window = sg.Window(("HTTPS Info: " + ipaddress), layout)

        while True:  # Event Loop
            event, values = window.read()
            if event == sg.WIN_CLOSED or event == 'Exit':
                break
            if event == 'Cookies':
                pprint(httpsinfo.cookies)
            if event == 'Headers':
                pprint(httpsinfo.headers)
            if event == 'Content':
                pprint(httpsinfo.content)
            if event == 'Raw':
                pprint(httpsinfo.raw)
        window.close()


# loop the program
main()

# build with auto-py-to-exe and pyinstaller
