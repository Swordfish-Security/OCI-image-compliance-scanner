from subprocess import Popen, PIPE, STDOUT
from pathlib import Path
from operator import methodcaller
import os
import json


def _getLayersDirs(data):
    dirs = []
    d = data['GraphDriver']['Data']
    if 'LowerDir' in d:
        d1 = d['UpperDir']
        d2 = d['LowerDir']
        dirs = d2.split(":")
        dirs.append(d1)
    else:
        dirs = []
        d = d['UpperDir']
        dirs.append(d)
    return dirs


def _returnStdout(result):
   
    info = "\033[96mInformational\033[0m"
    low = "\033[92mLow\033[0m"
    medium = "\033[93mMedium\033[0m"
    high = "\033[0;31mHigh\033[0m"
    critical = "\033[1;31mCritical\033[0m"
    passed = "\033[92mPASS\033[0m"
    failed = "\033[1;31mFAIL\033[0m"   
    
    match result['Severity']:
        case "Critical":
            sev = critical
        case "High":
            sev = high
        case "Medium":
            sev = medium
        case "Low":
            sev = low
        case "Informational":
            sev = info
    match result['Pass']:
        case True:
            res = passed
        case False:
            res = failed 
    if "Files" in result:
        print(f'{res}. Severity: {sev}. {result["Title"]}. {result["Description"]}.')
        for l in result["Files"]:
            for h in l:
                print("   Layer:", h, "Files:", l[h])
    else:
        print(f'{res}. Severity: {sev}. {result["Title"]}. {result["Description"]}.')
 
 
def Output():   
    format = {
        "Title": "",
        "Severity": "",
        "Pass": "",
        "Description": "",
        "Mitigation": ""
    }
    return format


class Image():  
    

    def __init__(self, name):
        self.name = name             


    def tagCheck(self):
        result = Output()   
        result["Title"] = f"Tag :latest"
        result["Mitigation"] = "The image must have a fixed tag to determine the version"
        n = self.name.split(':')
        tag = n[-1]
        if tag != "latest":
            result["Severity"] = "Informational"
            result["Pass"] = True
            result["Description"] = f"Image {self.name} has tag: {tag}"   
        elif not tag:
            result["Severity"] = "Critical"
            result["Pass"] = False
            result["Description"] = f"Image {self.name} tag not defined: {tag}"            
        else:
            result["Severity"] = "Critical"
            result["Pass"] = False
            result["Description"] = f"Image {self.name} has tag: {tag}" 
        _returnStdout(result)
        return result
    

    def labelCheck(self, data):
        result = Output()  
        result["Title"] = f"Image LABEL metadata"
        result["Mitigation"] = "The image must contain a set of labels specified by the developer in the LABEL instruction"        
        config = data['Config']        
        if 'Labels' in config:
            labels = config['Labels']
            if not labels:
                result["Severity"] = "Low"
                result["Pass"] = False
                result["Description"] = f"LABEL is not defined"                                
            else:
                result["Severity"] = "Informational"
                result["Pass"] = True
                result["Description"] = f"LABEL is =  {labels}"                    
        else:
            result["Severity"] = "Low"
            result["Pass"] = False
            result["Description"] = f"LABEL is not defined"   
        _returnStdout(result)                      
        return result


    def startupParamsCheck(self, data):    
        result = Output()
        result["Title"] = f"Parameters CMD, ENTRYPOINT"
        result["Mitigation"] = "It is good practice to specify default launch parameters by developer. You must define parameters in a CMD or ENTRYPOINT statement"        
        config = data['Config']        
        if 'Entrypoint' in config and 'Cmd' in config:
            result["Severity"] = "Informational"
            result["Pass"] = True
            result["Description"] = f"The image has startup parameters set in Entrypoint and CMD {data['Config']['Entrypoint']} {data['Config']['CMD']}"
        elif 'Entrypoint' in config:
            result["Severity"] = "Informational"
            result["Pass"] = True
            result["Description"] = f"The image has startup parameters set in Entrypoint {data['Config']['Entrypoint']}"            
        elif 'Cmd' in config:
            result["Severity"] = "Informational"
            result["Pass"] = True
            result["Description"] = f"The image has startup parameters set in CMD {data['Config']['Cmd']}"
        else: 
            result["Severity"] = "Low"
            result["Pass"] = False
            result["Description"] = f"The image does not have any startup parameters specified in ENTRYPOINT or CMD"                   
        _returnStdout(result)       
        return result               


    def exposeCheck(self, data):    
        result = Output()
        result["Title"] = f"Critical ports in the instructions EXPOSE"
        result["Mitigation"] = "Make sure your containers only use protocols for remote connectivity when necessary."
        badPorts = { "ssh": "22/tcp",
                     "telnet": "23/tcp",
                     "snmp": "161/udp",
                     "docker": "2375/tcp",
                     "docker": "2376/tcp",
                     "rdp": "3389/tcp"
                     }
        
        config = data['Config']
        ports_result = []
        if 'ExposedPorts' in config:
            ports = config['ExposedPorts']
            if ports:
                portsList = list(ports.keys())
                for port in portsList:
                    for protocol in badPorts:
                        if port == badPorts[protocol]:
                            ports_result.append(port)
                            result["Severity"] = "High"
                            result["Pass"] = False
                            result["Description"] = f"The image has critical port(s) in the EXPOSE statement: {ports_result}"                    
        if not ports_result:               
                       result["Severity"] = "Informational"
                       result["Pass"] = True
                       result["Description"] = f"The image does not have critical ports in the EXPOSE statement"           
        _returnStdout(result)                                              
        return result


    def defaultUserCheck(self, data):      
        result = Output()
        result["Title"] = f"Default user and group"
        result["Mitigation"] = "The default USER and GROUP must be explicitly defined in the USER statement and do not contain root or 0. For example, USER app:app"     
        config = data['Config']
        if 'User' in config:
            user_group = config['User']
            if not user_group:
                result["Severity"] = "Critical"
                result["Pass"] = False
                result["Description"] = f"User not defined"
            user = user_group.split(":")[0]
            try:
                group = user_group.split(":")[1]
            except IndexError as e:
                group = None
            if user == "root" or user == "0":
                result["Severity"] = "Critical"
                result["Pass"] = False
                result["Description"] = f"Default user is {user}"
            elif not group:
                result["Severity"] = "Critical"
                result["Pass"] = False
                result["Description"] = f"Default group not defined"
            elif group == "root" or user == "0":
                result["Severity"] = "Critical"
                result["Pass"] = False
                result["Description"] = f"Default group is {group}"
            else:
                result["Severity"] = "Informational"
                result["Pass"] = True
                result["Description"] = f"Default user is {user}, default group is {group}"
        else: 
            result["Severity"] = "Critical"
            result["Pass"] = False
            result["Description"] = f"User not defined"    
        _returnStdout(result)                    
        return result


    def layersCheck(self, data):    
        result = Output()
        result["Title"] = f"The number of layers in the image"
        result["Mitigation"] = "A good practice would be to squash all layers in the resulting image into a single layer. See docker squash, multistage build"        
        layers = data['RootFS']['Layers']
        if len(layers) == 1:
            result["Severity"] = "Informational"
            result["Pass"] = True
            result["Description"] = f"The image consists of one layer"         
        else:
            result["Severity"] = "Low"
            result["Pass"] = False 
            result["Description"] = f"Number of layers in the image {len(layers)}. It is necessary to minimize the number of layers if possible"            
        _returnStdout(result)                           
        return result          


    def fileCheck(self, find_expr, check_type, data):
        result = Output()
        result["Title"] = f"Checking for a {check_type} file"
        result["Mitigation"] = f"The image must not contain file(s) {check_type} in the image"               
        dirs = _getLayersDirs(data)
        result_files = []
        for dir in dirs:
            command = f"find {dir} {find_expr}"
            p = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
            output = p.stdout.read().decode('ascii')
            if output:           
                files_of_layer = output.replace(dir, '')                        
                files_of_layer_list = files_of_layer.split("\n")[:-1]
                d = dir.split("/")
                layer = str(d[-2])
                result_layer = {layer: files_of_layer_list}
                result_files.append(result_layer)  
        if result_files:
            result["Severity"] = "Critical"
            result["Pass"] = False
            result["Description"] = f"Found file"
            result["Files"] = result_files
        else:
            result["Severity"] = "Informational"
            result["Pass"] = True
            result["Description"] = f"File(s) {check_type} not found"         
        _returnStdout(result)                           
        return result


    def compCheck(self, compilers_list, data):
        result = Output()
        result["Title"] = f"Compilers in the image"
        result["Mitigation"] = "The image should not contain compilers in the file system, except when they are necessary for the operation of the application. Make sure that compilers are actually needed during execution"           
        dirs = _getLayersDirs(data)
        result_files = []
        for dir in dirs:
            compilers_of_layer = []
            for comp in compilers_list:
                find_expr = f"-type f -executable -name {comp}"
                command = f"find {dir} {find_expr}"
                p = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
                output = p.stdout.read().decode('ascii')  
                if output:    
                    compiler = output.replace(dir, '')    
                    compilers_list = compiler.split("\n")[:-1]   
                    compilers_of_layer = compilers_of_layer + compilers_list
            if compilers_of_layer:
                d = dir.split("/")
                layer = str(d[-2])
                result_layer = {layer: compilers_of_layer}
                result_files.append(result_layer)    
        if result_files:
            result["Severity"] = "Medium"
            result["Pass"] = False
            result["Description"] = f"Found file"
            result["Files"] = result_files   
        else:
            result["Severity"] = "Informational"
            result["Pass"] = True
            result["Description"] = f"Compiler(s) not found"        
        _returnStdout(result)               
        return result


    def osCheck(self, data):
        result = Output()
        result["Title"] = f"Checking for OS type"
        result["Mitigation"] = "A good practice would be to use Distroless images to minimize the components in the image"             
        result["Pass"] = True
        dirs = _getLayersDirs(data)
        for dir in dirs:        
            release_path = (dir + "/etc/os-release")       
            try:
                with open(release_path) as my_file:
                    lines = my_file.read().splitlines()
                    els = list(map(methodcaller("split", "="), lines))
                    os_version = []
                    for el in els:
                        if el[0] == "NAME" or el[0] == "VERSION_ID":
                            o_v = el[1]
                            l = o_v.replace('"', '')
                            os_version.append(l)             
            except FileNotFoundError:
                continue
        if os_version:
            result["Severity"] = "Informational"
            result["Description"] = f"The image {self.name} is based on the OS {os_version}"   
        else:
            result["Severity"] = "Informational"
            result["Description"] = f"Failed to determine the base OS of image {self.name}"            
        _returnStdout(result)           
        return result
