import subprocess 
import os 
import json
import shlex 
import shutil
import sys
from module.compliance_checks import Image
from module.compilers import compilers_list

# Directory for saving reports inside container
report_dir = os.environ.get("COMPLIANCE_REPORTS_DIR", "reports")

# image full path for scan
# for example 
# COMPLIANCE_IMAGE_FULL_REF="docker.io/library/ubuntu:latest"
image = os.environ.get("COMPLIANCE_IMAGE_FULL_REF", False)

# Docker auth config for private repo
auth_config = os.environ.get("DOCKER_AUTH_CONFIG", False)

# Stdout json output
json_stdout = os.environ.get("COMPLIANCE_JSON_STDOUT", False)

# EXIT CODES
INFORMATIONAL = os.environ.get("INFORMATIONAL_EXIT_CODE", 0)
CRITICAL = os.environ.get("CRITICAL_EXIT_CODE", 12)
HIGH = os.environ.get("HIGH_EXIT_CODE", 13)
MEDIUM = os.environ.get("MEDIUM_EXIT_CODE", 14)
LOW = os.environ.get("LOW_EXIT_CODE", 15)
CANT_PULL_IMAGE = 20
CANT_GET_MANIFEST = 21
NOT_DEFINED_IMAGE = 22
CANT_CREATE_REPORT_DIR = 23

# Color output
colorCyan = '\033[96m'
colorGreen = '\033[92m'
colorWarning = '\033[93m'
colorDefault = '\033[0m'


def auth_repo(auth_config):
    if auth_config:
       path = f'/run/containers/0'
       file = f'{path}/auth.json'
       try:
          os.makedirs(path)
          with open(file, "w") as auth_file:
             auth_file.write(auth_config)
       except OSError: 
           print(f"Cannot write auth_config to {file}")


def run_command(command, realtime_output): 
    # Run command and return result
    if realtime_output is True:
        process = subprocess.run(shlex.split(command), text=True, stdout=sys.stdout, stderr=sys.stderr) 
        return process.stdout, process.stderr, process.returncode 
    else:
        process = subprocess.run(shlex.split(command), capture_output=True, text=True)
        return process.stdout, process.stderr, process.returncode 


def create_dir(report_dir):
    try: 
        if os.path.exists(report_dir) and os.path.isdir(report_dir):
           shutil.rmtree(report_dir)
           os.makedirs(report_dir)
        else: 
           os.makedirs(report_dir)
    except Exception as e: 
        print(f"{colorWarning}Error! Failed to create directory for reports!{colorDefault}")
        exit(CANT_CREATE_REPORT_DIR)


def pull_image(image):
        command_pull = f"podman pull '{image}' --log-level=fatal"
        stdout, stderr, returncode = run_command(command_pull, True) 
        if returncode != 0:          
            print(f"{colorWarning}Failed to pull image {image}{stderr}{colorDefault}") 
            exit(CANT_PULL_IMAGE) 
        else:            
            print(f"{colorGreen}Image pulled successfully{colorDefault}")


def get_manifest(image):
        command_inspect = f"podman image inspect {image}"
        stdout, stderr, returncode = run_command(command_inspect, False) 
        if returncode != 0:                 
            print(f"{colorWarning}Failed to get image manifest {image}{stderr}{colorDefault}") 
            exit(CANT_GET_MANIFEST) 
        else:
            d = json.loads(stdout)
            data = d[0]             
            print(f"{colorGreen}Image manifest received successfully{colorDefault}")             
            return data
        

def main(image): 
    # Auth config
    auth_repo(auth_config)
    # Create/refrest report dir
    create_dir(report_dir)
    # Start scan
    # Add :latest if tag not specified
    if ':' not in image:
        image = f"{image}:latest"
    image_short = ('_'.join((image.split("/")[-1]).split(":")[-2::]))
    print(f"{colorCyan}Image scanning started {image}{colorDefault}")        
    # Loading image into podman     
    print("1. Pulling the image")  
    pull_image(image)
    # Getting image manifest JSON manifest
    print("2. Getting the image manifest")
    data = get_manifest(image)
    image_name = image
    image_obj = Image(image_name)
    # Launch checks           
    print("3. Launch of compliance checks")      
    results = []
    results.append(image_obj.tagCheck())
    results.append(image_obj.exposeCheck(data))
    results.append(image_obj.defaultUserCheck(data))
    results.append(image_obj.labelCheck(data))
    results.append(image_obj.layersCheck(data))
    results.append(image_obj.startupParamsCheck(data))
    results.append(image_obj.fileCheck('-perm -4000', 'suid bit', data))
    results.append(image_obj.fileCheck('-perm -2000', 'sgid bit', data))
    results.append(image_obj.fileCheck('-name sudo -type f -executable', 'sudo', data))
    results.append(image_obj.fileCheck('-name su -type f -executable', 'su', data))
    results.append(image_obj.fileCheck('-name sshd -type f -executable', 'sshd', data))
    results.append(image_obj.fileCheck('-name ssh -type f -executable', 'ssh client', data))
    results.append(image_obj.fileCheck('-name nc -type f -executable', 'nc', data))   
    results.append(image_obj.fileCheck('-name netcat -type f -executable', 'netcat', data))
    results.append(image_obj.fileCheck('-name socat -type f -executable', 'socat', data))             
    results.append(image_obj.compCheck(compilers_list, data))
    results.append(image_obj.osCheck(data))
    result = {image: results}
    # Saving reports
    with open(f"{report_dir}/{image_short}-compliance.json", "w", encoding='utf-8') as jsonfile:
        json.dump(result, jsonfile, indent=4, ensure_ascii=False)
        print(f"{colorGreen}Compliance scan completed. Report file is {report_dir}/{image_short}-compliance.json{colorDefault}")
    if json_stdout == "true":
        print(json.dumps(result, indent=4, ensure_ascii=False))
    # Choose exit code
    checks = result[image][0:]
    severities = []
    for s in checks:
        severities.append(s["Severity"])
    for severity in severities:
        match severity:
            case "Critical":
                exit(CRITICAL)
            case "High":
                exit(HIGH)
            case "Medium":
                exit(MEDIUM)
            case "Low":
                exit(LOW)
            case "Informational":
                exit(INFORMATIONAL)


if __name__ == "__main__":
   if not image:
       print("The image is not specified in variable $COMPLIANCE_IMAGE_FULL_REF")       
       exit(NOT_DEFINED_IMAGE) 
   else:    
       print(f"Image sent for scanning {image}")
       main(image)
