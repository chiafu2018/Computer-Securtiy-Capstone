from pwn import *
import time
from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))

MOD = 2 ** 32

# Time-based PRNG prediction
def long_secure_random(seed):
    libc.srand(seed) 
    r = [libc.rand() % 32323 for _ in range(100)]

    for i in range(1, 100):
        r[i] = ((r[i] * r[i - 1]**3) % MOD +
                (r[i] * r[i - 1]**2 * 3) % MOD +
                (r[i] * r[i - 1] * 2) % MOD + r[i]) % MOD
    return r[99]

now = int(time.time())

for delta in range(0, 10):
    seed = now + delta
    guess = long_secure_random(seed)
    print(f"[+] Trying seed {seed}, guess: {guess}")

    p = remote('140.113.207.245', 30171)
    p.recvline()
    p.sendline(str(guess).encode())

    respond = p.recvline(timeout=0.2)
    print(respond.decode())

    if b"You succeed, here are your flag" in respond:
        break

    p.close()

print(p.recvall(timeout=0.2).decode())
p.close()
