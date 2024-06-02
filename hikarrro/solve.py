from pwn import *

seed = b"Nk6ELRTJxGa"

moves = [
	# recv: 57 36
	[58, 59], # recv: 1 10
	[59, 60], # recv: 10 19
	[60, 61], # recv: 19 28
	[61, 62], # recv: 36 45
	[62, 61], # recv: 28 37
	[61, 62], # recv: 37 44
	[62, 61], # recv: 4 21
	[61, 62], # recv: 21 31
	[62, 61], # recv: 45 38
	[61, 60], # recv: 31 37
	[60, 61], # recv: 38 52
	[61, 62], # recv: 44 45
	[62, 63], # recv: 45 46
	[63, 62], # recv: 46 38
	[62, 63], # recv: 38 46
	[63, 62], # recv: 46 38
	[62, 53], # recv: 38 29
	[53, 60], # recv: 29 36
	[60, 51], # recv: 36 35
	[51, 60], # recv: 35 43
	[60, 53], # recv: 37 31
	[53, 62], # recv: 52 38
	[62, 61], # recv: 43 44
	[61, 60], # recv: 31 37
	[60, 61],
]

if args.REMOTE:
	r = remote("", "")
else:
	r = process(["./run_challenge.sh"])

r.sendlineafter(b"Seed?", seed)

for start, finish in moves:
	r.recvuntil(b"AI moved: ")
	ai_move = r.recvline().strip().decode()
	print(ai_move)
	r.sendlineafter(b"Your move?", f'{start} {finish}'.encode())

r.recvuntil(b"flag: b'")
flag = r.recvuntil(b"\\n'", drop=True)
print(flag.decode())

r.close()
