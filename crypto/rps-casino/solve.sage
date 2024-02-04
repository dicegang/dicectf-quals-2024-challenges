import os
from pwn import *
from tqdm import tqdm
from functools import reduce

OUTPUT_SIZE = 4
MASK = (1 << OUTPUT_SIZE) - 1

def fakeLFSR():
	state = list(identity_matrix(GF(2), 64))
	while 1:
		yield state[-OUTPUT_SIZE:]
		for i in range(OUTPUT_SIZE):
			bit = state[-1] + state[-2] + state[-4] + state[-5]
			state = [bit] + state[:63]

def realLFSR(state):
	while 1:
		yield state & MASK
		for i in range(OUTPUT_SIZE):
			bit = (state ^^ (state >> 1) ^^ (state >> 3) ^^ (state >> 4)) & 1
			state = (state >> 1) | (bit << 63)

outs = []
n = 56
rng = fakeLFSR()
inexact_rels = []
exact_rels = []

with process(["python3", "rng.py"]) as r:
	for i in range(n):
		rel = sum(next(rng))
		r.sendlineafter(b": ", b"rock")
		resp = r.readline().strip()
		if resp == b'Tie!':
			outs.append(0)
			exact_rels.append(rel)
		elif resp == b'You lose!':
			outs.append(1)
			inexact_rels.append(rel)
		elif resp == b'You win!':
			outs.append(2)
			inexact_rels.append(rel)
		else: print(resp)

	print(len(exact_rels))

	M = block_matrix(GF(2), [
		[matrix(GF(2), exact_rels), zero_matrix(GF(2), len(exact_rels), len(inexact_rels))],
		[matrix(GF(2), inexact_rels), identity_matrix(GF(2), len(inexact_rels))]
	])

	M = M.rref()
	from collections import defaultdict
	fvs = defaultdict(int)
	for row in M:
		s, *nzp = row.nonzero_positions()
		m = 1 << (63 - s)
		for i in nzp:
			fvs[i] |= m
			if i < 64:
				fvs[i] |= 1 << (63 - i)
	import itertools
	fvs_0 = [j for i,j in fvs.items() if i<64]
	print(len(fvs_0), len(inexact_rels))
	from sage.combinat.gray_codes import product, combinations
	def check(state):
		iterator = product([2]*len(fvs_0))
		nn = 0
		while 1:
			nn += 1
			rng = realLFSR(state)
			for out1, out2 in zip(rng, outs):
				if out1 % 3 != out2: break
			else:
				for i in range(50):
					r.sendlineafter(b": ", ["paper", "scissors", "rock"][next(rng) % 3])
					r.interactive()
			
			try:
				p,ii = next(iterator)
				state ^^= fvs_0[p]
			except StopIteration: break

	for k in range(len(inexact_rels)):
		state = reduce(lambda x,y: x^^y, [fvs[i] for i in range(64 + k, 64+len(inexact_rels))], 0)
		if not k: continue
		iterator = iter(tqdm(combinations(len(inexact_rels), k), total=int(binomial(len(inexact_rels), k)-1)))
		while 1:
			check(state)
			try:
				i,j = next(iterator)
				state ^^= fvs[64+i] ^^ fvs[64+j]
			except StopIteration: break
