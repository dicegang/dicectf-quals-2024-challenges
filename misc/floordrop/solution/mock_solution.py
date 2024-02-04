import asyncio
import json
from pwn import *
import gmpy2
import web3

MODULUS = 2**44497-1

def sloth_root(x, p):
    exponent = (p + 1) // 4
    x = gmpy2.powmod(x, exponent, p)
    return int(x)

def solve_challenge(x):
    y = sloth_root(x, MODULUS)
    return y

CONTRACTS_DIR = os.getenv('CONTRACTS_DIR', '../contracts/build')
PROOF_OF_WORK_ABI = json.loads(open(f'{CONTRACTS_DIR}/ProofOfWork.abi').read())

async def main():
    key = sys.argv[1]
    wallet = web3.Account.from_key(key)

    w3 = web3.AsyncWeb3(web3.AsyncHTTPProvider('https://floordrop-rpc.hpmv.dev'))
    my_nonce = await w3.eth.get_transaction_count(wallet.address, 'latest')

    p = remote('mc.ax', 32123)
    p.sendlineafter(b'option: ', '1')
    p.recvuntil('Challenge contract deployed at ')
    contract = p.recvline().strip().decode('ascii')
    print('contract:', contract)
    contract = w3.eth.contract(abi=PROOF_OF_WORK_ABI, address=contract)
    p.recvuntil('Challenge nonce: ')
    nonce = int(p.recvline().strip(), 16)
    print('nonce:', nonce)
    p.recvuntil('setChallenge will be called with: ')
    chal = int(p.recvline().strip())
    print('chal:', chal)
    sol = solve_challenge(chal)
    sol = sol.to_bytes((sol.bit_length() + 7) // 8, 'big')

    p.recvuntil('setChallenge transaction ')
    txhash = p.recvline().split(b';')[0].decode('ascii')
    print('txhash:', txhash)

    tx = await w3.eth.get_transaction(txhash)
    gas_price = tx['gasPrice']

    sol_tx = await contract.functions.solveChallenge(sol, nonce).build_transaction({
        'gas': 1000000,
        'gasPrice': gas_price,
        'nonce': my_nonce,
        'chainId': 133713371337,
    })
    sol_tx = wallet.sign_transaction(sol_tx)
    sol_tx_hash = await w3.eth.send_raw_transaction(sol_tx.rawTransaction)
    print('sol_tx_hash:', sol_tx_hash)
    p.interactive()

asyncio.run(main())