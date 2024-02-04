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
SOLUTION_ABI = json.loads(open(f'{CONTRACTS_DIR}/Solution.abi').read())
SOLUTION_BIN = bytes.fromhex(open(f'{CONTRACTS_DIR}/Solution.bin').read())

async def main():
    key = sys.argv[1]
    wallet = web3.Account.from_key(key)
    w3 = web3.AsyncWeb3(web3.AsyncHTTPProvider('https://floordrop-rpc.hpmv.dev'))
    my_nonce = await w3.eth.get_transaction_count(wallet.address, 'latest')

    gas_price = await w3.eth.gas_price * 2
    contract = w3.eth.contract(abi=SOLUTION_ABI, bytecode=SOLUTION_BIN)
    tx = await contract.constructor().build_transaction({
        'from': wallet.address,
        'gas': 1000000,
        'gasPrice': gas_price,
        'nonce': my_nonce,
        'chainId': 133713371337,
    })
    tx = wallet.sign_transaction(tx)
    tx_hash = await w3.eth.send_raw_transaction(tx.rawTransaction)
    print('Deploy:', tx_hash.hex())
    receipt = await w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise ValueError('Contract deployment failed')
    print('Deployed at:', receipt.contractAddress)
    solution_contract = w3.eth.contract(abi=SOLUTION_ABI, address=receipt.contractAddress)

    my_nonce = await w3.eth.get_transaction_count(wallet.address, 'latest')

    p = remote('mc.ax', 32123)
    p.sendlineafter(b'option: ', '2')
    p.recvuntil('Challenge contract deployed at ')
    contract = p.recvline().strip().decode('ascii')
    print('contract:', contract)
    p.recvuntil('Challenge nonce: ')
    nonce = int(p.recvline().strip(), 16)
    print('nonce:', nonce)

    p.recvuntil('setChallenge transaction ')
    txhash = p.recvline().split(b';')[0].decode('ascii')
    print('txhash:', txhash)

    tx = await w3.eth.get_transaction(txhash)
    gas_price = tx['gasPrice']

    backrun = await solution_contract.functions.solveChallenge(random.randbytes(5562), nonce).build_transaction({
        'gas': 1000000,
        'gasPrice': gas_price,
        'nonce': my_nonce + 1,
        'chainId': 133713371337,
    })
    backrun = wallet.sign_transaction(backrun)
    backrun_hash = await w3.eth.send_raw_transaction(backrun.rawTransaction)
    print('backrun_hash:', backrun_hash)

    chal = web3.Web3.to_int(web3.Web3.to_bytes(tx['input'])[4:])
    print('chal:', chal)
    sol = solve_challenge(chal)
    sol = sol.to_bytes((sol.bit_length() + 7) // 8, 'big')

    sol_tx = await solution_contract.functions.feedSolution(sol, contract).build_transaction({
        'gas': 8000000,
        'gasPrice': gas_price * 2,
        'nonce': my_nonce,
        'chainId': 133713371337,
    })
    sol_tx = wallet.sign_transaction(sol_tx)
    sol_tx_hash = await w3.eth.send_raw_transaction(sol_tx.rawTransaction)
    print('sol_tx_hash:', sol_tx_hash)
    p.interactive()

asyncio.run(main())