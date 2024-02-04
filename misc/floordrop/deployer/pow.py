import asyncio
import datetime
import json
import os
import secrets
import sys
import time
import web3

MODULUS = 2**44497-1
CHALSIZE = 2**128

def sloth_root(x, p):
    # Lazy import, for production we don't need it
    import gmpy2
    exponent = (p + 1) // 4
    x = gmpy2.powmod(x, exponent, p)
    return int(x)

def sloth_square(y, p):
    # Lazy import, for production we don't need it
    import gmpy2
    y = gmpy2.mpz(y)
    y = gmpy2.powmod(y, 2, p)
    return int(y)

def get_challenge():
    x = secrets.randbelow(CHALSIZE)
    return x

def solve_challenge(x):
    y = sloth_root(x, MODULUS)
    return y

sysprint = print
def print(content):
    sysprint(f'[{datetime.datetime.now()}] {content}', flush=True)

CONTRACTS_DIR = os.getenv('CONTRACTS_DIR', '../contracts/build')
PROOF_OF_WORK_ABI = json.loads(open(f'{CONTRACTS_DIR}/ProofOfWork.abi').read())
PROOF_OF_WORK_BIN = bytes.fromhex(open(f'{CONTRACTS_DIR}/ProofOfWork.bin').read())

async def run_challenge(deployer: web3.Account, w3: web3.AsyncWeb3, dry_run: bool, debug_test: int, cleanup=None):
    gas_price = await w3.eth.gas_price
    gas_price = gas_price * 2
    chainid = await w3.eth.chain_id
    
    if gas_price > 1000 * 10**9:
        raise Exception(f"Current blockchain gas price {gas_price / 1e9} gwei is too high; please wait until traffic has settled down")

    if await w3.eth.get_balance(deployer.address) < 2 * 10**18:
        raise Exception(f"Challenge runner account {deployer.address} has insufficient balance; this is an infra issue.")

    print("Deploying challenge contract...")
    contract = w3.eth.contract(abi=PROOF_OF_WORK_ABI, bytecode=PROOF_OF_WORK_BIN)
    deployer_nonce = await w3.eth.get_transaction_count(deployer.address, 'latest')
    tx = await contract.constructor().build_transaction({
        'from': deployer.address,
        'gas': 1000000,
        'gasPrice': gas_price,
        'nonce': deployer_nonce, 
        'chainId': chainid,
    })
    tx = deployer.sign_transaction(tx)
    deployer_nonce += 1
    deploy_tx_hash = await w3.eth.send_raw_transaction(tx.rawTransaction)

    deploy_receipt = await w3.eth.wait_for_transaction_receipt(deploy_tx_hash, timeout=30)
    print(f'Challenge contract deployed at {deploy_receipt.contractAddress}')
    contract = w3.eth.contract(abi=PROOF_OF_WORK_ABI, address=deploy_receipt.contractAddress)

    if debug_test:
        helper_account = web3.Account.create()
        print(f'DEBUG: Helper account created: {helper_account.address}')
        tx = deployer.sign_transaction({
            'to': helper_account.address,
            'value': 10**17,
            'gas': 21000,
            'gasPrice': gas_price,
            'nonce': deployer_nonce,
            'chainId': chainid,
        })
        deployer_nonce += 1
        tx_hash = await w3.eth.send_raw_transaction(tx.rawTransaction)
        print(f'DEBUG: Sent 0.1 ETH to helper account {helper_account.address} in transaction {tx_hash.hex()}')
        await w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        helper_balance = await w3.eth.get_balance(helper_account.address)
        if helper_balance != 10**17:
            raise Exception(f'DEBUG: Helper account {helper_account.address} balance is {helper_balance}, expected 10**17')
        helper_nonce = await w3.eth.get_transaction_count(helper_account.address, 'latest')

    challenge_nonce = 2**255 | secrets.randbelow(2**256)
    print(f'Challenge nonce: {hex(challenge_nonce)}')
    print('Use this nonce when calling solveChallenge, i.e. solveChallenge(solution, nonce), remember solution is big endian bytes, and nonce is uint256')

    chal = get_challenge()
    if dry_run:
        print(f'MOCK: setChallenge will be called with: {chal}')
        print(f'MOCK: Waiting for 5 seconds to give you a chance to compute the solution...')
        await asyncio.sleep(5)
    
    if debug_test:
        print(f'DEBUG: Preparing the solution...')
        solution = solve_challenge(chal)

    gas_price = await w3.eth.gas_price
    gas_price = gas_price * 2
    if gas_price > 1000 * 10**9:
        raise Exception(f"Current blockchain gas price {gas_price / 1e9} gwei is too high; please wait until traffic has settled down")

    tx_set = await contract.functions.setChallenge(chal).build_transaction({
        'from': deployer.address,
        'gas': 100000,
        'gasPrice': gas_price,
        'nonce': deployer_nonce,
        'chainId': chainid,
    })
    tx_set = deployer.sign_transaction(tx_set)
    deployer_nonce += 1
    tx_expire = await contract.functions.expireChallenge().build_transaction({
        'from': deployer.address,
        'gas': 100000,
        'gasPrice': gas_price,
        'nonce': deployer_nonce,
        'chainId': chainid,
    })
    tx_expire = deployer.sign_transaction(tx_expire)
    deployer_nonce += 1
    if debug_test:
        tx_solve = await contract.functions.solveChallenge(solution.to_bytes((solution.bit_length() + 7)//8, byteorder='big'), challenge_nonce).build_transaction({
            'from': helper_account.address,
            'gas': 1000000,
            'gasPrice': gas_price,
            'nonce': helper_nonce,
            'chainId': chainid,
        })
        tx_solve = helper_account.sign_transaction(tx_solve)
        helper_nonce += 1

    print("The challenge will be set momentarily...")
    current_block = await w3.eth.block_number
    while current_block == await w3.eth.block_number:
        await asyncio.sleep(0.3)
    
    challenge_txn_time = time.time()
    tx_hash_set = await w3.eth.send_raw_transaction(tx_set.rawTransaction)
    print(f'Sent setChallenge transaction {tx_hash_set.hex()}; waiting 2secs before sending expireChallenge transaction...')

    if debug_test:
        tx_from_mempool = await w3.eth.get_transaction(tx_hash_set)
        if tx_from_mempool is None:
            raise Exception(f'DEBUG: setChallenge transaction {tx_hash_set.hex()} not found in mempool')
        print(f'Mempool tx data: {tx_from_mempool}')


    if debug_test == 1:
        await asyncio.sleep(1)
        tx_hash_solve = await w3.eth.send_raw_transaction(tx_solve.rawTransaction)
        print(f'DEBUG: Sent solveChallenge transaction {tx_hash_solve.hex()}')

    await asyncio.sleep(2 - (time.time() - challenge_txn_time))

    tx_expire_set = await w3.eth.send_raw_transaction(tx_expire.rawTransaction)
    print(f'Sent expireChallenge transaction {tx_expire_set.hex()}')
    elapsed = time.time() - challenge_txn_time
    if elapsed > 3:
        raise Exception(f'Could not send expireChallenge within time; this is an infra issue.')
    
    if debug_test == 2:
        await asyncio.sleep(1)
        tx_hash_solve = await w3.eth.send_raw_transaction(tx_solve.rawTransaction)
        print(f'DEBUG: Sent solveChallenge transaction LATE: {tx_hash_solve.hex()}')

    print(f'Waiting for transactions to finalize...')
    receipt_set = await w3.eth.wait_for_transaction_receipt(tx_hash_set, timeout=30)
    receipt_expire = await w3.eth.wait_for_transaction_receipt(tx_expire_set, timeout=30)
    print(f'Set challenge transaction finalized in block {receipt_set.blockNumber}')
    print(f'Expire challenge transaction finalized in block {receipt_expire.blockNumber}')
    if receipt_set.blockNumber != receipt_expire.blockNumber:
        raise Exception(f'setChallenge and expireChallenge transactions were finalized in different blocks; this is either a transient issue or an infra issue.')

    logs = await w3.eth.get_logs({
        'address': contract.address,
        'fromBlock': receipt_set.blockNumber,
        'toBlock': receipt_set.blockNumber,
        'topics': [
            '0x9446df33874beaaab82e58198bc4585bfe7c74ef6f8e1e24f6739d853b4d5145',
            hex(challenge_nonce)
        ]})

    if cleanup:
        tx_hash = tx_hash_set.hex()
        result = 'noflag'
        if len(logs) > 0:
            if dry_run:
                result = 'mockflag'
            else:
                result = 'gotflag'
        await cleanup(tx_hash, result)
    if len(logs) == 0:
        print(f'We did not find the correct GotFlag event. Better luck next time!')
        return
    for log in logs:
        print(f'GotFlag event with correct nonce found in setChallenge transaction {log.transactionHash.hex()}!')
    if dry_run:
        print('Congratulations! You have successfully solved the mock challenge! The real flag would be printed here if this was a real one. Good luck!')
    else:
        print('Congratulations! You have successfully solved the challenge! Here is your flag: dice{fr0ntrunn1ng_1s_n0t_ju5t_f0r_s4ndw1ch1ng_f8d9f834}')


async def main():
    w3 = web3.AsyncWeb3(web3.AsyncHTTPProvider('https://floordrop-rpc.hpmv.dev'))
    deployer = web3.Account.from_key(sys.argv[1])
    await run_challenge(deployer, w3, False, 1)

if __name__ == "__main__":
    asyncio.run(main())