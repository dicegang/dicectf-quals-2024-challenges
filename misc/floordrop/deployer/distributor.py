import asyncio
import datetime
import json
import os
from typing import List
from pymongo import MongoClient
import web3

CONTRACTS_DIR = os.getenv('CONTRACTS_DIR', '../contracts/build')
DISTRIBUTOR_ABI = json.loads(open(f'{CONTRACTS_DIR}/Distributor.abi').read())
DISTRIBUTOR_BIN = bytes.fromhex(open(f'{CONTRACTS_DIR}/Distributor.bin').read())
DESIRED_ACCOUNTS = int(os.getenv('DESIRED_ACCOUNTS', '10'))

sysprint = print
def print(content):
    sysprint(f'[{datetime.datetime.now()}] {content}', flush=True)
    
class Distributor:
    def __init__(self, w3: web3.AsyncWeb3, faucet_key: str):
        self.faucet = web3.Account.from_key(faucet_key)
        self.client = MongoClient(os.getenv('MONGODB_URI'))
        self.operators = self.client['ctf'].get_collection('operators')
        self.w3 = w3

    async def init(self):
        ready = self.operators.count_documents({'state': 'ready'})
        print(f'Mongodb sanity check: have {ready} operators')

        self.chainid = await self.w3.eth.chain_id
        gas_price = (await self.w3.eth.gas_price) * 5
        faucet_nonce = await self.w3.eth.get_transaction_count(self.faucet.address, 'latest')
        distributor = self.w3.eth.contract(abi=DISTRIBUTOR_ABI, bytecode=DISTRIBUTOR_BIN)
        tx = await distributor.constructor().build_transaction({
            'from': self.faucet.address,
            'gas': 1000000,
            'gasPrice': gas_price,
            'nonce': faucet_nonce,
            'chainId': self.chainid
        })
        faucet_nonce += 1
        tx = self.faucet.sign_transaction(tx)
        tx_hash = await self.w3.eth.send_raw_transaction(tx.rawTransaction)
        receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash)
        self.distributor = self.w3.eth.contract(abi=DISTRIBUTOR_ABI, address=receipt.contractAddress)
        print(f'Distributor contract deployed at {receipt.contractAddress}')
    
    async def update_operators(self):
        ready = self.operators.count_documents({'state': 'ready'})
        if ready >= DESIRED_ACCOUNTS:
            return
        to_add = min(100, DESIRED_ACCOUNTS + 10 - ready)
        print(f'Have {ready} operators, desired {DESIRED_ACCOUNTS}, adding {to_add} more...')
        gas_price = (await self.w3.eth.gas_price) * 5
        operators: List[web3.Account] = [web3.Account.create() for _ in range(to_add)]
        nonce = await self.w3.eth.get_transaction_count(self.faucet.address, 'latest')
        tx = await self.distributor.functions.send([op.address for op in operators], 100 * 10**18).build_transaction({
            'from': self.faucet.address,
            'gas': 4000000,
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': self.chainid,
            'value': to_add * 100 * 10**18
        })
        nonce += 1
        tx = self.faucet.sign_transaction(tx)
        tx_hash = await self.w3.eth.send_raw_transaction(tx.rawTransaction)
        print(f'Sent transaction to add {to_add} operators in transaction {tx_hash.hex()}')
        receipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash, 30)
        if receipt.status != 1:
            print(f'Distribution transaction {tx_hash.hex()} failed; receipt: {receipt}')
            # throttle.. because this likely is a setup issue.
            await asyncio.sleep(60)
            raise Exception(f'Distribution transaction {tx_hash.hex()} failed')
        
        print(f'Tx {tx_hash.hex()} confirmed')
        self.operators.insert_many([{'address': op.address, 'key': op.key, 'state': 'ready'} for op in operators])

    async def run(self):
        await self.init()
        while True:
            try:
                await self.update_operators()
            except Exception as e:
                print(f'Error: {e}')
            await asyncio.sleep(1)

async def main():
    w3 = web3.AsyncWeb3(web3.AsyncHTTPProvider('https://floordrop-rpc.hpmv.dev'))
    distributor = Distributor(w3, os.getenv('FAUCET_KEY'))
    await distributor.run()

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
