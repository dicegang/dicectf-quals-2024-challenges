#!/usr/local/bin/python
import os
import time
from pymongo import MongoClient

sysprint = print
def print(content):
    sysprint(content, flush=True)
    
async def main():
    print('Welcome to Floordrop: Time Warp! Can you pick up the flag in time?')
    print('  1. Solve a mock challenge (extra time to solve)')
    print('  2. Solve the real challenge')
    print('  3. Exit')
    choice = input('Please choose an option: ')
    if choice == '3':
        print('Goodbye!')
        return
    if choice not in ['1', '2']:
        print('Invalid choice, good bye!')
        return

    print("Preparing challenge...")
    import web3
    import pow
    db =  MongoClient(os.getenv('MONGODB_URI'))['ctf']
    operators = db.get_collection('operators')
    attempts = db.get_collection('attempts')
    w3 = web3.AsyncWeb3(web3.AsyncHTTPProvider('https://floordrop-rpc.hpmv.dev'))
    operator = operators.find_one_and_update({'state': 'ready'}, {'$set': {'state': 'busy'}})
    if operator == None:
        print('No operator available to run the challenge. This is an infra issue, please contact an admin.')
        return
    operator_account = web3.Account.from_key(operator['key'])

    attempt = attempts.insert_one({'timestamp': time.time(), 'mock': choice == '1', 'status': 'pending', 'tx_hash': '', 'result': ''}).inserted_id

    async def cleanup(tx_hash, result):
        remaining_balance = await w3.eth.get_balance(operator_account.address, 'latest')
        if remaining_balance > 2 * 10 ** 18:
            operators.update_one({'_id': operator['_id']}, {'$set': {'state': 'ready'}})
        else:
            operators.update_one({'_id': operator['_id']}, {'$set': {'state': 'exhausted'}})
        attempts.update_one({'_id': attempt}, {'$set': {'status': 'completed', 'tx_hash': tx_hash, 'result': result}})

    try:
        await pow.run_challenge(operator_account, w3, choice == '1', 0, cleanup)

    except Exception as e:
        attempts.update_one({'_id': attempt}, {'$set': {'status': 'failed', 'result': str(e)}})
        print(f'Error running the challenge, please try again or if the issue persists, contact an admin: {e}')

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())