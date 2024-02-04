import streamlit as st
from pymongo import MongoClient
import web3
import os
import pow

st.set_page_config(
    page_title="Faucet",
    page_icon=":game_die:",
)


def get_operators():
    client = MongoClient(os.getenv("MONGODB_URI"))
    db = client["ctf"]
    return db.get_collection("operators")


operators = get_operators()
w3 = web3.Web3(web3.HTTPProvider("https://floordrop-rpc.hpmv.dev"))


def cleanup(operator_account):
    remaining_balance = w3.eth.get_balance(operator_account.address, "latest")
    if remaining_balance > 2 * 10**18:
        operators.update_one({"_id": operator["_id"]}, {"$set": {"state": "ready"}})
    else:
        operators.update_one({"_id": operator["_id"]}, {"$set": {"state": "exhausted"}})


def distribute_funds(operator_account, destination_address):
    gas_price = w3.eth.gas_price * 5
    chainid = w3.eth.chain_id
    nonce = w3.eth.get_transaction_count(operator_account.address, "latest")
    tx = {
        "to": destination_address,
        "value": 10**18,
        "gas": 21000,
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": chainid,
    }

    tx = operator_account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(tx.rawTransaction)

    print(
        f"Sent 1 DICE from operator {operator_account.address} to {destination_address}: {tx_hash.hex()}"
    )
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, 30)
    if receipt.status != 1:
        print(f"Distribution transaction {tx_hash.hex()} failed; receipt: {receipt}")
        raise Exception(
            f"Distribution transaction {tx_hash.hex()} failed. Are you sure the target address is a wallet?"
        )

    nonce += 1
    print(f"Tx {tx_hash.hex()} confirmed")

    return tx_hash


destination_address = st.text_input("Enter a wallet address:")

SOLVER_URL = 'https://goo.gle/kctf-pow'

if 'challenge' not in st.session_state:
    st.session_state['challenge'] = pow.get_challenge(int(os.getenv('POW', '1000')))
challenge = st.session_state['challenge']

st.write("To prevent spam, please also submit a proof of work; use the following script and paste the solution:")
st.code("python3 <(curl -sSL {}) solve {}".format(SOLVER_URL, challenge), language="bash")

pow_solution = st.text_input("Enter the proof of work solution:")


if st.button("Get DICE"):
    if not pow.verify_challenge(challenge, pow_solution):
        if not pow_solution:
            st.write("Please submit a proof of work solution.")
        else:
            st.write("Proof of work failed.")
        st.stop()

    if not web3.Web3.is_address(destination_address):
        st.write("Please specify a valid address.")
        st.stop()
        
    destination_address = web3.Web3.to_checksum_address(destination_address)
    operator = operators.find_one_and_update(
        {"state": "ready"}, {"$set": {"state": "busy"}}
    )
    if operator == None:
        st.write(
            "No operators have enough balance :( This is an infra issue, please contact an admin."
        )
        st.stop()

    del st.session_state['challenge'] # delete challenge to prevent reusing the pow
    operator_account = web3.Account.from_key(operator["key"])
    st.write("Please wait...")
    tx_hash = distribute_funds(operator_account, destination_address)
    st.markdown(
        f"Sent 1 DICE from `{operator_account.address}` to `{destination_address}`: `{tx_hash.hex()}`"
    )
    cleanup(operator_account)
