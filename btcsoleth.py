import secrets
from hdwallet import HDWallet
from hdwallet.symbols import BTC, ETH
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base58
import re
from urllib.request import urlopen
from time import sleep
import json
import requests

# Constants
ETHERSCAN_API_KEY = '2EM2PYTD6MTQEPKCKHHP92V1BWZE5DYVJX'
SATOSHIS_PER_BTC = 1e+8

def generate_random_hex64():
    """Generates a random 64-character hexadecimal string."""
    return secrets.token_hex(32)

def generate_bitcoin_addresses(private_key, num_addresses):
    """Generates Bitcoin addresses from the given private key."""
    addresses = []
    for _ in range(num_addresses):
        hdwallet = HDWallet(symbol=BTC)
        hdwallet.from_private_key(private_key=private_key)

        addresses.append({
            "p2pkh": hdwallet.p2pkh_address(),
            "p2sh": hdwallet.p2sh_address(),
            "p2wpkh": hdwallet.p2wpkh_address(),
            "p2wpkh_in_p2sh": hdwallet.p2wpkh_in_p2sh_address(),
            "p2wsh": hdwallet.p2wsh_address(),
            "p2wsh_in_p2sh": hdwallet.p2wsh_in_p2sh_address()
        })

    return addresses

def generate_solana_address(private_key):
    """Generates a Solana address from the given private key."""
    private_key_bytes = bytes.fromhex(private_key)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return base58.b58encode(public_key_bytes).decode('utf-8')

def generate_ethereum_address(private_key):
    """Generates an Ethereum address from the given private key."""
    hdwallet = HDWallet(symbol=ETH)
    hdwallet.from_private_key(private_key=private_key)
    return hdwallet.p2pkh_address()

def check_balance(address):
    """Checks the balance of a Bitcoin address."""
    check_address = address.strip()
    parse_address_structure = re.match(r' *(1[0-9A-Za-z]{25,34}|3[0-9A-Za-z]{25,34}|bc1[0-9A-Za-z]{25,100})', check_address)
    
    if parse_address_structure is None:
        print("\nThis Bitcoin Address is invalid: " + check_address)
        return None

    check_address = parse_address_structure.group(1)
    
    for attempt in range(1):  # Retry up to 5 times
        try:
            response = urlopen(f"https://blockchain.info/address/{check_address}?format=json", timeout=1.5)
            json_data = json.loads(response.read().decode('utf-8'))
            balance = json_data['final_balance'] / SATOSHIS_PER_BTC
            return balance
        except Exception as e:
            print(f"Attempt {attempt + 1}: Error retrieving balance for {check_address}: {str(e)}")
            sleep(1)  # Wait before retrying
    
    print(f"Failed to retrieve data for address: {check_address}.")
    return None

def check_balance_rpc(url, address):
    """Checks the balance of a Solana address using RPC."""
    headers = {"Content-Type": "application/json"}
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    })

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=1.5)
        result = response.json()

        if 'error' in result:
            return 0  # Error retrieving balance

        if 'result' in result and 'value' in result['result']:
            return result['result']['value']
        
        return 0  # Unexpected response structure
    except requests.exceptions.RequestException:
        return None  # Connection error

def format_balance(lamports):
    """Formats the balance from lamports to SOL."""
    sol_balance = lamports / 1_000_000_000  # Convert lamports to SOL
    return f"◎{sol_balance:.9f}"  # Format to 9 decimal places

def save_to_file(btc_address, solana_address, eth_address, private_key_bytes, btc_balance, solana_balance, eth_balance):
    """Saves the addresses and their balances to a file if any balance is greater than zero."""
    with open("found/btcsoleth.txt", "a") as file:
        file.write(f"Private Key: {private_key_bytes.hex()}\n")
        if btc_balance > 0:
            file.write(f"Bitcoin Address: {btc_address}, Balance: {btc_balance} BTC\n")
        if solana_balance > 0:
            file.write(f"Solana Address: {solana_address}, Balance: {format_balance(solana_balance)}\n")
        if eth_balance > 0:
            file.write(f"Ethereum Address: {eth_address}, Balance: {eth_balance} ETH\n")
        file.write("\n")

def check_address_balances_and_save(rpc_urls, solana_address, private_key_bytes):
    """Checks the balance of a Solana address and returns it."""
    balance = None
    for rpc_url in rpc_urls:
        balance = check_balance_rpc(rpc_url, solana_address)
        if balance is not None:
            break

    return balance

def check_ethereum_balance(address):
    """Checks the Ethereum balance of an address."""
    url = f'https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}'
    
    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            if 'result' in data and data['result'] != '':
                balance = int(data['result']) / 10**18  # Convert from wei to Ether
                return balance
            
            print(f"Balance information not found or invalid for address: {address}")
            return None
        
        print(f"Failed to retrieve balance for address: {address}. Status code: {response.status_code}")
        return None
    
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while checking Ethereum balance: {e}")
        return None

def main():
    num_addresses = int(input("Enter the number of addresses to generate: "))
    
    for _ in range(num_addresses):
        private_key = generate_random_hex64()
        
        print("\n____________________________________________________________________________")

        print("\033[1;34mPrivate Key:\033[0m \033[92m\033[1m\033[4m", private_key, "\033[0m")

        btc_addresses = generate_bitcoin_addresses(private_key, 1)  # Generate one set of addresses per key
        
        print("\033[97mBitcoin Addresses:\033[0m")
        
        btc_balance = None
        
        for address in btc_addresses:
            for address_type, address_value in address.items():
                print(f"\033[93m{address_type}:\033[0m \033[97m\033[1m\033[4m{address_value}\033[0m")
                btc_balance = check_balance(address_value)
                if btc_balance is not None:
                    print(f"\033[97mBalance:\033[0m \033[1;32m\033[1m{btc_balance} BTC\033[0m")

        solana_address = generate_solana_address(private_key)
        
        print(f"\033[93mSolana:\033[0m \033[97\033[1m\033[4m{solana_address}\033[0m")

        rpc_urls = [
            "https://api.mainnet-beta.solana.com",
            "https://api.testnet.solana.com",
            "https://api.devnet.solana.com"
        ]
        
        solana_balance = check_address_balances_and_save(rpc_urls, solana_address, private_key.encode())
        
        if solana_balance is not None:
            print(f"\033[93mSolana Balance:\033[0m \033[1;32m\033[1m{format_balance(solana_balance)}\033[0m")

        eth_address = generate_ethereum_address(private_key)
        
        print(f"\033[93mEthereum:\033[0m \033[97m\033[1m\033[4m{eth_address}\033[0m")
        
        eth_balance = check_ethereum_balance(eth_address)
        
        if eth_balance is not None:
            print(f"\033[93mBalance:\033[0m \033[1;32m\033[1m{eth_balance} ETH\033[0m")

        # Save to file only if any balances are greater than zero
        if (btc_balance and btc_balance > 0) or (solana_balance and solana_balance > 0) or (eth_balance and eth_balance > 0):
            save_to_file(btc_addresses[-1]['p2pkh'], solana_address, eth_address, private_key.encode(), btc_balance or 0.0, solana_balance or 0.0, eth_balance or 0.0)

if __name__ == "__main__":
    main()
