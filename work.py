import json
import asyncio
import aiohttp
import time
from datetime import datetime
from decimal import Decimal
from web3 import Web3
from eth_account import Account
from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message
import platform
import re
from web3.exceptions import ContractLogicError, BadFunctionCallOutput
import logging
import logging.handlers
import sys

if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Logging setup with UTF-8 encoding
LOG_FILE = "cmd_log.txt"
class CustomFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.utcnow().strftime("%H:%M:%S")

# Custom StreamHandler to force UTF-8 encoding
class UTF8StreamHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__(sys.stdout)
        self.stream = sys.stdout
        self.stream.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'),
        UTF8StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

CONFIG_PATH = "config.json"
TRADE_HISTORY_PATH = "trade_history.json"

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)

def append_trade_history(trade_data):
    try:
        with open(TRADE_HISTORY_PATH, "r") as f:
            history = json.load(f)
    except:
        history = []
    history.append(trade_data)
    with open(TRADE_HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2)

def is_blacklisted(token_address):
    try:
        checksum_address = Web3.to_checksum_address(token_address)
        with open("blacklist.json", "r") as f:
            blacklist = json.load(f)
        logger.info(f"Security Check - Checking blacklist for token {checksum_address}")
        return checksum_address.lower() in [addr.lower() for addr in blacklist]
    except (ValueError, Exception) as e:
        logger.error(f"Security Check - Blacklist check failed for {token_address}: {e}")
        return False

async def resolve_contract_to_ticker(contract_address):
    try:
        if not Web3.is_address(contract_address):
            logger.error(f"Contract Resolution - Invalid contract address: {contract_address}")
            return None
        async with aiohttp.ClientSession() as session:
            url = f"https://api.dexscreener.com/latest/dex/tokens/{contract_address}?chain=base"
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    logger.error(f"Contract Resolution - DexScreener API failed for {contract_address}: HTTP {resp.status}")
                    return None
                data = await resp.json()
                pairs = data.get("pairs", [])
                for pair in pairs:
                    if pair["chainId"].lower() in ("8453", "base"):
                        base_token = pair["baseToken"]["address"].lower()
                        quote_token = pair["quoteToken"]["address"].lower()
                        if base_token == contract_address.lower():
                            return f"{pair['baseToken']['symbol']}/{pair['quoteToken']['symbol']}"
                        elif quote_token == contract_address.lower():
                            return f"{pair['quoteToken']['symbol']}/{pair['baseToken']['symbol']}"
                logger.warning(f"Contract Resolution - No valid pair found for contract {contract_address}")
                return None
    except Exception as e:
        logger.error(f"Contract Resolution - Error resolving contract {contract_address}: {e}")
        return None

config = load_config()

web3 = Web3(Web3.HTTPProvider(config["base_rpc"]))

try:
    if not web3.is_connected():
        raise Exception("Failed to connect to Base RPC.")
    logger.info(f"System Event - Connected to Base RPC: {config['base_rpc']}")
except Exception as e:
    logger.error(f"System Event - RPC connection error: {e}")
    exit(1)

account = Account.from_key(config["private_key"])
WALLET_ADDRESS = Web3.to_checksum_address(config["wallet_address"])
CHAIN_ID = web3.eth.chain_id

UNISWAP_V2_ROUTER = Web3.to_checksum_address("0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24")
UNISWAP_FACTORY_ADDRESS = Web3.to_checksum_address("0x327Df1E6de05895d2ab08513aaDD9313Fe505d86")
WETH_ADDRESS = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")
VIRTUAL_ADDRESS = Web3.to_checksum_address("0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b")

if VIRTUAL_ADDRESS == WETH_ADDRESS:
    logger.error("System Event - VIRTUAL_ADDRESS is set to WETH address.")
    exit(1)

TRAILING_PCT = config.get("trailing_pct", 10)
TSL_ENABLED = config.get("tsl_enabled", False)

UNISWAP_ROUTER_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactETHForTokens",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactTokensForETH",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactTokensForTokens",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"}
        ],
        "name": "getAmountsOut",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

UNISWAP_FACTORY_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "token0", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "token1", "type": "address"},
            {"indexed": False, "internalType": "address", "name": "pair", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "", "type": "uint256"}
        ],
        "name": "PairCreated",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "tokenA", "type": "address"},
            {"internalType": "address", "name": "tokenB", "type": "address"}
        ],
        "name": "getPair",
        "outputs": [{"internalType": "address", "name": "pair", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    }
]

ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_spender", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [
            {"name": "_owner", "type": "address"},
            {"name": "_spender", "type": "address"}
        ],
        "name": "allowance",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

SUPPORTING_FEE_ABI = [
    {
        "name": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
        "type": "function",
        "inputs": [
            {"name": "amountIn", "type": "uint256"},
            {"name": "amountOutMin", "type": "uint256"},
            {"name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    }
]

router_contract = web3.eth.contract(address=UNISWAP_V2_ROUTER, abi=UNISWAP_ROUTER_ABI)
factory_contract = web3.eth.contract(address=UNISWAP_FACTORY_ADDRESS, abi=UNISWAP_FACTORY_ABI)

BOT_TOKEN = config["telegram_token"]
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

monitor_task = None
active_trade = None
stop_monitoring = False
ALLOWED_CHAT_IDS = {config["allowed_chat_id"]}
notified_blacklisted_tokens = set()

def is_allowed(chat_id):
    return chat_id in ALLOWED_CHAT_IDS

async def check_security(contract_address):
    async with aiohttp.ClientSession() as session:
        goplus_ok = False
        honeypot_ok = False
        async def check_goplus():
            nonlocal goplus_ok
            try:
                goplus_url = f"https://api.gopluslabs.io/api/v1/token_security/{CHAIN_ID}?contract_addresses={contract_address}"
                logger.info(f"Security Check - GoPlus API check for {contract_address}")
                async with session.get(goplus_url, timeout=10) as r3:
                    if r3.status == 200:
                        res3 = await r3.json()
                        goplus_ok = res3.get("result", {}).get(contract_address.lower(), {}).get("is_honeypot", "0") == "0"
                    else:
                        logger.error(f"Security Check - GoPlus API failed: HTTP {r3.status}")
            except Exception as e:
                logger.error(f"Security Check - GoPlus check failed for {contract_address}: {e}")

        async def check_honeypot():
            nonlocal honeypot_ok
            try:
                honeypot_url = f"https://api.honeypot.is/v2/IsHoneypot?address={contract_address}&chainID={CHAIN_ID}"
                logger.info(f"Security Check - Honeypot API check for {contract_address}")
                async with session.get(honeypot_url, timeout=10) as r2:
                    if r2.status == 200:
                        res2 = await r2.json()
                        is_honeypot = res2.get("honeypotResult", {}).get("isHoneypot", True)
                        honeypot_ok = not is_honeypot
                    else:
                        logger.error(f"Security Check - Honeypot API failed: HTTP {r2.status}")
            except Exception as e:
                logger.error(f"Security Check - Honeypot check failed for {contract_address}: {e}")

        await asyncio.gather(check_goplus(), check_honeypot())
        logger.info(f"Security Check - Result for {contract_address}: GoPlus={goplus_ok}, Honeypot={honeypot_ok}")
        return goplus_ok and honeypot_ok

async def run_approve_if_needed(token_address):
    try:
        token_contract = web3.eth.contract(address=VIRTUAL_ADDRESS, abi=ERC20_ABI)
        virtual_amount = web3.to_wei(config.get("virtual_amount", 0.5), "ether")
        allowance = token_contract.functions.allowance(WALLET_ADDRESS, UNISWAP_V2_ROUTER).call()
        if allowance < virtual_amount:
            logger.info(f"Trade Initiation - Approving {web3.from_wei(virtual_amount, 'ether')} VIRTUAL for Uniswap router")
            nonce = web3.eth.get_transaction_count(WALLET_ADDRESS)
            approve_txn = token_contract.functions.approve(UNISWAP_V2_ROUTER, virtual_amount).build_transaction({
                'from': WALLET_ADDRESS,
                'gas': 100000,
                'maxPriorityFeePerGas': web3.eth.max_priority_fee,
                'maxFeePerGas': web3.eth.max_priority_fee + web3.eth.gas_price,
                'nonce': nonce
            })
            signed_approve = web3.eth.account.sign_transaction(approve_txn, private_key=config["private_key"])
            tx_hash_approve = web3.eth.send_raw_transaction(signed_approve.raw_transaction)
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash_approve, timeout=60)
            if receipt.status == 0:
                logger.error(f"Trade Initiation - Approval transaction reverted: {tx_hash_approve.hex()}")
                raise ContractLogicError("Approval transaction reverted")
            logger.info(f"Trade Initiation - Approval successful: {tx_hash_approve.hex()}")
        else:
            logger.info("Trade Initiation - Token already approved for Uniswap router")
    except Exception as e:
        logger.error(f"Trade Initiation - Approval failed for token {token_address}: {e}")

async def monitor_pair_created():
    global stop_monitoring
    logger.info("Monitoring Event - PairCreated event listener started")
    event_signature = "PairCreated(address,address,address,uint256)"
    raw_hash = web3.keccak(text=event_signature).hex()
    event_signature_hash = "0x" + raw_hash[2:].rjust(64, '0')
    latest_block = web3.eth.block_number

    try:
        with open("blacklist.json", "r") as f:
            blacklist = json.load(f)
    except:
        blacklist = []

    while not stop_monitoring:
        if stop_monitoring:  # Check at the start of the loop
            logger.info("Monitoring Event - PairCreated monitoring stopped")
            break
        try:
            logs = web3.eth.get_logs({
                "fromBlock": latest_block,
                "toBlock": "latest",
                "address": UNISWAP_FACTORY_ADDRESS,
                "topics": [event_signature_hash]
            })
            latest_block = web3.eth.block_number + 1

            for log in logs:
                if stop_monitoring:  # Check before processing each log
                    logger.info("Monitoring Event - PairCreated monitoring stopped during log processing")
                    break
                topics = log["topics"]
                if len(topics) < 3 or any(len(topic.hex()) != 66 for topic in topics):
                    logger.warning(f"Pair Detection - Skipping invalid log: {topics}")
                    continue
                token0 = Web3.to_checksum_address("0x" + topics[1].hex()[-40:])
                token1 = Web3.to_checksum_address("0x" + topics[2].hex()[-40:])
                pair_address = Web3.to_checksum_address("0x" + log["data"].hex()[-40:])

                if VIRTUAL_ADDRESS in (token0, token1):
                    target_token = token1 if token0 == VIRTUAL_ADDRESS else token0
                    is_reverse = token0 == VIRTUAL_ADDRESS
                    pair_symbol = f"{target_token[:6]}.../{VIRTUAL_ADDRESS[:6]}..." if not is_reverse else f"{VIRTUAL_ADDRESS[:6]}.../{target_token[:6]}..."
                    logger.info(f"Pair Detection - Found pair {pair_symbol}, Address: {pair_address}, Reverse: {is_reverse}")

                    if is_blacklisted(target_token):
                        logger.warning(f"Security Check - Token {target_token} blacklisted, Pair: {pair_symbol}")
                        if target_token.lower() not in notified_blacklisted_tokens:
                            await bot.send_message(
                                chat_id=config["allowed_chat_id"],
                                text=f"⚠️ Token {target_token} ({pair_symbol}) is blacklisted. Please set a new coin using /set coin <PAIR or ADDRESS>. Bot stopped."
                            )
                            notified_blacklisted_tokens.add(target_token.lower())
                        continue

                    config["pair"] = f"{target_token[:6]}/VIRTUAL" if not is_reverse else f"VIRTUAL/{target_token[:6]}"
                    config["target_token_address"] = target_token
                    save_config(config)

                    if await check_security(target_token):
                        logger.info(f"Security Check - Token {target_token} passed for {pair_symbol}")
                        tx_hash, amount_in_vrl, tokens_bought = await execute_buy_trade(target_token, is_reverse)
                        if tx_hash:
                            logger.info(f"Trade Execution - Buy order filled for {pair_symbol}, {amount_in_vrl} VIRTUAL, {tokens_bought:.2f} tokens, TX: {tx_hash.hex()}")
                            await bot.send_message(
                                chat_id=config["allowed_chat_id"],
                                text=f"⚡ New pair {pair_symbol} traded! TX: https://basescan.org/tx/{tx_hash.hex()}"
                            )
                        else:
                            logger.error(f"Trade Execution - Buy order failed for {pair_symbol}")
                    else:
                        logger.error(f"Security Check - Token {target_token} failed for {pair_symbol}")

            await asyncio.sleep(0.05)
        except Exception as e:
            logger.error(f"Monitoring Event - PairCreated event error: {e}")
            await asyncio.sleep(0.5)

async def monitor_trade():
    global active_trade
    while active_trade:
        try:
            if not active_trade:
                break
            token_address = active_trade["token_address"]
            token_balance = active_trade["tokens_bought"]
            pair_symbols = active_trade["pair"].upper().split("/")
            output_token = WETH_ADDRESS if pair_symbols[1] == "WETH" else VIRTUAL_ADDRESS
            path = [token_address, output_token]
            try:
                amounts = router_contract.functions.getAmountsOut(token_balance, path).call()
                vrl_out = amounts[-1]
                vrl_out_ether = web3.from_wei(vrl_out, 'ether')
                token_balance_ether = web3.from_wei(token_balance, 'ether')
                exit_price = float(vrl_out_ether) / float(token_balance_ether) if token_balance_ether > 0 else 0
            except Exception as e:
                logger.error(f"Trade Monitoring - getAmountsOut error: {e}")
                exit_price = 0
            entry_price = active_trade.get("entry_price", 0)
            profit_pct = ((exit_price - entry_price) / entry_price) * 100 if entry_price > 0 else 0
            loss_pct = ((entry_price - exit_price) / entry_price) * 100 if entry_price > 0 else 0

            # Update max_profit if current profit is higher
            if "max_profit" not in active_trade or profit_pct > active_trade["max_profit"]:
                active_trade["max_profit"] = profit_pct
                logger.info(f"Trade Monitoring - New max profit for {active_trade['pair']}: {profit_pct:.1f}%")

            # Dynamic TSL logic: Set TSL to nearest 10% multiple if profit crosses 10.01%, 20.01%, etc.
            if TSL_ENABLED and profit_pct >= 10.01:
                # Calculate the TSL level (nearest 10% multiple)
                tsl_level = int(profit_pct / 10) * 10  # E.g., 10.01% -> 10%, 20.01% -> 20%, 100.01% -> 100%
                if "tsl_level" not in active_trade or tsl_level > active_trade["tsl_level"]:
                    active_trade["tsl_level"] = tsl_level
                    logger.info(f"Trade Monitoring - TSL updated to {tsl_level}% for {active_trade['pair']}")

            # Check if TSL is triggered
            if TSL_ENABLED and "tsl_level" in active_trade and profit_pct <= active_trade["tsl_level"]:
                logger.info(f"Trade Condition - TSL triggered for {active_trade['pair']}, Peak: {active_trade['max_profit']:.1f}%, Current: {profit_pct:.1f}%, TSL Level: {active_trade['tsl_level']}%")
                tx_hash = await force_close_trade(reason="tsl")
                if tx_hash:
                    logger.info(f"Trade Closure - TSL triggered for {active_trade['pair']}, Profit: {profit_pct:.2f}%, TX: {tx_hash.hex()}")
                    await bot.send_message(
                        chat_id=config["allowed_chat_id"],
                        text=f"🛑 TSL triggered! Sold at {profit_pct:.2f}% profit. Peak: {active_trade['max_profit']:.1f}%. TSL Level: {active_trade['tsl_level']}%. TX: https://basescan.org/tx/{tx_hash.hex()}"
                    )
                    trade_data = {
                        "type": "sell",
                        "pair": active_trade["pair"],
                        "token_address": token_address,
                        "tokens_sold": float(web3.from_wei(token_balance, 'ether')),
                        "tx_hash": tx_hash.hex(),
                        "timestamp": datetime.utcnow().isoformat(),
                        "trigger": "tsl",
                        "profit_percent": float(profit_pct),
                        "max_profit": float(active_trade["max_profit"]),
                        "tsl_level": float(active_trade["tsl_level"])
                    }
                    append_trade_history(trade_data)
                break

            # Take-profit check
            if profit_pct >= config["take_profit_percent"]:
                logger.info(f"Trade Condition - Take-profit {config['take_profit_percent']}% reached for {active_trade['pair']}")
                tx_hash = await force_close_trade(reason="tp")
                if tx_hash:
                    logger.info(f"Trade Closure - Take-profit for {active_trade['pair']}, Profit: {profit_pct:.2f}%, TX: {tx_hash.hex()}")
                    await bot.send_message(
                        chat_id=config["allowed_chat_id"],
                        text=f"🎯 Take-profit triggered! Sold at {profit_pct:.2f}% profit. TX: https://basescan.org/tx/{tx_hash.hex()}"
                    )
                break

            # Stop-loss check
            if loss_pct >= config["stop_loss_percent"]:
                logger.info(f"Trade Condition - Stop-loss {config['stop_loss_percent']}% reached for {active_trade['pair']}")
                tx_hash = await force_close_trade(reason="sl")
                if tx_hash:
                    logger.info(f"Trade Closure - Stop-loss for {active_trade['pair']}, Loss: {loss_pct:.2f}%, TX: {tx_hash.hex()}")
                    await bot.send_message(
                        chat_id=config["allowed_chat_id"],
                        text=f"🛑 Stop-loss triggered! Sold at {loss_pct:.2f}% loss. TX: https://basescan.org/tx/{tx_hash.hex()}"
                    )
                    trade_data = {
                        "type": "sell",
                        "pair": active_trade["pair"],
                        "token_address": token_address,
                        "tokens_sold": float(web3.from_wei(token_balance, 'ether')),
                        "tx_hash": tx_hash.hex(),
                        "timestamp": datetime.utcnow().isoformat(),
                        "trigger": "sl",
                        "loss_percent": float(loss_pct)
                    }
                    append_trade_history(trade_data)
                break

            await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"Trade Monitoring - Error: {e}")
            await asyncio.sleep(1)

async def monitor_dexscreener():
    global active_trade, stop_monitoring
    pair = config["pair"].upper()
    reverse_pair = "/".join(reversed(config["pair"].split("/"))).upper()
    min_liq = config["min_liquidity_usd"]
    target_token_address = config.get("target_token_address")
    pair_pattern = re.compile(r'^[A-Z0-9]+/[A-Z0-9]+$')

    if not pair_pattern.match(pair):
        logger.error(f"Monitoring Event - Invalid pair format: {pair}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=f"⚠️ Invalid pair format: {pair}. Please set a valid pair using /set coin <PAIR>."
        )
        return
    if target_token_address and not Web3.is_address(target_token_address):
        logger.error(f"Monitoring Event - Invalid token address: {target_token_address}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=f"⚠️ Invalid token address: {target_token_address}. Please set a valid address using /set coin <ADDRESS>. Bot stopped."
        )
        config["target_token_address"] = None
        save_config(config)
        stop_monitoring = True
        return

    logger.info(f"Monitoring Event - Started DexScreener for pair {pair} or {reverse_pair}, Min Liquidity: ${min_liq:,}")
    if target_token_address:
        logger.info(f"Monitoring Event - Also checking token address: {target_token_address}")

    retry_count = 0
    max_retries = 3
    while not stop_monitoring:
        if stop_monitoring:  # Check at the start of the loop
            logger.info("Monitoring Event - DexScreener monitoring stopped")
            break
        try:
            async with aiohttp.ClientSession() as session:
                if target_token_address and Web3.is_address(target_token_address):
                    url = f"https://api.dexscreener.com/latest/dex/tokens/{target_token_address}?chain=base"
                    logger.info(f"Monitoring Event - Checking DexScreener for token {target_token_address}")
                else:
                    url = f"https://api.dexscreener.com/latest/dex/search?q={pair}&chain=base"
                    logger.info(f"Monitoring Event - Checking DexScreener for pair {pair}")

                async with session.get(url, timeout=10) as resp:
                    if resp.status != 200:
                        logger.error(f"Monitoring Event - DexScreener API failed: HTTP {resp.status}")
                        retry_count += 1
                        if retry_count >= max_retries:
                            logger.error("Monitoring Event - Max retries reached for DexScreener API")
                            await bot.send_message(
                                chat_id=config["allowed_chat_id"],
                                text="❌ DexScreener API failed after retries. Please check network or API status."
                            )
                            stop_monitoring = True
                            break
                        await asyncio.sleep(1)
                        continue
                    retry_count = 0
                    data = await resp.json()
                    pairs = data.get("pairs", [])
                    found_pair = False
                    for p in pairs:
                        if stop_monitoring:  # Check before processing each pair
                            logger.info("Monitoring Event - DexScreener monitoring stopped during pair processing")
                            break
                        base_symbol = p["baseToken"]["symbol"].upper()
                        quote_symbol = p["quoteToken"]["symbol"].upper()
                        try:
                            base_token_address = Web3.to_checksum_address(p["baseToken"]["address"])
                            quote_token_address = Web3.to_checksum_address(p["quoteToken"]["address"])
                        except ValueError as e:
                            logger.error(f"Monitoring Event - Invalid address in DexScreener response: {e}")
                            continue
                        symbol_pair = f"{base_symbol}/{quote_symbol}"
                        reverse_symbol_pair = f"{quote_symbol}/{base_symbol}"
                        chain_id = p.get("chainId")
                        if ((symbol_pair == pair or symbol_pair == reverse_pair) or
                            (target_token_address and (base_token_address == target_token_address or quote_token_address == target_token_address))) and \
                            str(chain_id).lower() in ("8453", "base"):
                            found_pair = True
                            liquidity = float(p.get("liquidity", {}).get("usd", 0))
                            token_address = base_token_address
                            is_reverse = symbol_pair == reverse_pair or (target_token_address and quote_token_address == target_token_address)
                            if is_reverse:
                                token_address = quote_token_address

                            if is_blacklisted(token_address):
                                logger.warning(f"Security Check - Token {token_address} blacklisted, Pair: {symbol_pair}")
                                if token_address.lower() not in notified_blacklisted_tokens:
                                    await bot.send_message(
                                        chat_id=config["allowed_chat_id"],
                                        text=f"⚠️ Token {token_address} ({symbol_pair}) is blacklisted. Please set a new coin using /set coin <PAIR or ADDRESS>. Bot stopped."
                                    )
                                    notified_blacklisted_tokens.add(token_address.lower())
                                    config["target_token_address"] = None
                                    save_config(config)
                                    stop_monitoring = True
                                    break
                                continue

                            logger.info(f"Liquidity Check - Pair: {symbol_pair}, Liquidity: ${liquidity:,.2f}")
                            if liquidity >= min_liq:
                                logger.info(f"Liquidity Check - Threshold met for {symbol_pair}, Liquidity: ${liquidity:,.2f}, Threshold: ${min_liq:,.2f}")
                                if active_trade is None and not stop_monitoring:  # Additional stop_monitoring check
                                    logger.info(f"Trade Initiation - Checking and executing trade for {symbol_pair}, Token: {token_address}")
                                    asyncio.create_task(run_approve_if_needed(token_address))
                                    if await check_security(token_address):
                                        logger.info(f"Security Check - Token {token_address} passed for {symbol_pair}")
                                        tx_hash, amount_in_vrl, tokens_bought = await execute_buy_trade(token_address, is_reverse)
                                        if tx_hash:
                                            logger.info(f"Trade Execution - Buy order filled for {symbol_pair}, {amount_in_vrl} VIRTUAL, {tokens_bought:.2f} tokens, TX: {tx_hash.hex()}")
                                            await bot.send_message(
                                                chat_id=config["allowed_chat_id"],
                                                text=f"🚀 Trade executed for {symbol_pair}! TX: https://basescan.org/tx/{tx_hash.hex()}"
                                            )
                                            asyncio.create_task(monitor_trade())
                                        else:
                                            logger.error(f"Trade Execution - Buy order failed for {symbol_pair}")
                                    else:
                                        logger.error(f"Security Check - Token {token_address} failed for {symbol_pair}")
                                        await bot.send_message(
                                            chat_id=config["allowed_chat_id"],
                                            text=f"❌ Security check failed for {symbol_pair}"
                                        )
                                else:
                                    logger.warning(f"Trade Initiation - Trade already active for {active_trade['pair']} or monitoring stopped")
                            else:
                                logger.info(f"Liquidity Check - Liquidity ${liquidity:,.2f} below threshold ${min_liq:,.2f} for {symbol_pair}")
                    if not found_pair:
                        logger.warning(f"Pair Detection - Pair {pair} or {reverse_pair} or token {target_token_address} not found")
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.error(f"Monitoring Event - Error: {e}")
            retry_count += 1
            if retry_count >= max_retries:
                logger.error("Monitoring Event - Max retries reached for DexScreener API")
                await bot.send_message(
                    chat_id=config["allowed_chat_id"],
                    text="❌ DexScreener API failed after retries. Please check network or API status."
                )
                stop_monitoring = True
                break
            await asyncio.sleep(1)

async def execute_buy_trade(token_address, is_reverse=False):
    global active_trade
    virtual_amount = web3.to_wei(config.get("virtual_amount", 0.5), "ether")
    token_contract = web3.eth.contract(address=VIRTUAL_ADDRESS, abi=ERC20_ABI)

    try:
        virtual_balance = token_contract.functions.balanceOf(WALLET_ADDRESS).call()
        if virtual_balance < virtual_amount:
            logger.error(f"Trade Initiation - Insufficient VIRTUAL balance: Required {web3.from_wei(virtual_amount, 'ether')}, Available {web3.from_wei(virtual_balance, 'ether')}")
            await bot.send_message(
                chat_id=config["allowed_chat_id"],
                text=f"❌ Insufficient VIRTUAL balance. Required: {web3.from_wei(virtual_amount, 'ether')} VIRTUAL, Available: {web3.from_wei(virtual_balance, 'ether')} VIRTUAL"
            )
            return None, 0, 0
    except (BadFunctionCallOutput, Exception) as e:
        logger.error(f"Trade Initiation - Invalid VIRTUAL token address or contract call failed: {e}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text="❌ Cannot execute trade: Invalid VIRTUAL token address or contract call failed."
        )
        return None, 0, 0

    deadline = int(time.time()) + 30
    path = [VIRTUAL_ADDRESS, token_address] if not is_reverse else [token_address, VIRTUAL_ADDRESS]
    slippage_tolerance = config.get("slippage_tolerance", 0.15)
    try:
        amounts = router_contract.functions.getAmountsOut(virtual_amount, path).call()
        amount_out_min = int(amounts[-1] * (1 - slippage_tolerance))
        tokens_bought = amounts[-1]
        virtual_amount_ether = web3.from_wei(virtual_amount, 'ether')
        tokens_bought_ether = web3.from_wei(tokens_bought, 'ether')
        entry_price = float(virtual_amount_ether) / float(tokens_bought_ether) if tokens_bought_ether > 0 else 0
    except Exception as e:
        logger.error(f"Trade Initiation - Failed to fetch token price: {e}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=f"❌ Failed to fetch token price for trade: {str(e)}. Please check pair or token address."
        )
        return None, 0, 0

    try:
        allowance = token_contract.functions.allowance(WALLET_ADDRESS, UNISWAP_V2_ROUTER).call()
        if allowance < virtual_amount:
            logger.warning(f"Trade Initiation - Approval not yet completed for {web3.from_wei(virtual_amount, 'ether')} VIRTUAL; retrying after delay")
            await asyncio.sleep(2)  # Wait for parallel approval to complete
            allowance = token_contract.functions.allowance(WALLET_ADDRESS, UNISWAP_V2_ROUTER).call()
            if allowance < virtual_amount:
                logger.error(f"Trade Initiation - Insufficient approval for {web3.from_wei(virtual_amount, 'ether')} VIRTUAL")
                await bot.send_message(
                    chat_id=config["allowed_chat_id"],
                    text=f"❌ Trade failed: Token approval not completed"
                )
                return None, 0, 0

        nonce = web3.eth.get_transaction_count(WALLET_ADDRESS)
        logger.info(f"Trade Initiation - Placing buy order for {config['pair']}, {virtual_amount_ether} VIRTUAL, Token: {token_address}")
        txn = router_contract.functions.swapExactTokensForTokens(
            virtual_amount,
            amount_out_min,
            path,
            WALLET_ADDRESS,
            deadline
        ).build_transaction({
            'from': WALLET_ADDRESS,
            'gas': 300000,
            'maxPriorityFeePerGas': web3.eth.max_priority_fee,
            'maxFeePerGas': web3.eth.max_priority_fee + web3.eth.gas_price,
            'nonce': nonce
        })

        signed_txn = web3.eth.account.sign_transaction(txn, private_key=config["private_key"])
        tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status == 0:
            logger.error(f"Trade Execution - Buy order reverted: {tx_hash.hex()}")
            raise ContractLogicError("Transaction reverted")

        token_contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)
        actual_tokens_bought = token_contract.functions.balanceOf(WALLET_ADDRESS).call()
        actual_tokens_bought_ether = web3.from_wei(actual_tokens_bought, 'ether')
        entry_price = float(virtual_amount_ether) / float(actual_tokens_bought_ether) if actual_tokens_bought_ether > 0 else 0

        active_trade = {
            "pair": config["pair"],
            "token_address": token_address,
            "vrl_spent": web3.from_wei(virtual_amount, 'ether'),
            "tokens_bought": actual_tokens_bought,
            "tx_hash": tx_hash.hex(),
            "entry_price": float(entry_price),
            "max_profit": 0
        }

        trade_data = {
            "type": "buy",
            "pair": config["pair"],
            "token_address": token_address,
            "virtual_spent": float(web3.from_wei(virtual_amount, 'ether')),
            "tokens_bought": float(web3.from_wei(actual_tokens_bought, 'ether')),
            "entry_price": float(entry_price),
            "tx_hash": tx_hash.hex(),
            "timestamp": datetime.utcnow().isoformat()
        }
        append_trade_history(trade_data)

        logger.info(f"Trade Execution - Buy order filled for {config['pair']}, {web3.from_wei(virtual_amount, 'ether')} VIRTUAL, {web3.from_wei(actual_tokens_bought, 'ether'):.2f} tokens, TX: {tx_hash.hex()}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=(
                f"✅ Trade executed for {config['pair']}!\n"
                f"💰 Spent: {web3.from_wei(virtual_amount, 'ether')} VIRTUAL\n"
                f"📥 Entry Price: {entry_price:.6f} VIRTUAL/token\n"
                f"📗 TX: https://basescan.org/tx/{tx_hash.hex()}"
            )
        )

        return tx_hash, web3.from_wei(virtual_amount, 'ether'), actual_tokens_bought

    except ContractLogicError as e:
        logger.error(f"Trade Execution - Transaction reverted: {e}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=f"❌ Buy trade failed: Transaction reverted"
        )
        return None, 0, 0
    except Exception as e:
        logger.error(f"Trade Execution - Error: {e}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=f"❌ Buy trade error: {str(e)}"
        )
        return None, 0, 0

async def force_close_trade(reason="manual"):
    global active_trade, monitor_task, stop_monitoring
    if not active_trade:
        logger.warning("Trade Closure - No active trade to close")
        return None

    token_address = active_trade["token_address"]
    full_amount = active_trade["tokens_bought"]
    token_contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)

    try:
        token_balance = token_contract.functions.balanceOf(WALLET_ADDRESS).call()
        if token_balance < full_amount:
            logger.error(f"Trade Closure - Insufficient token balance: Available {web3.from_wei(token_balance, 'ether')}, Required {web3.from_wei(full_amount, 'ether')}")
            await bot.send_message(
                chat_id=config["allowed_chat_id"],
                text="⚠️ Not enough tokens to sell."
            )
            active_trade = None
            stop_monitoring = True
            return None

        pair = active_trade["pair"].upper()
        pair_tokens = pair.split("/")
        output_token = VIRTUAL_ADDRESS if pair_tokens[1] == "VIRTUAL" else WETH_ADDRESS
        path = [token_address, output_token]
        output_symbol = "VIRTUAL" if output_token == VIRTUAL_ADDRESS else "WETH"

        try:
            amounts = router_contract.functions.getAmountsOut(full_amount, path).call()
            vrl_out = amounts[-1]
            vrl_out_ether = web3.from_wei(vrl_out, 'ether')
            full_amount_ether = web3.from_wei(full_amount, 'ether')
            exit_price = float(vrl_out_ether) / float(full_amount_ether) if full_amount_ether > 0 else 0
        except Exception as e:
            logger.error(f"Trade Closure - Error fetching exit price: {e}")
            exit_price = 0

        allowance = token_contract.functions.allowance(WALLET_ADDRESS, UNISWAP_V2_ROUTER).call()
        if allowance < full_amount:
            logger.info(f"Trade Closure - Approving {web3.from_wei(full_amount, 'ether')} tokens for Uniswap router")
            approve_txn = token_contract.functions.approve(UNISWAP_V2_ROUTER, full_amount).build_transaction({
                'from': WALLET_ADDRESS,
                'gas': 100000,
                'maxPriorityFeePerGas': web3.eth.max_priority_fee,
                'maxFeePerGas': web3.eth.max_priority_fee + web3.eth.gas_price,
                'nonce': web3.eth.get_transaction_count(WALLET_ADDRESS)
            })
            signed_approve = web3.eth.account.sign_transaction(approve_txn, private_key=config["private_key"])
            tx_hash_approve = web3.eth.send_raw_transaction(signed_approve.raw_transaction)
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash_approve, timeout=60)
            if receipt.status == 0:
                logger.error(f"Trade Closure - Approval transaction reverted: {tx_hash_approve.hex()}")
                raise ContractLogicError("Approval transaction reverted")
            logger.info(f"Trade Closure - Approval successful: {tx_hash_approve.hex()}")

        router_supporting = web3.eth.contract(address=UNISWAP_V2_ROUTER, abi=SUPPORTING_FEE_ABI)
        deadline = int(time.time()) + 30

        amount_to_sell = full_amount
        logger.info(f"Trade Closure - Placing sell order for {pair}, {web3.from_wei(amount_to_sell, 'ether')} tokens, Output: {output_symbol}")
        txn = router_supporting.functions.swapExactTokensForTokensSupportingFeeOnTransferTokens(
            amount_to_sell,
            0,
            path,
            WALLET_ADDRESS,
            deadline
        ).build_transaction({
            'from': WALLET_ADDRESS,
            'gas': 400000,
            'maxPriorityFeePerGas': web3.eth.max_priority_fee,
            'maxFeePerGas': web3.eth.max_priority_fee + web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(WALLET_ADDRESS)
        })

        signed_txn = web3.eth.account.sign_transaction(txn, private_key=config["private_key"])
        tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

        if receipt.status == 1:
            logger.info(f"Trade Closure - Sold {web3.from_wei(amount_to_sell, 'ether')} tokens of {pair} at {exit_price:.6f} {output_symbol}/token, TX: {tx_hash.hex()}")
            await bot.send_message(
                chat_id=config["allowed_chat_id"],
                text=(
                    f"✅ Sell Success!\n"
                    f"📤 Sold: {web3.from_wei(amount_to_sell, 'ether')} tokens\n"
                    f"📤 Exit Price: {exit_price:.6f} {output_symbol}/token\n"
                    f"📗 TX: https://basescan.org/tx/{tx_hash.hex()}\n"
                    f"📋 Exit Reason: {reason}\n"
                    f"🛑 Bot stopped. Use /start to resume trading."
                )
            )
            trade_data = {
                "type": "sell",
                "pair": active_trade["pair"],
                "token_address": token_address,
                "tokens_sold": float(web3.from_wei(amount_to_sell, 'ether')),
                "tx_hash": tx_hash.hex(),
                "timestamp": datetime.utcnow().isoformat(),
                "exit_price": float(exit_price),
                "reason": reason
            }
            append_trade_history(trade_data)
            active_trade = None
            stop_monitoring = True
            if monitor_task:  # Cancel monitoring tasks
                try:
                    monitor_task.cancel()
                    await asyncio.gather(monitor_task, return_exceptions=True)
                    logger.info("System Event - Monitoring tasks cancelled after trade closure")
                except Exception as e:
                    logger.error(f"System Event - Error cancelling monitor tasks: {e}")
                monitor_task = None
            return tx_hash
        else:
            logger.error(f"Trade Closure - Sell transaction reverted: {tx_hash.hex()}")
            await bot.send_message(
                chat_id=config["allowed_chat_id"],
                text="❌ Sell transaction reverted."
            )
            active_trade = None
            stop_monitoring = True
            return None

    except Exception as e:
        logger.error(f"Trade Closure - Error: {e}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=f"❌ Emergency sell error: {str(e)}"
        )
        active_trade = None
        stop_monitoring = True
        if monitor_task:  # Cancel monitoring tasks on error
            try:
                monitor_task.cancel()
                await asyncio.gather(monitor_task, return_exceptions=True)
                logger.info("System Event - Monitoring tasks cancelled after trade closure error")
            except Exception as e:
                logger.error(f"System Event - Error cancelling monitor tasks: {e}")
            monitor_task = None
        return None

@dp.message(Command("start"))
async def cmd_start(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    global monitor_task, stop_monitoring
    if monitor_task and not monitor_task.done():
        logger.info("System Event - Monitoring already running")
        await message.reply("⚠️ Monitor already running.")
        return
    target_token_address = config.get("target_token_address")
    if target_token_address and not Web3.is_address(target_token_address):
        logger.error(f"System Event - Invalid token address: {target_token_address}")
        await message.reply(
            f"⚠️ Invalid token address: {target_token_address}. Please set a valid address using /set coin <ADDRESS>."
        )
        config["target_token_address"] = None
        save_config(config)
        return
    if target_token_address and is_blacklisted(target_token_address):
        logger.warning(f"Security Check - Token {target_token_address} blacklisted")
        await message.reply(
            f"⚠️ Token {target_token_address} ({config['pair']}) is blacklisted. Please set a new coin using /set coin <PAIR or ADDRESS>."
        )
        return
    stop_monitoring = False
    monitor_task = asyncio.gather(
        monitor_dexscreener(),
        monitor_pair_created()
    )
    logger.info("System Event - Monitoring started for DexScreener and PairCreated")
    await message.reply("✅ Monitoring started for DexScreener and PairCreated events.")

@dp.message(Command("stop"))
async def cmd_stop(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    global monitor_task, active_trade, stop_monitoring
    logger.info("System Event - Stopping monitoring")
    stop_monitoring = True
    if monitor_task:
        try:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
            logger.info("System Event - Monitor task cancelled")
        except Exception as e:
            logger.error(f"System Event - Stop error: {e}")
        monitor_task = None
    if is_blacklisted(config.get("target_token_address")):
        config["target_token_address"] = None
        save_config(config)
    active_trade = None
    await message.reply("🛑 Monitoring stopped.")

@dp.message(Command("status"))
async def cmd_status(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    status = "Running" if monitor_task and not monitor_task.done() else "Stopped"
    logger.info(f"System Event - Bot status checked: {status}")
    await message.reply(f"📡 Bot status: {status}")

@dp.message(Command("setting"))
async def cmd_setting(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    msg = (
        f"⚙️ Current settings:\n"
        f"Pair: {config['pair']}\n"
        f"Token Address: {config.get('target_token_address', 'Not set')}\n"
        f"Min Liquidity (USD): ${config['min_liquidity_usd']}\n"
        f"Take Profit %: {config['take_profit_percent']}%\n"
        f"Stop Loss %: {config['stop_loss_percent']}%\n"
        f"Virtual Amount: {config.get('virtual_amount', 0.5)} VIRTUAL\n"
        f"Slippage Tolerance: {config.get('slippage_tolerance', 0.15) * 100}%\n"
        f"TSL Percentage: {config.get('trailing_pct', 10)}%\n"
        f"TSL Enabled: {'Yes' if config.get('tsl_enabled', False) else 'No'}"
    )
    log_msg = msg.replace('\n', '; ')
    logger.info(f"System Event - Displayed settings: {log_msg}")
    await message.reply(msg)

@dp.message(Command("set"))
async def cmd_set(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    args = message.text.split(' ', 2)
    if len(args) < 3:
        logger.error("System Event - Invalid /set command format")
        await message.reply("❌ Invalid format. Use `/set param value`")
        return
    param = args[1].lower()
    value = args[2].strip()
    logger.info(f"System Event - Setting {param} to {value}")
    if param == "coin":
        if Web3.is_address(value):
            ticker = await resolve_contract_to_ticker(value)
            if ticker:
                config["pair"] = ticker.upper()
                config["target_token_address"] = Web3.to_checksum_address(value)
                logger.info(f"System Event - Resolved contract {value} to pair {ticker}")
                await message.reply(f"✅ Resolved contract {value} to pair {ticker}")
            else:
                logger.error(f"System Event - Could not resolve contract address {value}")
                await message.reply(f"❌ Could not resolve contract address {value} to a valid pair.")
                return
        else:
            config["pair"] = value.upper()
            config["target_token_address"] = None
        save_config(config)
        await message.reply(f"✅ Setting updated: coin = {value}")
    elif param == "liq":
        try:
            config["min_liquidity_usd"] = float(value)
        except ValueError:
            logger.error("System Event - Liquidity must be a number")
            await message.reply("❌ Liquidity must be a number.")
            return
    elif param == "tp":
        try:
            config["take_profit_percent"] = float(value)
        except ValueError:
            logger.error("System Event - Take profit must be a number")
            await message.reply("❌ Take profit must be a number.")
            return
    elif param == "sl":
        try:
            config["stop_loss_percent"] = float(value)
            if config["stop_loss_percent"] <= 0:
                logger.error("System Event - Stop loss must be positive")
                await message.reply("❌ Stop loss must be positive.")
                return
        except ValueError:
            logger.error("System Event - Invalid stop loss value")
            await message.reply("❌ Stop loss must be a number.")
            return
    elif param == "vrl":
        try:
            config["virtual_amount"] = float(value)
        except ValueError:
            logger.error("System Event - Virtual amount must be a number")
            await message.reply("❌ Virtual amount must be a number.")
            return
    elif param == "slippage":
        try:
            config["slippage_tolerance"] = float(value)
            if config["slippage_tolerance"] <= 0 or config["slippage_tolerance"] > 1:
                logger.error("System Event - Slippage must be between 0 and 1")
                await message.reply("❌ Slippage must be between 0 and 1.")
                return
        except ValueError:
            logger.error("System Event - Invalid slippage value")
            await message.reply("❌ Slippage must be a number.")
            return
    elif param == "tsl":
        try:
            global TRAILING_PCT
            config["trailing_pct"] = float(value)
            TRAILING_PCT = config["trailing_pct"]
            if config["trailing_pct"] <= 0:
                logger.error("System Event - TSL percentage must be positive")
                await message.reply("❌ TSL percentage must be positive.")
                return
        except ValueError:
            logger.error("System Event - Invalid TSL percentage")
            await message.reply("❌ TSL percentage must be a number.")
            return
    else:
        logger.error(f"System Event - Unknown setting: {param}")
        await message.reply("❌ Unknown setting.")
        return
    save_config(config)
    logger.info(f"System Event - Updated setting: {param} = {value}")
    await message.reply(f"✅ Setting updated: {param} = {value}")

@dp.message(Command("tsl"))
async def cmd_tsl(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    args = message.text.split(' ', 1)
    if len(args) < 2:
        logger.error("System Event - Invalid /tsl command format")
        await message.reply("❌ Invalid format. Use `/tsl on` or `/tsl off`")
        return
    action = args[1].lower()
    global TSL_ENABLED
    logger.info(f"System Event - TSL action: {action}")
    if action == "on":
        config["tsl_enabled"] = True
        TSL_ENABLED = True
        await message.reply("✅ TSL enabled.")
    elif action == "off":
        config["tsl_enabled"] = False
        TSL_ENABLED = False
        await message.reply("✅ TSL disabled.")
    else:
        logger.error("System Event - Invalid TSL action")
        await message.reply("❌ Invalid action. Use `on` or `off`.")
    save_config(config)

@dp.message(Command("trade", "active"))
async def cmd_trade(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    global active_trade
    if not active_trade:
        logger.info("System Event - No active trade")
        await message.reply("⚠️ No active trade.")
        return
    msg = (
        f"💼 Active Trade Info:\n"
        f"Pair: {active_trade['pair']}\n"
        f"VIRTUAL Spent: {active_trade['vrl_spent']} VIRTUAL\n"
        f"Tokens Bought: {web3.from_wei(active_trade['tokens_bought'], 'ether')}\n"
        f"Entry Price: {active_trade['entry_price']:.6f} VIRTUAL/token\n"
        f"Max Profit: {active_trade.get('max_profit', 0):.1f}%\n"
        f"Buy TX: https://basescan.org/tx/{active_trade['tx_hash']}"
    )
    log_msg = msg.replace('\n', '; ')
    logger.info(f"System Event - Active trade info: {log_msg}")
    await message.reply(msg)

@dp.message(Command("balance"))
async def cmd_balance(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    eth_balance = web3.from_wei(web3.eth.get_balance(WALLET_ADDRESS), 'ether')
    
    virtual_contract = web3.eth.contract(address=VIRTUAL_ADDRESS, abi=ERC20_ABI)
    
    try:
        virtual_balance = web3.from_wei(virtual_contract.functions.balanceOf(WALLET_ADDRESS).call(), 'ether')
    except (BadFunctionCallOutput, Exception) as e:
        virtual_balance = f"Error: Invalid VIRTUAL token address: {e}"
        logger.error(f"System Event - VIRTUAL balance error: {e}")

    msg = f"💰 Wallet Balances:\nETH: {eth_balance:.6f}\nVIRTUAL: {virtual_balance}"
    
    if active_trade:
        token_address = active_trade["token_address"]
        token_contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)
        try:
            token_balance = web3.from_wei(token_contract.functions.balanceOf(WALLET_ADDRESS).call(), 'ether')
        except (BadFunctionCallOutput, Exception) as e:
            token_balance = f"Error: {e}"
            logger.error(f"System Event - Token balance error: {e}")
        token_symbol = active_trade["pair"].split('/')[0]
        msg += f"\n{token_symbol}: {token_balance}"

    log_msg = msg.replace('\n', '; ')
    logger.info(f"System Event - Wallet balances: {log_msg}")
    await message.reply(msg)

@dp.message(Command("close"))
async def cmd_close(message: Message):
    if not is_allowed(message.chat.id):
        await message.reply("❌ Access denied.")
        return
    global active_trade
    if not active_trade:
        logger.info("System Event - No active trade to close")
        await message.reply("⚠️ No active trade to close.")
        return
    logger.info("System Event - Initiating trade closure")
    await message.reply("🔄 Closing active trade, selling tokens...")
    tx_hash = await force_close_trade(reason="manual")
    if tx_hash:
        logger.info(f"System Event - Trade closed successfully: {tx_hash.hex()}")
        await message.reply(f"✅ Trade closed! Sell TX: https://basescan.org/tx/{tx_hash.hex()}")
    else:
        logger.error("System Event - Trade closure failed")
        await message.reply("❌ Sell failed or no tokens found.")

@dp.message(Command("help"))
async def cmd_help(message: Message):
    help_msg = (
        "🤖 Bot Commands:\n"
        "/start - Start monitoring\n"
        "/stop - Stop monitoring\n"
        "/status - Show bot status\n"
        "/setting - Show current settings\n"
        "/set coin <PAIR or ADDRESS> - Set trading pair (e.g. AIN/VIRTUAL or 0x...)\n"
        "/set liq <amount> - Set minimum liquidity USD\n"
        "/set tp <percent> - Set take profit %\n"
        "/set sl <percent> - Set stop loss %\n"
        "/set vrl <amount> - Set VIRTUAL amount for trades\n"
        "/set slippage <value> - Set slippage tolerance (0 to 1)\n"
        "/set tsl <percent> - Set trailing stop loss %\n"
        "/tsl on - Enable trailing stop loss\n"
        "/tsl off - Disable trailing stop loss\n"
        "/trade or /active - Show active trade info\n"
        "/balance - Show ETH, VIRTUAL, and active trade token balances\n"
        "/close - Close active trade (sell tokens)\n"
        "/help - Show this message"
    )
    logger.info("System Event - Help message displayed")
    await message.reply(help_msg)

async def main():
    logger.info("System Event - Bot initializing with config.json")
    if config.get("target_token_address") and not Web3.is_address(config.get("target_token_address")):
        logger.error(f"System Event - Invalid token address in config: {config['target_token_address']}")
        await bot.send_message(
            chat_id=config["allowed_chat_id"],
            text=f"⚠️ Invalid token address in config: {config['target_token_address']}. Reset to None. Please set a valid address using /set coin <ADDRESS>."
        )
        config["target_token_address"] = None
        save_config(config)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())