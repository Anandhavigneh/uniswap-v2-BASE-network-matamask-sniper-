# Base Chain Hybrid Sniper Bot

A high-performance automated sniping system engineered for Base Chain.
This bot combines millisecond-level detection, hybrid monitoring, and strong security validation to execute trades the moment a new token pair goes live.

## 1. Project Overview

The Base Chain Hybrid Sniper Bot is designed for users who want extremely fast entry timing while maintaining strict safety checks.
It continuously monitors DexScreener + On-Chain PairCreated events, filters out unsafe tokens, and executes trades with optimized slippage and configurable risk parameters.

This bot is fully controllable through Telegram and supports dynamic runtime updates without restarting.

## 2. Core Features
### 2.1 Hybrid Monitoring Engine

Simultaneous DexScreener polling

Native PairCreated event listener on Base RPC

Real-time detection even before DexScreener updates

Zero-delay execution once conditions are met

### 2.2 Security Filters

Blacklist validation

Liquidity threshold filtering

Optional QuickIntel & GoPlus fallback checks

Slippage protection

Token address validation

### 2.3 Full Telegram Control

All config values can be updated live:

/start – Start monitoring

/stop – Stop monitoring

/setting – View current settings

/set coin SYMBOL/VIRTUAL – Set trading pair

/set vrl <amount> – Adjust virtual amount

/set tp <percent> – Modify take-profit

/set sl <percent> – Modify stop-loss

/tsl on/off – Enable or disable trailing SL

/trade – Show active trade

/balance – Show wallet balances

/close – Close active trade

2.4 Automated Risk Control

Take-Profit auto-sell

Stop-Loss auto-sell

Trailing Stop Loss (TSL)

Manual override via /close

### 2.5 Logging & Trade History

All actions are written to:

cmd_log.txt — Monitoring, trades, and system events

trade_history.json — Every buy/sell recorded for transparency

## 3. High-Level Architecture
User → Telegram Bot → Command Parser → Config Manager
                     ↓
            Monitoring Engine
            | • DexScreener Polling
            | • PairCreated Listener
            ↓
        Validation Layer
        | • Blacklist Check
        | • Liquidity Check
        | • Slippage Estimator
            ↓
        Execution Engine
        | • Buy Handler
        | • Sell Handler (TP, SL, TSL)
            ↓
        Post-Trade System
        | • PnL Tracking
        | • Balance Updates
        | • Trade History Logging

## 4. Image Demonstration Section

Below are professional sections with placeholders where your screenshots will be placed.

IMAGE 1 — Telegram Command Overview

(Add your screenshot showing the command list here.)

Purpose of Image 1

Shows available Telegram bot commands

Helps users understand runtime configurability

Demonstrates how easily commands can be used


<img width="1245" height="962" alt="Image" src="https://github.com/user-attachments/assets/cbcbfa00-3d99-4ec9-a7aa-5ee8797ce751" />


IMAGE 2 — Setting Pair and Virtual Amount

(Add screenshot showing /set coin and /set vrl.)

Purpose of Image 2

Demonstrates pair configuration

Shows real-time updates in chat

Displays confirmation messages

<img width="1239" height="962" alt="Image" src="https://github.com/user-attachments/assets/5d63fd23-c53a-45c9-b366-0dcac7d37f18" />

IMAGE 3 — Starting Monitoring and Trade Trigger

(Add screenshot showing /start and trade executed.)

Purpose of Image 3

Displays monitoring activation

Shows instant trade execution when pair detected

Displays TX link and entry price

<img width="1238" height="964" alt="Image" src="https://github.com/user-attachments/assets/378c350f-6c2e-49e0-bf02-a5dececbfe2a" />

IMAGE 4 — Wallet Balance & Live Trade Details

(Add screenshot showing /balance or /trade output.)

Purpose of Image 4

Shows wallet summary

Shows current trade details

Confirms correct token accounting

<img width="1231" height="893" alt="Image" src="https://github.com/user-attachments/assets/ab0bc5b6-627c-4887-9161-dc82634b9eda" />

IMAGE 5 — Automatic TP / SL / TSL Execution

(Add screenshot showing sell success or trailing stop.)

Purpose of Image 5

Displays automated sell logic

Shows profit capture

Confirms exit reason

<img width="1238" height="968" alt="Image" src="https://github.com/user-attachments/assets/3ebd68c8-8b5a-447d-ab3e-02fae4e882ce" />

## 5. Configuration File Breakdown

Your config.json defines all runtime parameters.

Example from your project:

Pair

Min liquidity

Virtual amount

Slippage tolerance

TP, SL, TSL values

RPC URL

Wallet address

Telegram bot token

Each Telegram command modifies these fields instantly.

## 6. Execution Flow Explained in Detail
Step-by-step

User sets pair using /set coin

Bot saves pair to config.json

User starts monitoring using /start

Monitoring engine begins scanning for the pair

On pair detection:

Blacklist check

Liquidity check

Slippage estimation

If all validations pass → Buy transaction is executed

After buy:

TSL, TP, SL logic becomes active

Trade tracked in real-time

If exit condition meets → Sell order executes

All trade info is logged and displayed on Telegram

## 7. Files Overview
File	Purpose
work.py	Main engine controlling monitoring, trading, Telegram
config.json	User configuration: TP, SL, liquidity, pair, wallet
blacklist.json	Unsafe tokens to skip
trade_history.json	All buy/sell records
cmd_log.txt	Runtime logs for events and errors
## 8. Installation & Running
1. Install Python requirements
pip install web3 aiogram aiohttp

2. Add your private key, wallet, and Telegram bot token in config.json.
3. Run the bot
python work.py

4. Open Telegram → Use /start to begin monitoring.
## 9. Recommended Usage Strategy

Always test with small VIRTUAL amounts.

Set reasonable liquidity threshold (e.g., 100k USD).

Use TSL for volatile coins.

Close manually if needed with /close.

Monitor logs for anomalies.

## 10. Conclusion

This project provides a fully automated, secure, and high-speed sniping system for Base Chain.
Its Telegram interface, hybrid monitoring, and safety layers make it a robust choice for new-launch sniping and rapid trading environments.

# Disclaimer

This project is provided strictly for educational and research purposes. Automated trading, sniping bots, and blockchain interactions involve financial risk, technical vulnerabilities, and market volatility. The authors and contributors of this project do not guarantee profits, outcomes, performance, or reliability of this software.

By using this bot, you acknowledge and agree to the following:

You are solely responsible for all actions performed by the bot, including but not limited to buying, selling, swapping, and interacting with smart contracts.

You understand that cryptocurrency markets are highly volatile and that losses can exceed deposits.

You assume full responsibility for securing your private keys, wallet access, and configuration data. The developers do not store, log, or recover any user credentials.

You understand that the use of automated trading tools may violate local laws or platform terms. It is your responsibility to ensure compliance with applicable regulations.

The project is provided “as is,” without warranties of any kind, express or implied. The authors are not liable for any financial loss, system failure, smart contract exploits, or malicious token behavior.
