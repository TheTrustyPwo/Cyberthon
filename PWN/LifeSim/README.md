# Life Sim

## Problem Statement

Welcome to LifeSim! Can you figure out a way to obtain enough funds to purchase the ridiculously priced flag?

Interact with the service at: `chals.t.cyberthon24.ctf.sg:33051` to begin.

Hint: Think of possible logical flaws in the code!

## Solution

Upon connection, we are greeted with a user menu, with the following options
```
[1] Go to work 💼
[2] Go shopping 🛒
[3] Visit the bank 🏦
[4] Quit Game 🚪
```

It is clear that our goal is to somehow obtain enough money to purchase the flag
```
=> 2

[1] Flag ($1000000000) 🇸🇬
[2] Peanuts ($2) 🥜
[3] Jelly Donut ($10) 🍙
[4] Leave 🚪
```

After some exploration, we see that we can deposit and withdraw money from the bank
```
=> 3

Current Savings: $0

[1] Deposit Money 💵
[2] Withdraw Money 💸
[3] Leave 🚪
```

What if we try to deposit a negative amount of money to obtain free money in our wallet?

```
=> 1

Amount to deposit: $-1000000000

Current Savings: $-1000000000

[1] Deposit Money 💵
[2] Withdraw Money 💸
[3] Leave 🚪
```

It works!!!

Now just purchase the flag from the shop with the money that seemingly appeared out of nowhere.
