# Cardano App

A simple Cardano SL app for Ledger Nano S, supporting ed25519 derivation and keys.

This app is compatible with the Cardano-ledger-node-js-api client, currently forked on git@github.com:HiddenField/cardano-ledger-node-js-api.git

## Current instruction set available:


| Get Public Key for a given derivation path | INS_GET_PUBLIC_KEY | 0x02 |
| Generate random public key on 44'/1815'/[WALLET_INDEX]'/0'| INS_GET_RND_PUB_KEY | 0x0C |
| Calculates and returns the Wallet Index | INS_GET_WALLET_INDEX | 0x0E |

## APDU Breakdown

See - doc/cardanoapp.asc

## Building

Environment setup and developer documentation is succinctly provided in Ledger’s Read the Docs [http://ledger.readthedocs.io/en/latest/].
Fix’s Vagrant project is also very useful for setting up development environments off linux - Ledger Vagrant [https://github.com/fix/ledger-vagrant].

```
git clone repo

make load

make delete
```
