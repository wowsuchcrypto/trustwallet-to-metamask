#!/usr/bin/env python3

import sys
from bip_utils import Bip32, Bip44, Bip39SeedGenerator, Bip44Coins
from binascii import hexlify

if len(sys.argv) < 2 or sys.argv[1] == "":
    print("No mnemonic given")
    exit(1)

mnemonic = sys.argv[1]

words = mnemonic.split(" ")
print("BIP39 mnemonic starts with: {} {} ...".format(words[0], words[1]))

seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
print("BIP39 seed: {}".format(hexlify(seed_bytes).decode("utf-8")))

bip32 = Bip32.FromSeed(seed_bytes)
print("BIP32 root key: {}".format(bip32.PrivateKey().ToExtended()))

derivation_path = "m/44'/60'/0'/0"

extended = Bip32.FromSeedAndPath(seed_bytes, derivation_path)
print("BIP32 extended public key: {}".format(extended.PublicKey().ToExtended()))
print("BIP32 extended private key: {}".format(extended.PrivateKey().ToExtended()))

derived_0_path = f"{derivation_path}/0"
derived_0_address = extended.DerivePath("0")
print("Derived {} public key: {}".format(derived_0_path, derived_0_address.EcdsaPublicKey().RawCompressed().ToHex()))
print("Derived {} private key: {}".format(derived_0_path, derived_0_address.EcdsaPrivateKey().Raw().ToHex()))
