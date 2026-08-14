# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

import re
from collections import namedtuple
from decimal import Decimal
from hashlib import sha256

from electrumx.lib import util
from electrumx.lib.hash import Base58, double_sha256, hash_to_hex_str
from electrumx.lib.hash import HASHX_LEN, decode_segwit_address
from electrumx.lib.script import ScriptPubKey
import electrumx.lib.tx as lib_tx
from electrumx.server import daemon
from electrumx.server.session import ElectrumX

Block = namedtuple("Block", "raw header transactions")


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin:
    '''Base class of coin hierarchy.'''

    SHORTNAME = "BSV"
    NET = "mainnet"
    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\\[[0-9a-fA-F:]+\\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    SESSIONCLS = ElectrumX
    BASIC_HEADER_SIZE = 80
    DEFAULT_MAX_SEND = 1000000
    DESERIALIZER = lib_tx.Deserializer
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 500
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    RPC_PORT = 8332
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    GENESIS_ACTIVATION = 100_000_000
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []

    ESTIMATEFEE_MODES = (None, 'CONSERVATIVE', 'ECONOMICAL')

    @classmethod
    def bucket_estimatefee_block_target(cls, n: int) -> int:
        # values based on https://github.com/bitcoin/bitcoin/blob/af05bd9e1e362c3148e3b434b7fac96a9a5155a1/src/policy/fees.h#L131  # noqa
        if n <= 1:
            return 1
        if n <= 12:
            return n
        if n == 25:  # so common that we make an exception for it
            return n
        if n <= 48:
            return n // 2 * 2
        if n <= 1008:
            return n // 24 * 24
        return 1008

    @classmethod
    def prefetch_limit(cls, height):
        if height <= 650_000:
            return 100
        return 10

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        return (cls.static_header_offset(height + 1)
                - cls.static_header_offset(height))

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ['CHAIN_SIZE', 'CHAIN_SIZE_HEIGHT', 'AVG_BLOCK_SIZE']
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower() and
                    coin.NET.lower() == net.lower()):
                coin_req_attrs = req_attrs.copy()
                missing = [attr for attr in coin_req_attrs
                           if not hasattr(coin, attr)]
                if missing:
                    raise CoinError('coin {} missing {} attributes'
                                    .format(name, missing))
                return coin
        raise CoinError('unknown coin {} and network {} combination'
                        .format(name, net))

    @classmethod
    def sanitize_url(cls, url):
        # Remove surrounding ws and trailing /s
        url = url.strip().rstrip('/')
        match = cls.RPC_URL_REGEX.match(url)
        if not match:
            raise CoinError('invalid daemon URL: "{}"'.format(url))
        if match.groups()[1] is None:
            url += ':{:d}'.format(cls.RPC_PORT)
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        return url + '/'

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script.'''
        return sha256(script).digest()[:HASHX_LEN]

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

    @classmethod
    def hash160_to_P2PKH_script(cls, hash160):
        return ScriptPubKey.P2PKH_script(hash160)

    @classmethod
    def hash160_to_P2PKH_hashX(cls, hash160):
        return cls.hashX_from_script(cls.hash160_to_P2PKH_script(hash160))

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a pubkey hash.

        Pass the address (either P2PKH or P2SH) in base58 form.
        '''
        raw = Base58.decode_check(address)

        # Require version byte(s) plus hash160.
        verbyte = -1
        verlen = len(raw) - 20
        if verlen > 0:
            verbyte, hash160 = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return cls.hash160_to_P2PKH_script(hash160)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash160)

        raise CoinError('invalid address: {}'.format(address))

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        return block[:cls.static_header_len(height)]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        header = cls.block_header(raw_block, height)
        txs = cls.DESERIALIZER(raw_block, start=len(header)).read_tx_block()
        return Block(raw_block, header, txs)

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BSV is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN


class Ravencoin(Coin):
    NAME = "Ravencoin"
    SHORTNAME = "RVN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("3C")
    P2SH_VERBYTES = [bytes.fromhex("7A")]
    GENESIS_HASH = ('0000006b444bc2f2ffe627be9d9e7e7a'
                    '0730000870ef6eb6da46c8eae389df90')
    DEFAULT_MAX_SEND = 10_000_000
    X16RV2_ACTIVATION_TIME = 1569945600   # algo switch to x16rv2 at this timestamp
    KAWPOW_ACTIVATION_TIME = 1588788000  # kawpow algo activation time
    KAWPOW_ACTIVATION_HEIGHT = 1219736
    KAWPOW_HEADER_SIZE = 120
    
    CHAIN_SIZE = 20_156_386_851
    CHAIN_SIZE_HEIGHT = 2_096_467
    AVG_BLOCK_SIZE = 12_681
    
    RPC_PORT = 8766
    REORG_LIMIT = 100
    PEERS = [
        'rvn4lyfe.com s50002',
        'aethyn.com t s',
        'electrum1.rvn.rocks s50002',
        'electrum2.rvn.rocks s50002',
        'electrum3.rvn.rocks s50002',
        'electrum.ravencoin.foundation s50002',
        'aq7vuqykup2voklcrpqljf6jnjkzrouowsjfrmybdou5kdhrpr6sjjid.onion t s'
    ]

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.'''
        if cls.KAWPOW_ACTIVATION_HEIGHT < 0 or height < cls.KAWPOW_ACTIVATION_HEIGHT:
            result = height * cls.BASIC_HEADER_SIZE
        else:  # RVN block header size increased with kawpow fork
            baseoffset = cls.KAWPOW_ACTIVATION_HEIGHT * cls.BASIC_HEADER_SIZE
            result = baseoffset + ((height - cls.KAWPOW_ACTIVATION_HEIGHT) * cls.KAWPOW_HEADER_SIZE)
        return result

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        timestamp = util.unpack_le_uint32_from(header, 68)[0]
        assert cls.KAWPOW_ACTIVATION_TIME > 0

        def reverse_bytes(data):
            b = bytearray(data)
            b.reverse()
            return bytes(b)

        if timestamp >= cls.KAWPOW_ACTIVATION_TIME:
            import kawpow
            nNonce64 = util.unpack_le_uint64_from(header, 80)[0]  # uint64_t
            mix_hash = reverse_bytes(header[88:120])  # uint256

            header_hash = reverse_bytes(double_sha256(header[:80]))

            final_hash = reverse_bytes(kawpow.light_verify(header_hash, mix_hash, nNonce64))
            return final_hash

        elif timestamp >= cls.X16RV2_ACTIVATION_TIME:
            import x16rv2_hash
            return x16rv2_hash.getPoWHash(header)
        else:
            import x16r_hash
            return x16r_hash.getPoWHash(header)

class Avian(Coin):
    NAME = "Avian"
    SHORTNAME = "AVN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    # base58Prefixes in Avian's chainparams.cpp: PUBKEY_ADDRESS 60, SCRIPT_ADDRESS 122
    P2PKH_VERBYTE = bytes.fromhex("3C")
    P2SH_VERBYTES = [bytes.fromhex("7A")]
    WIF_BYTE = bytes.fromhex("80")
    SEGWIT_HRP = "avn"
    GENESIS_HASH = ('000000cdb10fc01df7fba251f2168ef7'
                    'cd7854b571049db4902c315694461dd0')
    DEFAULT_MAX_SEND = 10_000_000
    X16RT_ACTIVATION_TIME = 1638847406   # algo switch to x16rt at this timestamp
    CROW_ACTIVATION_TIME = 1638847407  # crow dual algo activation time

    CHAIN_SIZE = 20_156_386_851
    CHAIN_SIZE_HEIGHT = 2_096_467
    AVG_BLOCK_SIZE = 12_681

    RPC_PORT = 7896
    REORG_LIMIT = 100
    PEERS = [
        'electrum-us.avn.network s50002',
        'electrum-ca.avn.network s50002'
    ]

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a coin address.

        Accepts bech32 native SegWit addresses (avn1q...) as well as legacy
        Base58Check P2PKH and P2SH addresses.
        '''
        witver, witprog = decode_segwit_address(cls.SEGWIT_HRP, address)
        if witprog is not None:
            if witver == 0 and len(witprog) == 20:
                return ScriptPubKey.P2WPKH_script(witprog)
            if witver == 0 and len(witprog) == 32:
                return ScriptPubKey.P2WSH_script(witprog)
            raise CoinError(f'invalid SegWit address: {address}')
        # Fall back to legacy Base58Check (P2PKH / P2SH)
        return super().pay_to_address_script(address)

    @classmethod
    def header_hash(cls, header):
        timestamp = util.unpack_le_uint32_from(header, 68)[0]
        version = int(util.unpack_le_int32_from(header)[0])
        if timestamp >= cls.CROW_ACTIVATION_TIME: # dual algo
            if (version >> 16) & 0xFF == 0:
               import x16rt_hash
               return x16rt_hash.getPoWHash(header)
            else:
               import minotaurx_hash
               return minotaurx_hash.getPoWHash(header)
        elif timestamp >= cls.X16RT_ACTIVATION_TIME: # x16rt
            import x16rt_hash
            return x16rt_hash.getPoWHash(header)
        else:
            import x16r_hash
            return x16r_hash.getPoWHash(header)
