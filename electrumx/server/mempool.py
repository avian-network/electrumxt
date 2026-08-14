# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Mempool handling.'''
import itertools
import math
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Dict, Sequence, Tuple, Set, Iterable, Optional
import re

import attr
from aiorpcx import TaskGroup, run_in_thread, sleep
from asyncio import Lock

from electrumx.lib.addresses import public_key_to_address
from electrumx.lib.hash import hash_to_hex_str, hex_str_to_hash
from electrumx.lib.script import OpCodes, ScriptError, Script
from electrumx.lib.tx import read_tx
from electrumx.lib.util import DataParser, class_logger, chunks, base_encode
from electrumx.server.db import UTXO


class OPPushDataGeneric:
    def __init__(self, pushlen: Callable = None):
        if pushlen is not None:
            self.check_data_len = pushlen

    @classmethod
    def check_data_len(cls, datalen: int) -> bool:
        # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are
        return OpCodes.OP_PUSHDATA4 >= datalen >= 0

    @classmethod
    def is_instance(cls, item):
        # accept objects that are instances of this class
        # or other classes that are subclasses
        return isinstance(item, cls) \
               or (isinstance(item, type) and issubclass(item, cls))


SCRIPTPUBKEY_TEMPLATE_P2PK = [OPPushDataGeneric(lambda x: x in (33, 65)), OpCodes.OP_CHECKSIG]
# Marks an address as valid for restricted assets via qualifier or restricted itself.
ASSET_NULL_TEMPLATE = [OpCodes.OP_RVN_ASSET, OPPushDataGeneric(lambda x: x == 20), OPPushDataGeneric()]
# Used with creating restricted assets. Dictates the qualifier assets associated.
ASSET_NULL_VERIFIER_TEMPLATE = [OpCodes.OP_RVN_ASSET, OpCodes.OP_RESERVED, OPPushDataGeneric()]
# Stop all movements of a restricted asset.
ASSET_GLOBAL_RESTRICTION_TEMPLATE = [OpCodes.OP_RVN_ASSET, OpCodes.OP_RESERVED, OpCodes.OP_RESERVED,
                                     OPPushDataGeneric()]


# -1 if doesn't match, positive if does. Indicates index in script
def match_script_against_template(script, template) -> int:
    """Returns whether 'script' matches 'template'."""
    if script is None:
        return -1
    if len(script) < len(template):
        return -1
    ctr = 0
    for i in range(len(template)):
        ctr += 1
        template_item = template[i]
        script_item = script[i]
        if OPPushDataGeneric.is_instance(template_item) and template_item.check_data_len(script_item[0]):
            continue
        if template_item != script_item[0]:
            return -1
    return ctr


@attr.s(slots=True)
class MemPoolTx(object):
    prevouts = attr.ib()
    # (hashX, value, is_asset, asset_name) tuple
    in_pairs = attr.ib()
    out_pairs = attr.ib()
    fee = attr.ib()
    size = attr.ib()


@attr.s(slots=True)
class MemPoolTxSummary(object):
    hash = attr.ib()
    fee = attr.ib()
    has_unconfirmed_inputs = attr.ib()


class DBSyncError(Exception):
    pass


class MemPoolAPI(ABC):
    '''A concrete instance of this class is passed to the MemPool object
    and used by it to query DB and blockchain state.'''

    @abstractmethod
    async def height(self):
        '''Query bitcoind for its height.'''

    @abstractmethod
    def cached_height(self):
        '''Return the height of bitcoind the last time it was queried,
        for any reason, without actually querying it.
        '''

    @abstractmethod
    def db_height(self):
        '''Return the height flushed to the on-disk DB.'''

    @abstractmethod
    async def mempool_hashes(self):
        '''Query bitcoind for the hashes of all transactions in its
        mempool, returned as a list.'''

    @abstractmethod
    async def raw_transactions(self, hex_hashes):
        '''Query bitcoind for the serialized raw transactions with the given
        hashes.  Missing transactions are returned as None.

        hex_hashes is an iterable of hexadecimal hash strings.'''

    @abstractmethod
    async def lookup_utxos(self, prevouts):
        '''Return a list of (hashX, value) pairs each prevout if unspent,
        otherwise return None if spent or not found.

        prevouts - an iterable of (hash, index) pairs
        '''

    @abstractmethod
    async def on_mempool(self, touched, height, assets,
                         tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                         freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched):
        '''Called each time the mempool is synchronized.  touched is a set of
        hashXs touched since the previous call.  height is the
        daemon's height at the time the mempool was obtained.'''


class MemPool(object):
    '''Representation of the daemon's mempool.

        coin - a coin class from coins.py
        api - an object implementing MemPoolAPI

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the calls in the external interface.  To that end we
    maintain the following maps:

       tx:     tx_hash -> MemPoolTx
       hashXs: hashX   -> set of all hashes of txs touching the hashX
    '''

    def __init__(self, env, api, refresh_secs=5.0, log_status_secs=60.0):
        assert isinstance(api, MemPoolAPI)
        self.coin = env.coin
        self.api = api
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.txs = {}
        self.hashXs = defaultdict(set)  # None can be a key
        self.asset_creates = {}
        self.tx_to_asset_create: Dict[bytes, Set[str]] = defaultdict(set)
        self.asset_reissues = {}
        self.tx_to_asset_reissue: Dict[bytes, Set[str]] = defaultdict(set)

        # qualifier -> dict[ txid, (h160, tx_pos, flag) ]
        self.qualifier_tags: Dict[str, Dict[bytes, Tuple[bytes, int, bool]]] = defaultdict(dict)
        self.tx_to_qualifier_tags: Dict[bytes, Set[str]] = defaultdict(set)

        # h160 -> dict[ txid, (qualifier, tx_pos, flag) ]
        self.h160_tags: Dict[bytes, Dict[bytes, Tuple[str, int, bool]]] = defaultdict(dict)
        self.tx_to_h160_tags: Dict[bytes, Set[bytes]] = defaultdict(set)

        # asset -> dict [ txid, (data, expr, tx_pos) ]
        self.broadcasts: Dict[str, Dict[bytes, Tuple[bytes, Optional[int], int]]] = defaultdict(dict)
        self.tx_to_broadcast: Dict[bytes, Set[str]] = defaultdict(set)

        # asset -> dict [ txid, (tx_pox, flag) ]
        self.freezes: Dict[str, Dict[bytes, Tuple[int, bool]]] = defaultdict(dict)
        self.tx_to_freeze: Dict[bytes, Set[str]] = defaultdict(set)

        # asset -> dict [ txid, (qual_pos, res_pos, verifier) ]
        self.verifiers: Dict[str, Dict[bytes, Tuple[int, int, str]]] = defaultdict(dict)
        self.tx_to_verifier: Dict[bytes, Set[str]] = defaultdict(set)

        # asset -> dict [txid, qual_pos, res_pos, res) ]
        self.qualifier_associations: Dict[str, Dict[bytes, Tuple[int, int, str]]] = defaultdict(dict)
        self.tx_to_qualifier_associations: Dict[bytes, Set[str]] = defaultdict(set)

        self.cached_compact_histogram = []
        self.refresh_secs = refresh_secs
        self.log_status_secs = log_status_secs
        # Prevents mempool refreshes during fee histogram calculation
        self.lock = Lock()

    async def _logging(self, synchronized_event):
        '''Print regular logs of mempool stats.'''

        def fmt_amt(amount):
            whole, frac = divmod(amount, 100_000_000)
            frac = f'{frac:08}'.rstrip('0') or '0'
            frac = f'{frac:8}'
            return f'{whole:,d}.{frac}'
    
        self.logger.info('beginning processing of daemon mempool.  '
                         'This can take some time...')
        start = time.monotonic()
        await synchronized_event.wait()
        elapsed = time.monotonic() - start
        self.logger.info(f'synced in {elapsed:.2f}s')
        while True:
            mempool_size = sum(tx.size for tx in self.txs.values())
            fees = sum(tx.fee for tx in self.txs.values())
            sats_byte = fees / (mempool_size or 1)
            log_msg = f'{len(self.txs):,d} txs {mempool_size/1_000_000:.2f} MB fees {fmt_amt(fees)} ({sats_byte:.3f} sats/b) touching {len(self.hashXs):,d} addresses'
            if self.asset_creates:
                log_msg += f', {len(self.asset_creates):,d} asset creations'
            if self.asset_reissues:
                log_msg += f', {len(self.asset_reissues):,d} asset reissues'
            if self.qualifier_tags:
                log_msg += f', {sum(len(x) for x in self.qualifier_tags.values()):,d} qualifier tags'
            if self.h160_tags:
                log_msg += f', {sum(len(x) for x in self.h160_tags.values()):,d} h160s tagged'
            if self.broadcasts:
                log_msg += f', {sum(len(x) for x in self.broadcasts.values()):,d} broadcasts'
            if self.freezes:
                log_msg += f', {len(self.freezes):,d} freezes'
            if self.verifiers:
                log_msg += f', {len(self.verifiers):,d} verifier string updates'
            if self.qualifier_associations:
                log_msg += f', {sum(len(x) for x in self.qualifier_associations.values()):,d} qualifier associations'
            self.logger.info(log_msg)
            await sleep(self.log_status_secs)
            await synchronized_event.wait()

    async def _refresh_histogram(self, synchronized_event):
        while True:
            await synchronized_event.wait()
            async with self.lock:
                # Threaded as can be expensive
                await run_in_thread(self._update_histogram, 100_000)
            await sleep(self.coin.MEMPOOL_HISTOGRAM_REFRESH_SECS)

    def _update_histogram(self, bin_size):
        # Build a histogram by fee rate
        histogram = defaultdict(int)
        for tx in self.txs.values():
            fee_rate = tx.fee / tx.size
            # use 0.1 sat/byte resolution
            # note: rounding *down* is intentional. This ensures txs
            #       with a given fee rate will end up counted in the expected
            #       bucket/interval of the compact histogram.
            fee_rate = math.floor(10 * fee_rate) / 10
            histogram[fee_rate] += tx.size

        compact = self._compress_histogram(histogram, bin_size=bin_size)
        self.logger.info(f'compact fee histogram: {compact}')
        self.cached_compact_histogram = compact


    @classmethod
    def _compress_histogram(
            cls, histogram: Dict[float, int], *, bin_size: int
    ) -> Sequence[Tuple[float, int]]:
        '''Calculate and return a compact fee histogram as needed for
        "mempool.get_fee_histogram" protocol request.
        histogram: feerate (sat/byte) -> total size in bytes of txs that pay approx feerate
        '''
        # Now compact it.  For efficiency, get_fees returns a
        # compact histogram with variable bin size.  The compact
        # histogram is an array of (fee_rate, vsize) values.
        # vsize_n is the cumulative virtual size of mempool
        # transactions with a fee rate in the interval
        # [rate_(n-1), rate_n)], and rate_(n-1) > rate_n.
        # Intervals are chosen to create tranches containing at
        # least 100kb of transactions
        assert bin_size > 0
        compact = []
        cum_size = 0
        prev_fee_rate = None
        for fee_rate, size in sorted(histogram.items(), reverse=True):
            # if there is a big lump of txns at this specific size,
            # consider adding the previous item now (if not added already)
            if size > 2 * bin_size and prev_fee_rate is not None and cum_size > 0:
                compact.append((prev_fee_rate, cum_size))
                cum_size = 0
                bin_size *= 1.1
            # now consider adding this item
            cum_size += size
            if cum_size > bin_size:
                compact.append((fee_rate, cum_size))
                cum_size = 0
                bin_size *= 1.1
            prev_fee_rate = fee_rate
        return compact

    def _accept_transactions(self, tx_map, utxo_map, touched, assets_touched: Set[str],
                             tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                             freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched):
        '''Accept transactions in tx_map to the mempool if all their inputs
        can be found in the existing mempool or a utxo_map from the
        DB.

        Returns an (unprocessed tx_map, unspent utxo_map) pair.
        '''
        hashXs = self.hashXs
        txs = self.txs
        tx_to_create = self.tx_to_asset_create
        tx_to_reissue = self.tx_to_asset_reissue
        tx_to_qualifier_tags = self.tx_to_qualifier_tags
        tx_to_h160_tags = self.tx_to_h160_tags
        tx_to_broadcast = self.tx_to_broadcast
        tx_to_freeze = self.tx_to_freeze
        tx_to_verifier = self.tx_to_verifier
        tx_to_qualifier_associations = self.tx_to_qualifier_associations

        deferred = {}
        unspent = set(utxo_map)
        # Try to find all prevouts so we can accept the TX
        for tx_hash, tx in tx_map.items():
            in_pairs = []
            try:
                for prevout in tx.prevouts:
                    utxo = utxo_map.get(prevout)
                    if not utxo:
                        prev_hash, prev_index = prevout
                        # Raises KeyError if prev_hash is not in txs
                        utxo = txs[prev_hash].out_pairs[prev_index]
                    in_pairs.append(utxo)
            except KeyError:
                deferred[tx_hash] = tx
                continue

            # Spend the prevouts
            unspent.difference_update(tx.prevouts)

            # Save the in_pairs, compute the fee and accept the TX
            tx.in_pairs = tuple(in_pairs)
            # Avoid negative fees if dealing with generation-like transactions
            # because some in_parts would be missing
            tx.fee = max(0, (sum((v if not asset else 0) for _, v, asset in tx.in_pairs) -
                             sum((v if not asset else 0) for _, v, asset in tx.out_pairs)))
            txs[tx_hash] = tx

            for hashX, _value, _ in itertools.chain(tx.in_pairs, tx.out_pairs):
                touched.add(hashX)
                hashXs[hashX].add(tx_hash)
            
            if tx_hash in tx_to_create:
                assets_touched.update(tx_to_create[tx_hash])
            if tx_hash in tx_to_reissue:
                assets_touched.update(tx_to_reissue[tx_hash])
            if tx_hash in tx_to_qualifier_tags:
                tag_qualifiers_touched.update(tx_to_qualifier_tags[tx_hash])
            if tx_hash in tx_to_h160_tags:
                tag_h160_touched.update(tx_to_h160_tags[tx_hash])
            if tx_hash in tx_to_broadcast:
                broadcasts_asset_touched.update(tx_to_broadcast[tx_hash])
            if tx_hash in tx_to_freeze:
                freezes_asset_touched.update(tx_to_freeze[tx_hash])
            if tx_hash in tx_to_verifier:
                verifier_string_asset_touched.update(tx_to_verifier[tx_hash])
            if tx_hash in tx_to_qualifier_associations:
                restricted_qualifier_touched.update(tx_to_qualifier_associations[tx_hash])

        return deferred, {prevout: utxo_map[prevout] for prevout in unspent}

    async def _refresh_hashes(self, synchronized_event):
        '''Refresh our view of the daemon's mempool.'''
        # Touched accumulates between calls to on_mempool and each
        # call transfers ownership
        touched = set()
        assets_touched = set()
        tag_qualifiers_touched = set()
        tag_h160_touched = set()
        broadcasts_asset_touched = set() 
        freezes_asset_touched = set()
        verifier_string_asset_touched = set()
        restricted_qualifier_touched = set()

        while True:
            height = self.api.cached_height()
            hex_hashes = await self.api.mempool_hashes()
            if height != await self.api.height():
                continue
            hashes = set(hex_str_to_hash(hh) for hh in hex_hashes)
            try:
                async with self.lock:
                    await self._process_mempool(hashes, touched, assets_touched, 
                                                tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                                                freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched,
                                                height)
            except DBSyncError:
                # The UTXO DB is not at the same height as the
                # mempool; wait and try again
                self.logger.debug('waiting for DB to sync')
            else:
                synchronized_event.set()
                synchronized_event.clear()
                await self.api.on_mempool(touched, height, assets_touched,
                                          tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                                          freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched)
                touched = set()
                assets_touched = set()
                tag_qualifiers_touched = set()
                tag_h160_touched = set()
                broadcasts_asset_touched = set() 
                freezes_asset_touched = set()
                verifier_string_asset_touched = set()
                restricted_qualifier_touched = set()
            await sleep(self.refresh_secs)

    async def _process_mempool(self, all_hashes, touched, assets_touched, 
                               tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                               freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched,
                               mempool_height):
        # Re-sync with the new set of hashes
        txs = self.txs
        hashXs = self.hashXs

        tx_to_create = self.tx_to_asset_create
        creates = self.asset_creates

        reissues = self.asset_reissues
        tx_to_reissue = self.tx_to_asset_reissue

        qualifier_tags = self.qualifier_tags
        tx_to_qualifier_tags = self.tx_to_qualifier_tags

        h160_tags = self.h160_tags
        tx_to_h160_tags = self.tx_to_h160_tags

        broadcasts = self.broadcasts
        tx_to_broadcast = self.tx_to_broadcast

        freezes = self.freezes
        tx_to_freeze = self.tx_to_freeze

        verifiers = self.verifiers
        tx_to_verifier = self.tx_to_verifier

        qualifier_associations = self.qualifier_associations
        tx_to_qualifier_associations = self.tx_to_qualifier_associations

        if mempool_height != self.api.db_height():
            raise DBSyncError

        # First handle txs that have disappeared
        for tx_hash in set(txs).difference(all_hashes):
            tx = txs.pop(tx_hash)

            reissued_assets = tx_to_reissue.pop(tx_hash, set())
            for reissued_asset in reissued_assets:
                reissues.pop(reissued_asset, None)

            created_assets = tx_to_create.pop(tx_hash, set())
            for created_asset in created_assets:
                creates.pop(created_asset, None)

            quals = tx_to_qualifier_tags.pop(tx_hash, set())
            for qual in quals:
                qualifier_tags[qual].pop(tx_hash, None)
                if not qualifier_tags[qual]:
                    qualifier_tags.pop(qual, None)

            h160s = tx_to_h160_tags.pop(tx_hash, set())
            for h160 in h160s:
                h160_tags[h160].pop(tx_hash, None)
                if not h160_tags[h160]:
                    h160_tags.pop(h160, None)

            broadcast = tx_to_broadcast.pop(tx_hash, set())
            for b in broadcast:
                broadcasts[b].pop(tx_hash, None)
                if not broadcasts[b]:
                    broadcasts.pop(b, None)

            freeze = tx_to_freeze.pop(tx_hash, set())
            for f in freeze:
                freezes[f].pop(tx_hash, None)
                if not freezes[f]:
                    freezes.pop(f, None)

            verifier = tx_to_verifier.pop(tx_hash, set())
            for v in verifier:
                verifiers[v].pop(tx_hash, None)
                if not verifiers[v]:
                    verifiers.pop(v, None)

            qualifier_association = tx_to_qualifier_associations.pop(tx_hash, set())
            for qa in qualifier_association:
                qualifier_associations[qa].pop(tx_hash)
                if not qualifier_associations[qa]:
                    qualifier_associations.pop(qa, None)

            tx_hashXs = set(hashX for hashX, value, _ in tx.in_pairs)
            tx_hashXs.update(hashX for hashX, value, _ in tx.out_pairs)
            for hashX in tx_hashXs:
                hashXs[hashX].remove(tx_hash)
                if not hashXs[hashX]:
                    del hashXs[hashX]
            touched.update(tx_hashXs)

        # Process new transactions
        new_hashes = list(all_hashes.difference(txs))
        if new_hashes:
            group = TaskGroup()
            for hashes in chunks(new_hashes, 200):
                coro = self._fetch_and_accept(hashes, all_hashes, touched, assets_touched,
                                              tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                                              freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched)
                await group.spawn(coro)

            tx_map = {}
            utxo_map = {}
            async for task in group:
                deferred, unspent = task.result()                

                tx_map.update(deferred)
                utxo_map.update(unspent)

            prior_count = 0
            # FIXME: this is not particularly efficient
            while tx_map and len(tx_map) != prior_count:
                prior_count = len(tx_map)
                tx_map, utxo_map = self._accept_transactions(tx_map, utxo_map,
                                                             touched, assets_touched,
                                                             tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                                                             freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched)
            if tx_map:
                self.logger.error(f'{len(tx_map)} txs dropped')

        return touched

    async def _fetch_and_accept(self, hashes, all_hashes, touched, assets_touched,
                                tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                                freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched):
        '''Fetch a list of mempool transactions.'''
        hex_hashes_iter = (hash_to_hex_str(hash) for hash in hashes)
        raw_txs = await self.api.raw_transactions(hex_hashes_iter)

        creates = self.asset_creates
        tx_to_create = self.tx_to_asset_create

        reissues = self.asset_reissues
        tx_to_reissue = self.tx_to_asset_reissue

        qualifier_tags = self.qualifier_tags
        tx_to_qualifier_tags = self.tx_to_qualifier_tags

        h160_tags = self.h160_tags
        tx_to_h160_tags = self.tx_to_h160_tags

        broadcasts = self.broadcasts
        tx_to_broadcast = self.tx_to_broadcast

        freezes = self.freezes
        tx_to_freeze = self.tx_to_freeze

        verifiers = self.verifiers
        tx_to_verifier = self.tx_to_verifier

        qualifier_associations = self.qualifier_associations
        tx_to_qualifier_associations = self.tx_to_qualifier_associations

        def deserialize_txs():    # This function is pure
            to_hashX = self.coin.hashX_from_script
            read_tx_and_size = read_tx
            # hashx -> txid -> txpos -> (data, expirey)
            maybe_broadcast = defaultdict(lambda: defaultdict(dict))  # type: Dict[bytes, Dict[bytes, Dict[int, Tuple[str, bytes, int]]]]
            verifier_string = None
            verifier_string_pos = None
            restricted_asset = None
            restricted_asset_pos = None
            txs = {}
            for tx_hash, raw_tx in zip(hashes, raw_txs):
                # The daemon may have evicted the tx from its
                # mempool or it may have gotten in a block
                if not raw_tx:
                    continue
                tx, tx_size, wit_hash = read_tx_and_size(raw_tx, 0)
                # Convert the inputs and outputs into (hashX, value) pairs
                # Drop generation-like inputs from MemPoolTx.prevouts
                txin_pairs = tuple((txin.prev_hash, txin.prev_idx)
                                   for txin in tx.inputs
                                   if not txin.is_generation())
                txout_tuple_list = []
                for vout_n, txout in enumerate(tx.outputs):
                    value = txout.value

                    # Every vout needs to be added for other methods to work properly

                    # Best effort for standard scripts
                    ops = Script.get_ops(txout.pk_script)
                    op_ptr = -1
                    for i in range(len(ops)):
                        op = ops[i][0]  # The OpCode
                        if op == OpCodes.OP_RVN_ASSET:
                            op_ptr = i
                            break

                    if op_ptr > 0:
                        # This script has OP_RVN_ASSET. Use everything before this for the script hash.
                        # Get the raw script bytes ending ptr from the previous opcode.
                        script_hash_end = ops[op_ptr - 1][1]
                        hashX = to_hashX(txout.pk_script[:script_hash_end])
                    else:
                        # There is no OP_RVN_ASSET. Hash as-is.
                        hashX = to_hashX(txout.pk_script)

                    # Best effort for standard asset portions
                    if op_ptr == 0:
                        if match_script_against_template(ops, ASSET_NULL_TEMPLATE) > -1:
                            h160 = ops[1][2]
                            asset_portion = ops[2][2]
                            asset_portion_deserializer = DataParser(asset_portion)
                            asset_name = asset_portion_deserializer.read_var_bytes_as_ascii()
                            flag = asset_portion_deserializer.read_boolean()
                            qualifier_tags[asset_name][tx_hash] = (h160, vout_n, flag)
                            tx_to_qualifier_tags[tx_hash].add(asset_name)
                            h160_tags[h160][tx_hash] = (asset_name, vout_n, flag)
                            tx_to_h160_tags[tx_hash].add(h160)
                        elif match_script_against_template(ops, ASSET_NULL_VERIFIER_TEMPLATE) > -1:
                            qualifiers_b = ops[2][2]
                            qualifiers_deserializer = DataParser(qualifiers_b)
                            verifier_string = qualifiers_deserializer.read_var_bytes_as_ascii()
                            verifier_string_pos = vout_n     
                        elif match_script_against_template(ops, ASSET_GLOBAL_RESTRICTION_TEMPLATE) > -1:
                            asset_portion = ops[3][2]
                            asset_portion_deserializer = DataParser(asset_portion)
                            asset_name = asset_portion_deserializer.read_var_bytes_as_ascii()
                            flag = asset_portion_deserializer.read_boolean()
                            freezes[asset_name][tx_hash] = (vout_n, flag)
                            tx_to_freeze[tx_hash].add(asset_name)
                        txout_tuple_list.append((hashX, value, None))
                    elif 0 < op_ptr:
                        try:
                            next_op = ops[op_ptr + 1]
                            asset_script = next_op[2]
                            asset_deserializer = DataParser(asset_script)
                            asset_deserializer.read_bytes(3)
                            asset_type = asset_deserializer.read_int()
                            asset_name = asset_deserializer.read_var_bytes_as_ascii()
                            if asset_name[0] == '$':
                                restricted_asset = asset_name
                                restricted_asset_pos = vout_n
                            if asset_type == b'o'[0]:
                                creates[asset_name] = {
                                    'sats_in_circulation': 100_000_000,
                                    'divisions': 0,
                                    'reissuable': False,
                                    'has_ipfs': False,
                                    'source': {
                                        'tx_hash': hash_to_hex_str(tx_hash),
                                        'tx_pos': vout_n,
                                        'height': -1
                                    }
                                }
                                tx_to_create[tx_hash].add(asset_name)
                                txout_tuple_list.append((hashX, 100_000_000, asset_name))
                            else:
                                value = int.from_bytes(asset_deserializer.read_bytes(8), 'little', signed=False)
                                # Asset reissue chaining is not allowed. There may only be
                                # one reissue in the mempool per asset name
                                if asset_type == b'r'[0]:
                                    divisions = asset_deserializer.read_int()
                                    reissuable = asset_deserializer.read_int()
                                    if asset_deserializer.cursor + 34 <= asset_deserializer.length:
                                        asset_data = asset_deserializer.read_bytes(34)
                                    else:
                                        asset_data = None
                                    d = {
                                        'sats_in_circulation': value,
                                        'divisions': divisions,
                                        'reissuable': True if reissuable != 0 else False,
                                        'has_ipfs': True if asset_data else False,
                                    }
                                    if asset_data:
                                      d['ipfs'] = base_encode(asset_data, 58) if asset_data else None
                                    
                                    d['source'] = {
                                            'tx_hash': hash_to_hex_str(tx_hash),
                                            'tx_pos': vout_n,
                                            'height': -1
                                        }
                                    
                                    reissues[asset_name] = d
                                    tx_to_reissue[tx_hash].add(asset_name)
                                elif asset_type == b'q'[0]:
                                    divisions = asset_deserializer.read_int()
                                    reissuable = asset_deserializer.read_int()
                                    has_meta = asset_deserializer.read_byte()
                                    if has_meta != b'\0':
                                        asset_data = asset_deserializer.read_bytes(34)
                                    else:
                                        asset_data = None

                                    d = {
                                        'sats_in_circulation': value,
                                        'divisions': divisions,
                                        'has_ipfs': True if asset_data else False,
                                        'reissuable': True if reissuable != 0 else False,
                                    }
                                    if asset_data:
                                        d['ipfs'] = base_encode(asset_data, 58) if asset_data else None
                                    d['source'] = {
                                            'tx_hash': hash_to_hex_str(tx_hash),
                                            'tx_pos': vout_n,
                                            'height': -1
                                        }

                                    creates[asset_name] = d
                                    tx_to_create[tx_hash].add(asset_name)
                                elif asset_type == b't'[0]:
                                    if not asset_deserializer.is_finished():
                                        data = asset_deserializer.read_bytes(34)
                                        expire_bytes = None
                                        if not asset_deserializer.is_finished():
                                            expire_bytes = asset_deserializer.read_bytes(8)
                                        maybe_broadcast[hashX][tx_hash][vout_n] = (asset_name, data, int.from_bytes(expire_bytes, 'little') if expire_bytes else None)
                                txout_tuple_list.append((hashX, value, asset_name))
                        except Exception as e:
                            self.logger.warn(f'failed to parse asset in mempool, defaulting to standard hashX: {e}')
                            hashX = to_hashX(txout.pk_script)
                            value = txout.value
                            txout_tuple_list.append((hashX, value, None))
                    else:
                        txout_tuple_list.append((hashX, value, None))

                if restricted_asset and verifier_string:
                    verifiers[restricted_asset][tx_hash] = (verifier_string_pos, restricted_asset_pos, verifier_string)
                    tx_to_verifier[tx_hash].add(restricted_asset)
                    qualifiers = re.findall(r'([A-Z0-9_.]+)', verifier_string)
                    for qualifier in qualifiers:
                        qualifier_associations[qualifier][tx_hash] = (verifier_string_pos, restricted_asset_pos, restricted_asset)
                        tx_to_qualifier_associations[tx_hash].add(qualifier)
                
                assert len(txout_tuple_list) == len(tx.outputs)

                txout_pairs = tuple(txout_tuple_list)
                txs[tx_hash] = MemPoolTx(txin_pairs, None, txout_pairs,
                                         0, tx_size)
            return txs, maybe_broadcast

        # Thread this potentially slow operation so as not to block
        tx_map, possible_broadcasts = await run_in_thread(deserialize_txs)

        # Determine all prevouts not in the mempool, and fetch the
        # UTXO information from the database.  Failed prevout lookups
        # return None - concurrent database updates happen - which is
        # relied upon by _accept_transactions. Ignore prevouts that are
        # generation-like.
        bc_prevouts = tuple((txid, prevout) for txid, tx in tx_map.items()
                         for prevout in tx.prevouts
                         if prevout[0] not in all_hashes)
        mp_prevouts = tuple((txid, prevout) for txid, tx in tx_map.items()
                         for prevout in tx.prevouts
                         if prevout[0] in all_hashes)

        for this_txid, prevout in mp_prevouts:
            prev_hash, prev_index = prevout

            tx = tx_map.get(prev_hash, None)
            if not tx:
                tx = self.txs.get(prev_hash, None)
            if not tx: continue
            hX, v, asset = tx.out_pairs[prev_index]
            for txid, d in possible_broadcasts[hX].items():
                if this_txid != txid: continue
                for tx_pos, (broadcast_asset, data, expiry) in d.items():
                    if broadcast_asset == asset:
                        broadcasts[asset][txid] = (data, expiry, tx_pos)
                        tx_to_broadcast[txid].add(asset)

        utxos = []

        for this_txid, (hX, asset, v) in zip((x[0] for x in bc_prevouts), await self.api.lookup_utxos((x[1] for x in bc_prevouts))):
            utxos.append((hX, v, asset))
            for txid, d in possible_broadcasts[hX].items():
                if this_txid != txid: continue
                for tx_pos, (broadcast_asset, data, expiry) in d.items():
                    if broadcast_asset == asset:
                        broadcasts[asset][txid] = (data, expiry, tx_pos)
                        tx_to_broadcast[txid].add(asset)
    
        utxo_map = {prevout: utxo for prevout, utxo in zip((x[1] for x in bc_prevouts), utxos)}

        return self._accept_transactions(tx_map, utxo_map, touched, assets_touched,
                                         tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                                         freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched)

    #
    # External interface
    #

    async def keep_synchronized(self, synchronized_event):
        '''Keep the mempool synchronized with the daemon.'''

        async with TaskGroup() as group:
            await group.spawn(self._refresh_hashes(synchronized_event))
            await group.spawn(self._refresh_histogram(synchronized_event))
            await group.spawn(self._logging(synchronized_event))

            async for task in group:
                if not task.cancelled():
                    task.result()

    async def balance_delta(self, hashX, asset) -> Dict[Optional[str], int]:
        '''Return the unconfirmed amount in the mempool for hashX.

        Can be positive or negative.
        '''

        def is_asset_valid(db_asset):
            if asset is None or asset is False: return db_asset is None
            elif asset is True: return True
            if isinstance(asset, Iterable):
                return db_asset in asset
            return db_asset == asset
        
        value = defaultdict(int)
        if hashX in self.hashXs:
            for hash_ in self.hashXs[hashX]:
                tx = self.txs[hash_]
                for h168, v, asset in tx.in_pairs:
                    if h168 == hashX and is_asset_valid(asset):
                        value[asset] -= v
                for h168, v, asset in tx.out_pairs:
                    if h168 == hashX and is_asset_valid(asset):
                        value[asset] += v
        return value

    async def compact_fee_histogram(self):
        '''Return a compact fee histogram of the current mempool.'''
        return self.cached_compact_histogram

    async def potential_spends(self, hashX):
        '''Return a set of (prev_hash, prev_idx) pairs from mempool
        transactions that touch hashX.

        None, some or all of these may be spends of the hashX, but all
        actual spends of it (in the DB or mempool) will be included.
        '''
        result = set()
        for tx_hash in self.hashXs.get(hashX, ()):
            tx = self.txs[tx_hash]
            result.update(tx.prevouts)
        return result

    async def transaction_summaries(self, hashX):
        '''Return a list of MemPoolTxSummary objects for the hashX.'''
        result = []
        for tx_hash in self.hashXs.get(hashX, ()):
            tx = self.txs[tx_hash]
            has_ui = any(hash in self.txs for hash, idx in tx.prevouts)
            result.append(MemPoolTxSummary(tx_hash, tx.fee, has_ui))
        return result

    async def unordered_UTXOs(self, hashX, asset):
        '''Return an unordered list of UTXO named tuples from mempool
        transactions that pay to hashX.

        This does not consider if any other mempool transactions spend
        the outputs.
        '''

        def is_asset_valid(db_asset):
            if asset is None or asset is False: return db_asset is None
            elif asset is True: return True
            if isinstance(asset, Iterable):
                return db_asset in asset
            return db_asset == asset

        utxos = []
        for tx_hash in self.hashXs.get(hashX, ()):
            tx = self.txs.get(tx_hash)
            for pos, (hX, value, asset) in enumerate(tx.out_pairs):
                if hX == hashX and is_asset_valid(asset):
                    utxos.append(UTXO(-1, pos, tx_hash, 0, asset, value))
        return utxos

    async def get_asset_creation_if_any(self, asset: str):
        return self.asset_creates.get(asset, None)

    async def get_asset_reissues_if_any(self, asset: str):
        return self.asset_reissues.get(asset, None)
    
    async def get_qualifier_tags(self, asset: str):
        ret = {}
        for txid, (h160, tx_pos, flag) in self.qualifier_tags.get(asset, dict()).items():
            ret[h160.hex()] = {
                'flag': flag,
                'height': -1,
                'tx_hash': hash_to_hex_str(txid),
                'tx_pos': tx_pos
            }
        return ret
    
    async def get_h160_tags(self, h160: str):
        ret = {}
        for txid, (asset, tx_pos, flag) in self.h160_tags.get(h160, dict()).items():
            ret[asset] = {
                'flag': flag,
                'height': -1,
                'tx_hash': hash_to_hex_str(txid),
                'tx_pos': tx_pos
            }
        return ret

    async def get_broadcasts(self, asset: str):
        ret = []
        for txid, (data, expiry, tx_pos) in self.broadcasts.get(asset, dict()).items():
            ret.append({
                'tx_hash': hash_to_hex_str(txid),
                'data': base_encode(data, 58),
                'expiration': expiry,
                'height': -1,
                'tx_pos': tx_pos,
            })
        return ret
    
    async def is_frozen(self, asset: str):
        for txid, (tx_pos, flag) in self.freezes.get(asset, dict()).items():
            return {
                'frozen': flag,
                'height': -1,
                'tx_hash': hash_to_hex_str(txid),
                'tx_pos': tx_pos
            }
        return None

    async def restricted_verifier(self, asset: str):
        for txid, (qual_pos, res_pos, string) in self.verifiers.get(asset, dict()).items():
            return {
                'string': string,
                'height': -1,
                'tx_hash': hash_to_hex_str(txid),
                'restricted_tx_pos': res_pos,
                'qualifying_tx_pos': qual_pos
            }
        return None

    async def restricted_assets_associated_with_qualifier(self, asset: str):
        ret_val = {}
        for txid, (qual_pos, res_pos, restricted_asset) in self.qualifier_associations.get(asset, dict()).items():
            ret_val[restricted_asset] = {
                'associated': True,
                'height': -1,
                'tx_hash': hash_to_hex_str(txid),
                'restricted_tx_pos': res_pos,
                'qualifying_tx_pos': qual_pos
            }
        return ret_val
