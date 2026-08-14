# Copyright (c) 2026, the Avian developers
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Rich, paginated address history.

Serves ``blockchain.scripthash.get_history_rich``: one call returns
display-ready, classified history rows (direction, net amount, counterparty,
fee, time) for a scripthash, newest-first and paginated.  Clients would
otherwise fetch every transaction of an address plus every parent transaction
of every input to work the same rows out for themselves.

Kept deliberately self-contained so it stays cheap to rebase onto upstream
ElectrumX: apart from the handler registration, the ``server.features`` flag
and one SessionManager attribute, everything lives here.
'''

import time
from collections import namedtuple

import pylru
from aiorpcx import RPCError, run_in_thread

from electrumx.lib.addresses import hash160_to_b58_address, public_key_to_address
from electrumx.lib.hash import encode_segwit_address, hash_to_hex_str
from electrumx.lib.script import OpCodes, Script
from electrumx.lib.tx import read_tx
from electrumx.lib.util import chunks, class_logger, unpack_le_uint32_from
from electrumx.server.daemon import DaemonError

# JSON RPC error codes; duplicated from session.py to keep this module free of
# imports that would make it circular.
BAD_REQUEST = 1
DAEMON_ERROR = 2

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
ORDERS = ('newest', 'oldest')

# Classified rows are immutable for a given (hashX, txid, height) so they are
# worth keeping around; a row is a small dict.
ROW_CACHE_SIZE = 20_000
BLOCK_TIME_CACHE_SIZE = 4096
# Timestamp offset in a block header, same for every coin we serve.
HEADER_TIMESTAMP_OFFSET = 68
# Transactions requested from the daemon in a single batched call.
DAEMON_BATCH_SIZE = 200


Prevout = namedtuple('Prevout', 'hashX value address')


def validate_page_args(page, page_size, order):
    '''Validate the pagination arguments, returning them normalised.

    Raises an RPCError if any of them is unusable.
    '''
    try:
        page = int(page)
        page_size = int(page_size)
    except (TypeError, ValueError):
        raise RPCError(BAD_REQUEST, 'page and page_size must be integers') from None
    if page < 0:
        raise RPCError(BAD_REQUEST, f'page {page} should be a non-negative integer')
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise RPCError(BAD_REQUEST, f'page_size must be between 1 and {MAX_PAGE_SIZE}')
    if order not in ORDERS:
        raise RPCError(BAD_REQUEST, f'order must be one of {", ".join(ORDERS)}')
    return page, page_size, order


def _address_from_ops(coin, ops):
    '''Return the address a standard output script pays to, else None.'''
    def pushed(n):
        op = ops[n]
        return bytes(op[2]) if len(op) > 2 else None

    count = len(ops)
    if (count == 5 and ops[0][0] == OpCodes.OP_DUP
            and ops[1][0] == OpCodes.OP_HASH160
            and ops[3][0] == OpCodes.OP_EQUALVERIFY
            and ops[4][0] == OpCodes.OP_CHECKSIG):
        hash160 = pushed(2)
        if hash160 and len(hash160) == 20:
            return hash160_to_b58_address(hash160, coin.P2PKH_VERBYTE)
    elif (count == 3 and ops[0][0] == OpCodes.OP_HASH160
            and ops[2][0] == OpCodes.OP_EQUAL):
        hash160 = pushed(1)
        if hash160 and len(hash160) == 20:
            return hash160_to_b58_address(hash160, coin.P2SH_VERBYTES[0])
    elif count == 2 and ops[1][0] == OpCodes.OP_CHECKSIG:
        pubkey = pushed(0)
        if pubkey and len(pubkey) in (33, 65):
            return public_key_to_address(pubkey, coin.P2PKH_VERBYTE)
    elif count == 2 and ops[0][0] == OpCodes.OP_0:
        hrp = getattr(coin, 'SEGWIT_HRP', None)
        witprog = pushed(1)
        if hrp and witprog and len(witprog) in (20, 32):
            return encode_segwit_address(hrp, 0, witprog)
    return None


def script_hashX_and_address(coin, script):
    '''Return an (hashX, address) pair for an output script.

    The hashX is what the block processor and the mempool index the script
    under - any Avian asset payload is stripped before hashing.  The address is
    None for scripts that do not pay to a standard address.
    '''
    script = bytes(script)
    ops = Script.get_ops(script)
    asset_ptr = -1
    malformed = False
    for n, op in enumerate(ops):
        if op[0] == OpCodes.OP_RVN_ASSET:
            asset_ptr = n
            break
        if op[0] == -1:
            malformed = True
            break

    if asset_ptr > 0:
        # Everything before OP_RVN_ASSET is the script that owns the output
        script = script[:ops[asset_ptr - 1][1]]
        ops = ops[:asset_ptr]

    hashX = coin.hashX_from_script(script)
    if malformed or asset_ptr == 0:
        # An unparseable script, or an asset tagging script that pays nobody
        return hashX, None
    return hashX, _address_from_ops(coin, ops)


def classify_tx(coin, hashX, tx, prevouts):
    '''Classify tx from the point of view of hashX.

    prevouts maps an input's (prev_hash, prev_idx) to a Prevout, or to None if
    the parent transaction could not be resolved.

    Returns a (kind, amount, counterparty, fee) tuple where kind is 'send' if
    the address funded any input and 'receive' otherwise, amount is the net
    number of satoshis the address gained or lost (a send therefore includes
    the fee it paid, as Electrum's own history does), counterparty is the
    largest other party of the transaction, and fee is None when an unresolved
    parent makes it uncomputable.
    '''
    coinbase = any(txin.is_generation() for txin in tx.inputs)
    value_in = ours_in = 0
    incomplete = False
    senders = []
    for txin in tx.inputs:
        if txin.is_generation():
            continue
        prevout = prevouts.get((bytes(txin.prev_hash), txin.prev_idx))
        if prevout is None:
            incomplete = True
            continue
        value_in += prevout.value
        if prevout.hashX == hashX:
            ours_in += prevout.value
        elif prevout.address:
            senders.append((prevout.value, prevout.address))

    value_out = ours_out = 0
    recipients = []
    ours_addresses = []
    for txout in tx.outputs:
        out_hashX, address = script_hashX_and_address(coin, txout.pk_script)
        value_out += txout.value
        if out_hashX == hashX:
            ours_out += txout.value
            if address:
                ours_addresses.append((txout.value, address))
        elif address:
            recipients.append((txout.value, address))

    if coinbase:
        fee = 0
    elif incomplete:
        fee = None
    else:
        fee = max(0, value_in - value_out)

    if ours_in:
        kind = 'send'
        # Prefer whoever we paid; a transaction that only pays ourselves
        # (a consolidation) has us as its own counterparty.
        others = recipients or ours_addresses
    else:
        kind = 'receive'
        others = senders
    counterparty = max(others)[1] if others else None

    return kind, abs(ours_out - ours_in), counterparty, fee


def _deserialize(items):
    '''Deserialize (tx_hash, raw_tx) pairs into a tx_hash -> Tx dict.

    Pure, and slow enough on a big page to be worth a thread.
    '''
    txs = {}
    for tx_hash, raw_tx in items:
        if raw_tx:
            tx, _size, _wit_hash = read_tx(raw_tx, 0)
            txs[tx_hash] = tx
    return txs


class RichHistory:
    '''Builds classified, paginated history pages for a scripthash.'''

    def __init__(self, session_mgr):
        self.session_mgr = session_mgr
        self.coin = session_mgr.env.coin
        self.db = session_mgr.db
        self.daemon = session_mgr.daemon
        self.mempool = session_mgr.mempool
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.row_cache = pylru.lrucache(ROW_CACHE_SIZE)
        self.block_time_cache = pylru.lrucache(BLOCK_TIME_CACHE_SIZE)
        self.lookups = 0
        self.hits = 0

    def cache_stats(self):
        '''Return a (lookups, hits, size) triple for the RPC getinfo call.'''
        return self.lookups, self.hits, len(self.row_cache)

    async def history_page(self, hashX, page, page_size, order):
        '''Return a (result, cost) pair, result being the JSON response.'''
        entries, cost = await self._history_entries(hashX, order)
        start = page * page_size
        rows, row_cost = await self._page_rows(hashX, entries[start:start + page_size])
        return {
            'total': len(entries),
            'page': page,
            'page_size': page_size,
            'order': order,
            'txs': rows,
        }, cost + row_cost

    async def _history_entries(self, hashX, order):
        '''Return a (entries, cost) pair.

        Each entry is a (tx_hash, height, mempool_fee) triple, ordered as
        requested.  Mempool transactions have a height of 0, or -1 if they have
        unconfirmed inputs, and sort ahead of confirmed ones when newest-first.
        '''
        confirmed, cost = await self.session_mgr.limited_history(hashX)
        summaries = await self.mempool.transaction_summaries(hashX)
        cost += 0.1 + len(summaries) / 50

        # The mempool is unordered; sort it so paging is stable between calls
        unconfirmed = sorted(((tx.hash, -tx.has_unconfirmed_inputs, tx.fee)
                              for tx in summaries),
                             key=lambda entry: (-entry[1], entry[0]))
        confirmed = [(tx_hash, height, None) for tx_hash, height in confirmed]
        if order == 'newest':
            return unconfirmed + confirmed[::-1], cost
        return confirmed + unconfirmed, cost

    async def _page_rows(self, hashX, entries):
        '''Return a (rows, cost) pair for the entries of a single page.'''
        cost = 0.1
        rows = []
        misses = []
        for entry in entries:
            tx_hash, height, _mempool_fee = entry
            self.lookups += 1
            row = self.row_cache.get((hashX, tx_hash, height))
            if row is None:
                misses.append(entry)
            else:
                self.hits += 1
                cost += 0.05
            rows.append(row)

        if misses:
            fresh, miss_cost = await self._classify(hashX, misses)
            cost += miss_cost
            rows = [row if row is not None else fresh[(entry[0], entry[1])]
                    for row, entry in zip(rows, entries)]

        # Confirmations move with every block, so they are not part of the
        # cached row.
        tip_height = self.db.state.height

        def confirmations(row):
            if row['height'] <= 0:
                return 0
            return max(0, tip_height - row['height'] + 1)

        return [dict(row, confirmations=confirmations(row)) for row in rows], cost

    async def _classify(self, hashX, misses):
        '''Classify uncached entries, returning a ({(tx_hash, height): row}, cost) pair.'''
        coin = self.coin
        raw_txs = await self._raw_txs(tx_hash for tx_hash, _height, _fee in misses)
        for (tx_hash, _height, _fee), raw_tx in zip(misses, raw_txs):
            if not raw_tx:
                raise RPCError(DAEMON_ERROR,
                               f'transaction {hash_to_hex_str(tx_hash)} could not be '
                               'read from the daemon - is it running with txindex=1?')
        txs = await run_in_thread(
            _deserialize, [(tx_hash, raw_tx)
                           for (tx_hash, _h, _f), raw_tx in zip(misses, raw_txs)])

        # Resolve the parents the inputs spend; some may be on this page already
        wanted = set()
        for tx in txs.values():
            wanted.update(bytes(txin.prev_hash) for txin in tx.inputs
                          if not txin.is_generation())
        parents = {tx_hash: txs[tx_hash] for tx_hash in wanted if tx_hash in txs}
        absent = [tx_hash for tx_hash in wanted if tx_hash not in parents]
        if absent:
            raw_parents = await self._raw_txs(absent)
            parents.update(await run_in_thread(_deserialize, list(zip(absent, raw_parents))))

        times = await self._block_times({height for _tx_hash, height, _fee in misses
                                         if height > 0})
        seen_at = int(time.time())

        def build_rows():
            rows = {}
            for tx_hash, height, mempool_fee in misses:
                tx = txs[tx_hash]
                prevouts = {}
                for txin in tx.inputs:
                    if txin.is_generation():
                        continue
                    key = (bytes(txin.prev_hash), txin.prev_idx)
                    parent = parents.get(key[0])
                    if parent is None or key[1] >= len(parent.outputs):
                        prevouts[key] = None
                        continue
                    txout = parent.outputs[key[1]]
                    out_hashX, address = script_hashX_and_address(coin, txout.pk_script)
                    prevouts[key] = Prevout(out_hashX, txout.value, address)

                kind, amount, counterparty, fee = classify_tx(coin, hashX, tx, prevouts)
                if fee is None:
                    fee = mempool_fee
                rows[(tx_hash, height)] = {
                    'txid': hash_to_hex_str(tx_hash),
                    'height': height,
                    # Mempool transactions have no block time; the first time we
                    # saw one is the closest thing we can offer.
                    'time': times.get(height) if height > 0 else seen_at,
                    'type': kind,
                    'amount': amount,
                    'counterparty': counterparty,
                    'fee': fee,
                }
            return rows

        rows = await run_in_thread(build_rows)
        for key, row in rows.items():
            self.row_cache[(hashX, ) + key] = row
        return rows, len(misses) * 1.0 + len(absent) * 0.1

    async def _raw_txs(self, tx_hashes):
        '''Return the raw transactions for tx_hashes, None where not found.'''
        hex_hashes = [hash_to_hex_str(tx_hash) for tx_hash in tx_hashes]
        raw_txs = []
        try:
            for batch in chunks(hex_hashes, DAEMON_BATCH_SIZE):
                raw_txs.extend(await self.daemon.getrawtransactions(batch))
        except DaemonError as e:
            raise RPCError(DAEMON_ERROR, f'daemon error: {e!r}') from None
        return raw_txs

    async def _block_times(self, heights):
        '''Return a height -> block timestamp dict.'''
        times = {}
        for height in heights:
            timestamp = self.block_time_cache.get(height)
            if timestamp is None:
                header = await self.db.raw_header(height)
                timestamp, = unpack_le_uint32_from(header, HEADER_TIMESTAMP_OFFSET)
                self.block_time_cache[height] = timestamp
            times[height] = timestamp
        return times
