# Copyright (c) 2016-2020, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Interface to the blockchain database.'''


import ast
import copy
import os
import time
import pylru
from array import array
from bisect import bisect_right
from collections import namedtuple
from typing import Optional, List, Dict

import attr
from aiorpcx import run_in_thread, sleep

from electrumx.lib import util
from electrumx.lib.hash import hash_to_hex_str, HASHX_LEN
from electrumx.lib.merkle import Merkle, MerkleCache
from electrumx.lib.util import (
    formatted_time, pack_be_uint32, pack_le_uint32,
    unpack_le_uint32, unpack_be_uint32, unpack_le_uint64, base_encode,
)
from electrumx.server.history import History
from electrumx.server.storage import db_class, Storage
from electrumx.server.env import Env

UTXO = namedtuple("UTXO", "tx_num tx_pos tx_hash height name value")

NULL_U32 = b'\xff\xff\xff\xff'
NULL_TXNUMB = b'\xff\xff\xff\xff\xff'

PREFIX_UTXO_HISTORY = b'h'
PREFIX_HASHX_LOOKUP = b'u'
PREFIX_UTXO_UNDO = b'U'
PREFIX_ASSET_TO_ID = b'a'
PREFIX_ID_TO_ASSET = b'A'
PREFIX_H160_TO_ID = b'h'
PREFIX_ID_TO_H160 = b'H'
PREFIX_ASSET_ID_UNDO = b'b'
PREFIX_H160_ID_UNDO = b'g'
PREFIX_METADATA = b'm'
PREFIX_METADATA_UNDO = b'M'
PREFIX_METADATA_HISTORY = b'n'
PREFIX_METADATA_HISTORY_UNDO = b'N'
PREFIX_BROADCAST = b'b'
PREFIX_BROADCAST_UNDO = b'B'
PREFIX_H160_TAG_CURRENT = b'H'
PREFIX_ASSET_TAG_CURRENT = b'A'
PREFIX_H160_TAG_HISTORY = b'h'
PREFIX_ASSET_TAG_HISTORY = b'a'
PREFIX_TAG_HISTORY_UNDO = b't'
PREFIX_TAG_CURRENT_UNDO = b'T'
PREFIX_FREEZE_CURRENT = b'F'
PREFIX_FREEZE_HISTORY = b'f'
PREFIX_FREEZE_CURRENT_UNDO = b'G'
PREFIX_FREEZE_HISTORY_UNDO = b'g'
PREFIX_VERIFIER_CURRENT = b'V'
PREFIX_VERIFIER_HISTORY = b'v'
PREFIX_VERIFIER_CURRENT_UNDO = b'W'
PREFIX_VERIFIER_HISTORY_UNDO = b'w'
PREFIX_ASSOCIATION_CURRENT = b'Q'
PREFIX_ASSOCIATION_HISTORY = b'q'
PREFIX_ASSOCIATION_CURRENT_UNDO = b'R'
PREFIX_ASSOCIATION_HISTORY_UNDO = b'r'

# Ensure we are not mashing prefixs
_utxo_db_prefixes = [
    PREFIX_UTXO_HISTORY,
    PREFIX_HASHX_LOOKUP,
    PREFIX_UTXO_UNDO
]
assert len(_utxo_db_prefixes) == len(set(_utxo_db_prefixes))

_suid_db_prefixes = [
    PREFIX_ASSET_TO_ID,
    PREFIX_ID_TO_ASSET,
    PREFIX_H160_TO_ID,
    PREFIX_ID_TO_H160,
    PREFIX_ASSET_ID_UNDO,
    PREFIX_H160_ID_UNDO
]
assert len(_suid_db_prefixes) == len(set(_suid_db_prefixes))

_asset_db_prefixes = [
    PREFIX_METADATA,
    PREFIX_METADATA_UNDO,
    PREFIX_METADATA_HISTORY,
    PREFIX_METADATA_HISTORY_UNDO,
    PREFIX_BROADCAST,
    PREFIX_BROADCAST_UNDO,
    PREFIX_H160_TAG_CURRENT,
    PREFIX_ASSET_TAG_CURRENT,
    PREFIX_H160_TAG_HISTORY,
    PREFIX_ASSET_TAG_HISTORY,
    PREFIX_TAG_HISTORY_UNDO,
    PREFIX_TAG_CURRENT_UNDO,
    PREFIX_FREEZE_CURRENT,
    PREFIX_FREEZE_HISTORY,
    PREFIX_FREEZE_CURRENT_UNDO,
    PREFIX_FREEZE_HISTORY_UNDO,
    PREFIX_VERIFIER_CURRENT,
    PREFIX_VERIFIER_HISTORY,
    PREFIX_VERIFIER_CURRENT_UNDO,
    PREFIX_VERIFIER_HISTORY_UNDO,
    PREFIX_ASSOCIATION_CURRENT,
    PREFIX_ASSOCIATION_HISTORY,
    PREFIX_ASSOCIATION_CURRENT_UNDO,
    PREFIX_ASSOCIATION_HISTORY_UNDO
]
assert len(_asset_db_prefixes) == len(set(_asset_db_prefixes))

# Storage Protocol
# flush_utxo_db:
#   history
#        1  |           4          |        4         |             5              |   11  |        4
#       'h' + txid (first 4 bytes) + txo idx (u32_le) + tx_numb (u64_le truncated) = hashX + asset id (u32_le)
#   utxo
#        1  |   11  |     4    |    4     |    5    |      8
#       'u' + hashX + asset id + utxo idx + tx_numb = sats (u64_le)
#   undo
#        1  |        4        |    11  |    5    |   8  |    4
#       'U' + height (u32_be) = [hashX + tx_numb + sats + asset id] ...
#
# flush_suid_db:
#   asset -> id
#        1  |  var  |    4
#       'a' + asset = asset id
#   id -> asset
#        1  |     4    |  var
#       'A' + asset id = asset
#   h160 -> id
#        1  |  20  |       4
#       'h' + h160 = h160 id (u32_le)
#   id -> h160
#        1  |    4    |  20
#       'H' + h160 id = h160
#   undo asset
#        1  |   4    |     4
#       'b' + height = [asset id] ...   
#   undo h160
#        1  |   4    |     4
#       'g' + height = [h160 id] ...
#
# flush_asset_db:
#   metadata
#        1  |     4    |           8           |       1      |      1     |          1          |         34        |       4        |       5        |(  1  |        4       |          5         )|(  1  |           4           |             5            )
#       'm' + asset id = total supply (u64_le) + divisibility + reissuable + has associated data + (associated data) + source txo idx + source tx numb + (\b0 + source txo div + source tx numb div) + (\b1 + source txo associated + source tx numb associated) 
#   metadata undo
#        1  |    4   |     4         |     var_int     |    var
#       'M' + height =[   asset id   +  len + metadata] ...
#
#   metadata history
#        1  |     4    |    4    |    5    |             8            |      1       |        34
#       'n' + asset id + txo idx + tx numb = additional sats (u64_le) + divisibility + (associated data)
#   metadata history undo
#        1  |   4    |      4    |    4    |    5
#       'N' + height = [asset id + txo idx + tx numb] ...
#
#   broadcast
#        1  |     4    |    4    |    5    |       34        |     8
#       'b' + asset id + txo idx + tx numb = associated data + timestamp
#   broadcast undo
#        1  |   4    |      4    |    4    |    5
#       'B' + height = [asset id + txo idx + tx numb] ...
#
#   latest tag (h160 lookup)
#       'H' + h160 id + asset id = txo idx + tx numb
#   latest tag (asset lookup)
#       'A' + asset id + h160 id = txo idx + tx numb
#   tag history (h160 lookup)
#        1  |    4    |    4    |    5    |    4     |  1
#       'h' + h160 id + txo idx + tx numb = asset id + flag
#   tag history (asset lookup)
#        1  |     4    |    4    |    5    |    4    |  1
#       'a' + asset id + txo idx + tx numb = h160 id + flag
#   tag history undo (what to delete)
#        1  |   4    |     4    |    4     |   
#       't' + height = [asset id + h160 id + txo idx + tx numb]...
#   latest tag undo (what to restore)
#       'T' + height = [asset id + h160 id + txo idx + tx numb]...
#
#   latest freeze ()
#       'F' + asset id = txo idx + tx numb
#   freeze history
#       'f' + asset id + txo idx + tx numb = flag
#   latest freeze undo
#       'G' + height = [asset id + txo idx + tx numb]
#   freeze history undo
#       'g' + height = [asset id + txo idx + tx numb] ...
#
#   latest verifier
#       'V' + asset id = restricted idx + qualifiers idx + tx numb
#       'v' + asset id + restricted idx + qualifiers idx + tx numb = string
#       'W' + height = [asset id + restricted idx + qualifiers idx + tx numb] ...
#       'w' + height = [asset id + restricted idx + qualifier idx + tx numb] ...
#
#   associations
#       'Q' + qual id + restric id = restricted idx + qualifiers idx + tx numb
#       'q' + qual id + restric id + restricted idx + qualifiers idx + tx numb = flag
#       'R' + height = [qualifier id + restricted id + restricted idx + qualifiers idx + tx numb]
#       'r'


@attr.s(slots=True)
class ChainState:
    height = attr.ib()
    tx_count = attr.ib()
    asset_count = attr.ib()
    h160_count = attr.ib()
    chain_size = attr.ib()
    tip = attr.ib()
    flush_count = attr.ib()   # of UTXOs
    sync_time = attr.ib()    # Cumulative
    flush_time = attr.ib()    # Time of flush
    first_sync = attr.ib()
    db_version = attr.ib()
    utxo_count = attr.ib()

    def copy(self):
        return copy.copy(self)


@attr.s(slots=True)
class FlushData(object):
    state = attr.ib(type=ChainState)
    headers = attr.ib()
    block_tx_hashes = attr.ib()
    
    # The following are flushed to the UTXO DB if undo_infos is not None
    utxo_undo_infos = attr.ib()
    utxo_adds = attr.ib()
    utxo_deletes = attr.ib()
    
    # Asset Ids
    asset_id_adds = attr.ib()
    asset_id_undo_infos = attr.ib()
    asset_id_deletes = attr.ib()
    
    # H160 Ids
    h160_id_adds = attr.ib()
    h160_id_undo_infos = attr.ib()
    h160_id_deletes = attr.ib()

    # Metadata
    metadata_sets = attr.ib()
    metadata_undo_infos = attr.ib()
    metadata_deletes = attr.ib()
    metadata_history_adds = attr.ib()
    metadata_history_undo_infos = attr.ib()
    metadata_history_deletes = attr.ib()

    # Broadcasts
    broadcast_adds = attr.ib()
    broadcast_undo_infos = attr.ib()
    broadcast_deletes = attr.ib()

    # Tags
    tag_sets = attr.ib()
    tag_undo_infos = attr.ib()
    tag_deletes = attr.ib()
    tag_history_adds = attr.ib()
    tag_history_undo_infos = attr.ib()
    tag_history_deletes = attr.ib()

    # Freezes
    freeze_sets = attr.ib()
    freeze_undo_infos = attr.ib()
    freeze_deletes = attr.ib()
    freeze_history_adds = attr.ib()
    freeze_history_undo_infos = attr.ib()
    freeze_history_deletes = attr.ib()

    # Verifier Strings
    verifier_sets = attr.ib()
    verifier_undo_infos = attr.ib()
    verifier_deletes = attr.ib()
    verifier_history_adds = attr.ib()
    verifier_history_undo_infos = attr.ib()
    verifier_history_deletes = attr.ib()

    # Associations
    association_sets = attr.ib()
    association_undo_infos = attr.ib()
    association_deletes = attr.ib()
    association_history_adds = attr.ib()
    association_history_undo_infos = attr.ib()
    association_history_deletes = attr.ib()

class DB:
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    DB_VERSIONS = [0]

    class DBError(Exception):
        '''Raised on general DB errors generally indicating corruption.'''

    def __init__(self, env: Env):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.env = env
        self.coin = env.coin

        self.header_offset = self.coin.static_header_offset
        self.header_len = self.coin.static_header_len

        self.logger.info(f'switching current directory to {env.db_dir}')
        os.chdir(env.db_dir)

        self.db_class = db_class(self.env.db_engine)
        self.history = History()
        self.utxo_db: Storage = None
        self.state: Optional[ChainState] = None
        self.last_flush_state = None

        self.fs_height = -1
        self.fs_tx_count = 0
        self.fs_asset_count = 0
        self.fs_h160_count = 0
        
        self.tx_counts = None
        
        self.asset_db: Storage = None
        self.suid_db: Storage = None

        self.logger.info(f'using {self.env.db_engine} for DB backend')

        # Header merkle cache
        self.merkle = Merkle()
        self.header_mc = MerkleCache(self.merkle, self.fs_block_hashes)

        self.headers_file = util.LogicalFile('meta/headers', 2, 16000000)
        self.tx_counts_file = util.LogicalFile('meta/txcounts', 2, 2000000)
        self.hashes_file = util.LogicalFile('meta/hashes', 4, 16000000)

    async def _read_tx_counts(self):
        if self.tx_counts is not None:
            return
        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        size = (self.state.height + 1) * 8
        tx_counts = self.tx_counts_file.read(0, size)
        assert len(tx_counts) == size
        self.tx_counts = array('Q', tx_counts)
        if self.tx_counts:
            assert self.state.tx_count == self.tx_counts[-1]
        else:
            assert self.state.tx_count == 0

    async def _open_dbs(self, for_sync, compacting) -> ChainState:
        assert self.utxo_db is None
        assert self.asset_db is None
        assert self.suid_db is None

        # First UTXO DB
        self.utxo_db = self.db_class('utxo', for_sync)
        if self.utxo_db.is_new:
            self.logger.info('created new database')
            self.logger.info('creating metadata directory')
            os.mkdir('meta')
            with util.open_file('COIN', create=True) as f:
                f.write(f'ElectrumX databases and metadata for '
                        f'{self.coin.NAME} {self.coin.NET}'.encode())
        else:
            self.logger.info(f'opened UTXO DB (for sync: {for_sync})')

        # Asset DB
        self.asset_db = self.db_class('asset', for_sync)

        # Sequential unique id DB
        self.suid_db = self.db_class('suid', for_sync)

        self.read_utxo_state()

        # Then history DB
        self.state.flush_count = self.history.open_db(self.db_class, for_sync,
                                                      self.state.flush_count,
                                                      compacting)
        self.clear_excess_undo_info()

        # Read TX counts (requires meta directory)
        await self._read_tx_counts()
        return self.state

    async def open_for_compacting(self):
        return await self._open_dbs(True, True)

    async def open_for_sync(self):
        '''Open the databases to sync to the daemon.

        When syncing we want to reserve a lot of open files for the
        synchronization.  When serving clients we want the open files for
        serving network connections.
        '''
        return await self._open_dbs(True, False)

    async def open_for_serving(self):
        '''Open the databases for serving.  If they are already open they are
        closed first.
        '''
        if self.utxo_db:
            self.logger.info('closing DBs to re-open for serving')
            self.utxo_db.close()
            self.asset_db.close()
            self.suid_db.close()
            self.history.close_db()
            self.utxo_db = None
            self.asset_db = None
            self.suid_db = None
            
        return await self._open_dbs(False, False)

    # Header merkle cache
    async def populate_header_merkle_cache(self):
        self.logger.info('populating header merkle cache...')
        length = max(1, self.state.height - self.env.reorg_limit)
        start = time.monotonic()
        await self.header_mc.initialize(length)
        elapsed = time.monotonic() - start
        self.logger.info(f'header merkle cache populated in {elapsed:.1f}s')

    async def header_branch_and_root(self, length, height):
        return await self.header_mc.branch_and_root(length, height)

    # Flushing
    def assert_flushed(self, flush_data: FlushData):
        '''Asserts state is fully flushed.'''
        assert flush_data.state.tx_count == self.fs_tx_count == self.state.tx_count
        assert flush_data.state.asset_count == self.fs_asset_count == self.state.asset_count
        assert flush_data.state.h160_count == self.fs_h160_count == self.state.h160_count
        assert flush_data.state.height == self.fs_height == self.state.height
        assert flush_data.state.tip == self.state.tip
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert not flush_data.utxo_adds
        assert not flush_data.utxo_deletes
        assert not flush_data.utxo_undo_infos

        assert not flush_data.asset_id_adds
        assert not flush_data.asset_id_undo_infos
        assert not flush_data.asset_id_deletes

        assert not flush_data.h160_id_adds
        assert not flush_data.h160_id_undo_infos
        assert not flush_data.h160_id_deletes

        assert not flush_data.metadata_sets
        assert not flush_data.metadata_undo_infos
        assert not flush_data.metadata_deletes
        assert not flush_data.metadata_history_adds
        assert not flush_data.metadata_history_undo_infos
        assert not flush_data.metadata_history_deletes

        assert not flush_data.tag_sets
        assert not flush_data.tag_undo_infos
        assert not flush_data.tag_deletes
        assert not flush_data.tag_history_adds
        assert not flush_data.tag_history_undo_infos
        assert not flush_data.tag_history_deletes

        assert not flush_data.freeze_sets
        assert not flush_data.freeze_undo_infos
        assert not flush_data.freeze_deletes
        assert not flush_data.freeze_history_adds
        assert not flush_data.freeze_history_undo_infos
        assert not flush_data.freeze_history_deletes

        assert not flush_data.verifier_sets
        assert not flush_data.verifier_undo_infos
        assert not flush_data.verifier_deletes
        assert not flush_data.verifier_history_adds
        assert not flush_data.verifier_history_deletes
        assert not flush_data.verifier_history_undo_infos

        assert not flush_data.association_sets
        assert not flush_data.association_undo_infos
        assert not flush_data.association_deletes
        assert not flush_data.association_history_adds
        assert not flush_data.association_history_undo_infos
        assert not flush_data.association_history_deletes

        assert not flush_data.broadcast_adds
        assert not flush_data.broadcast_deletes
        assert not flush_data.broadcast_undo_infos

        self.history.assert_flushed()

    
    def log_flush_stats(self, prefix, flush_data, elapsed):
        tx_delta = flush_data.state.tx_count - self.last_flush_state.tx_count
        asset_delta = flush_data.state.asset_count - self.last_flush_state.asset_count
        size_delta = flush_data.state.chain_size - self.last_flush_state.chain_size
        utxo_count_delta = flush_data.state.utxo_count - self.last_flush_state.utxo_count

        self.logger.info(f'flush #{self.history.flush_count:,d} took {elapsed:.1f}s.  '
                         f'Height {flush_data.state.height:,d} '
                         f'txs: {flush_data.state.tx_count:,d} ({tx_delta:+,d}) '
                         f'utxos: {flush_data.state.utxo_count:,d} ({utxo_count_delta:+,d}) '
                         f'assets: {flush_data.state.asset_count:,d} ({asset_delta:+,d}) '
                         f'size: {flush_data.state.chain_size:,d} ({size_delta:+,d})')
        return size_delta


    def flush_dbs(self, flush_data: FlushData, flush_utxos, size_remaining):
        '''Flush out cached state.  History is always flushed; UTXOs are
        flushed if flush_utxos.'''
        if flush_data.state.height == self.state.height:
            self.assert_flushed(flush_data)
            return

        start_time = time.time()

        # Flush to file system
        self.flush_fs(flush_data)

        # Then history
        self.flush_history()
        flush_data.state.flush_count = self.history.flush_count

        # Flush state last as it reads the wall time.
        if flush_utxos:
            self.flush_suid_db(flush_data)
            self.flush_asset_db(flush_data)
            self.flush_utxo_db(flush_data)

        end_time = time.time()
        elapsed = end_time - start_time
        flush_interval = end_time - self.last_flush_state.flush_time
        flush_data.state.flush_time = end_time
        flush_data.state.sync_time += flush_interval

        # Update and flush state again so as not to drop the batch commit time
        if flush_utxos:
            self.state = flush_data.state.copy()
            self.write_utxo_state(self.utxo_db)

        size_delta = self.log_flush_stats('flush', flush_data, elapsed)

        # Catch-up stats
        if self.utxo_db.for_sync:
            size_per_sec_gen = flush_data.state.chain_size / (flush_data.state.sync_time + 0.01)
            size_per_sec_last = size_delta / (flush_interval + 0.01)
            eta = size_remaining / (size_per_sec_last + 0.01) * 1.1
            self.logger.info(f'MB/sec since genesis: {size_per_sec_gen / 1_000_000:.2f}, '
                             f'since last flush: {size_per_sec_last / 1_000_000:.2f}')
            self.logger.info(f'sync time: {formatted_time(flush_data.state.sync_time)}  '
                             f'ETA: {formatted_time(eta)}')
        else:
            # Avian has a hard reorg limit of 60; we don't need to keep anything else
            self.clear_excess_undo_info(False)
        self.last_flush_state = flush_data.state.copy()
        
    def flush_fs(self, flush_data):
        '''Write headers, tx counts and block tx hashes to the filesystem.

        The first height to write is self.fs_height + 1.  The FS
        metadata is all append-only, so in a crash we just pick up
        again from the height stored in the DB.
        '''
        prior_tx_count = (self.tx_counts[self.fs_height]
                          if self.fs_height >= 0 else 0)
        assert len(flush_data.block_tx_hashes) == len(flush_data.headers)
        assert flush_data.state.height == self.fs_height + len(flush_data.headers)
        assert flush_data.state.tx_count == (self.tx_counts[-1] if self.tx_counts else 0)
        assert len(self.tx_counts) == flush_data.state.height + 1
        hashes = b''.join(flush_data.block_tx_hashes)
        flush_data.block_tx_hashes.clear()
        assert len(hashes) % 32 == 0
        assert len(hashes) // 32 == flush_data.state.tx_count - prior_tx_count

        # Write the headers, tx counts, and tx hashes
        height_start = self.fs_height + 1
        offset = self.header_offset(height_start)
        self.headers_file.write(offset, b''.join(flush_data.headers))
        flush_data.headers.clear()

        offset = height_start * self.tx_counts.itemsize
        self.tx_counts_file.write(offset,
                                  self.tx_counts[height_start:].tobytes())
        offset = prior_tx_count * 32
        self.hashes_file.write(offset, hashes)

        self.fs_height = flush_data.state.height
        self.fs_tx_count = flush_data.state.tx_count
        self.fs_asset_count = flush_data.state.asset_count
        self.fs_h160_count = flush_data.state.h160_count

    def flush_history(self):
        self.history.flush()

    def flush_suid_db(self, flush_data: FlushData):
        start_time = time.monotonic()
        asset_add_count = len(flush_data.asset_id_adds)
        h160_add_count = len(flush_data.h160_id_adds)
        with self.suid_db.write_batch() as batch:
            # Walk-backs
            batch_delete = batch.delete
            for deletion_list in [flush_data.asset_id_deletes, 
                                  flush_data.h160_id_deletes]:
                for key in sorted(deletion_list):
                    batch_delete(key)
                deletion_list.clear()

            batch_put = batch.put
            for key, value in flush_data.asset_id_adds.items():
                batch_put(PREFIX_ASSET_TO_ID + key, value)
                batch_put(PREFIX_ID_TO_ASSET + value, key)
            flush_data.asset_id_adds.clear()
            for key, value in flush_data.h160_id_adds.items():
                batch_put(PREFIX_H160_TO_ID + key, value)
                batch_put(PREFIX_ID_TO_H160 + value, key)
            flush_data.h160_id_adds.clear()

            for prefix, undo_list in [(PREFIX_ASSET_ID_UNDO, flush_data.asset_id_undo_infos),
                                      (PREFIX_H160_ID_UNDO, flush_data.h160_id_undo_infos)]:
                self.flush_undo_infos(batch_put, prefix, undo_list)
                undo_list.clear()
            
        if self.suid_db.for_sync:
            elapsed = time.monotonic() - start_time
            self.logger.info(f'flushed {asset_add_count:,d} asset ids, '
                             f'{h160_add_count:,d} h160 ids in '
                             f'{elapsed:.1f}s, committing...')

    def flush_asset_db(self, flush_data: FlushData):
        start_time = time.monotonic()
        metadata_sets = len(flush_data.metadata_sets)
        metadata_history_adds = len(flush_data.metadata_history_adds)
        broadcast_adds = len(flush_data.broadcast_adds)
        tag_sets = len(flush_data.tag_sets)
        tag_history_adds = len(flush_data.tag_history_adds)
        freeze_sets = len(flush_data.freeze_sets)
        freeze_history_adds = len(flush_data.freeze_history_adds)
        verifier_sets = len(flush_data.verifier_sets)
        verifier_history_adds = len(flush_data.verifier_history_adds)
        association_sets = len(flush_data.association_sets)
        association_history_adds = len(flush_data.association_history_adds)
        with self.asset_db.write_batch() as batch:
            batch_delete = batch.delete
            for deletion_list in [flush_data.metadata_deletes, 
                                  flush_data.metadata_history_deletes,
                                  flush_data.broadcast_deletes,
                                  flush_data.tag_deletes,
                                  flush_data.tag_history_deletes,
                                  flush_data.freeze_deletes,
                                  flush_data.freeze_history_deletes,
                                  flush_data.verifier_deletes,
                                  flush_data.verifier_history_deletes,
                                  flush_data.association_deletes,
                                  flush_data.association_history_deletes]:
                for key in sorted(deletion_list):
                    batch_delete(key)
                deletion_list.clear()

            batch_put = batch.put
            for prefix, simple_puts in [(PREFIX_METADATA, flush_data.metadata_sets),
                                        (PREFIX_METADATA_HISTORY, flush_data.metadata_history_adds),
                                        (PREFIX_BROADCAST, flush_data.broadcast_adds),
                                        (PREFIX_FREEZE_CURRENT, flush_data.freeze_sets),
                                        (PREFIX_FREEZE_HISTORY, flush_data.freeze_history_adds),
                                        (PREFIX_VERIFIER_CURRENT, flush_data.verifier_sets),
                                        (PREFIX_VERIFIER_HISTORY, flush_data.verifier_history_adds),
                                        (PREFIX_ASSOCIATION_CURRENT, flush_data.association_sets),
                                        (PREFIX_ASSOCIATION_HISTORY, flush_data.association_history_adds)]:
                for key, value in simple_puts.items():
                    batch_put(prefix + key, value)
                simple_puts.clear()

            for key, value in flush_data.tag_sets.items():
                asset_id = key[:4]
                h160_id = key[4:8]
                batch_put(PREFIX_ASSET_TAG_CURRENT + key, value)
                batch_put(PREFIX_H160_TAG_CURRENT + h160_id + asset_id, value)
            flush_data.tag_sets.clear()

            for key, value in flush_data.tag_history_adds.items():
                asset_id = key[:4]
                h160_id = key[4:8]
                suffix = key[8:]
                batch_put(PREFIX_ASSET_TAG_HISTORY + asset_id + suffix, h160_id + value)
                batch_put(PREFIX_H160_TAG_HISTORY + h160_id + suffix, asset_id + value)
            flush_data.tag_history_adds.clear()

            for prefix, undo_list in [(PREFIX_METADATA_UNDO, flush_data.metadata_undo_infos),
                                      (PREFIX_METADATA_HISTORY_UNDO, flush_data.metadata_history_undo_infos),
                                      (PREFIX_BROADCAST_UNDO, flush_data.broadcast_undo_infos),
                                      (PREFIX_TAG_CURRENT_UNDO, flush_data.tag_undo_infos),
                                      (PREFIX_TAG_HISTORY_UNDO, flush_data.tag_history_undo_infos),
                                      (PREFIX_FREEZE_CURRENT_UNDO, flush_data.freeze_undo_infos),
                                      (PREFIX_FREEZE_HISTORY_UNDO, flush_data.freeze_history_undo_infos),
                                      (PREFIX_VERIFIER_CURRENT_UNDO, flush_data.verifier_undo_infos),
                                      (PREFIX_VERIFIER_HISTORY_UNDO, flush_data.verifier_history_undo_infos),
                                      (PREFIX_ASSOCIATION_CURRENT_UNDO, flush_data.association_undo_infos),
                                      (PREFIX_ASSOCIATION_HISTORY_UNDO, flush_data.association_history_undo_infos)]:
                self.flush_undo_infos(batch_put, prefix, undo_list)
                undo_list.clear()
        
        if self.asset_db.for_sync:
            elapsed = time.monotonic() - start_time
            self.logger.info(f'flushed {metadata_sets:,d} asset metadata sets, '
                             f'{metadata_history_adds:,d} asset metadata histories, '
                             f'{tag_sets:,d} tag sets, '
                             f'{tag_history_adds:,d} tag histories, '
                             f'{freeze_sets:,d} freeze sets, '
                             f'{freeze_history_adds:,d} freeze histories, '
                             f'{verifier_sets:,d} verifier string sets, '
                             f'{verifier_history_adds:,d} verifier string histories, '
                             f'{association_sets:,d} qualifier association sets, '
                             f'{association_history_adds:,d} qualifier association histories, '
                             f'{broadcast_adds:,d} broadcasts in '
                             f'{elapsed:.1f}s, committing...')

    def flush_utxo_db(self, flush_data: FlushData):
        '''Flush the cached DB writes and UTXO set to the batch.'''
        # Care is needed because the writes generated by flushing the
        # UTXO state may have keys in common with our write cache or
        # may be in the DB already.
        start_time = time.monotonic()
        add_count = len(flush_data.utxo_adds)
        spend_count = len(flush_data.utxo_deletes) // 2
        with self.utxo_db.write_batch() as batch:
            # Spends
            batch_delete = batch.delete
            for key in sorted(flush_data.utxo_deletes):
                batch_delete(key)
            flush_data.utxo_deletes.clear()

            # New UTXOs
            batch_put = batch.put
            for key, value in flush_data.utxo_adds.items():
                # suffix = tx_idx + tx_num
                hashX = value[:HASHX_LEN]
                suffix = key[-4:] + value[HASHX_LEN:HASHX_LEN+5]
                asset_id = value[-4:]
                assert len(hashX) == HASHX_LEN
                assert len(asset_id) == 4
                batch_put(PREFIX_UTXO_HISTORY + key[:4] + suffix, hashX + asset_id)
                batch_put(PREFIX_HASHX_LOOKUP + hashX + asset_id + suffix, value[-12:-4])
            flush_data.utxo_adds.clear()

            # New undo information
            self.flush_undo_infos(batch_put, PREFIX_UTXO_UNDO, flush_data.utxo_undo_infos)
            flush_data.utxo_undo_infos.clear()

            if self.utxo_db.for_sync:
                block_count = flush_data.state.height - self.state.height
                asset_count = flush_data.state.asset_count - self.state.asset_count
                tx_count = flush_data.state.tx_count - self.state.tx_count
                size = (flush_data.state.chain_size - self.state.chain_size) / 1_000_000_000
                elapsed = time.monotonic() - start_time
                self.logger.info(f'flushed {block_count:,d} blocks size {size:.1f} GB with '
                                 f'{asset_count:,d} assets, '
                                 f'{tx_count:,d} txs, {add_count:,d} UTXO adds, '
                                 f'{spend_count:,d} spends in '
                                 f'{elapsed:.1f}s, committing...')

            self.state = flush_data.state.copy()
            self.write_utxo_state(batch)

    def flush_backup(self, flush_data, touched):
        '''Like flush_dbs() but when backing up.  All UTXOs are flushed.'''
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert flush_data.state.height < self.state.height
        self.history.assert_flushed()

        start_time = time.time()
        
        self.backup_fs(flush_data.state.height, flush_data.state.tx_count, flush_data.state.asset_count, flush_data.state.h160_count)
        self.history.backup(touched, flush_data.state.tx_count)

        self.flush_utxo_db(flush_data)
        self.flush_asset_db(flush_data)
        self.flush_suid_db(flush_data)

        elapsed = time.time() - start_time
        self.log_flush_stats('backup flush', flush_data, time.time() - start_time)

        self.last_flush_state = flush_data.state.copy()

    def backup_fs(self, height, tx_count, asset_count, h160_count):
        '''Back up during a reorg.  This just updates our pointers.'''
        self.fs_height = height
        self.fs_tx_count = tx_count
        self.fs_asset_count = asset_count
        self.fs_h160_count = h160_count
        # Truncate header_mc: header count is 1 more than the height.
        self.header_mc.truncate(height + 1)

    async def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = await self.read_headers(height, 1)
        if n != 1:
            raise IndexError(f'height {height:,d} out of range')
        return header

    async def read_headers(self, start_height, count):
        '''Requires start_height >= 0, count >= 0.  Reads as many headers as are available
        starting at start_height up to count.  This would be zero if start_height is
        beyond state.height, for example.

        Returns a (binary, n) pair where binary is the concatenated binary headers, and n
        is the count of headers returned.
        '''
        if start_height < 0 or count < 0:
            raise self.DBError(f'{count:,d} headers starting at '
                               f'{start_height:,d} not on disk')

        def read_headers():
            # Read some from disk
            disk_count = max(0, min(count, self.state.height + 1 - start_height))
            if disk_count:
                offset = self.header_offset(start_height)
                size = self.header_offset(start_height + disk_count) - offset
                return self.headers_file.read(offset, size), disk_count
            return b'', 0

        return await run_in_thread(read_headers)

    def fs_tx_hash(self, tx_num):
        '''Return a pair (tx_hash, tx_height) for the given tx number.

        If the tx_height is not on disk, returns (None, tx_height).'''
        tx_height = bisect_right(self.tx_counts, tx_num)
        if tx_height > self.state.height:
            tx_hash = None
        else:
            tx_hash = self.hashes_file.read(tx_num * 32, 32)
        return tx_hash, tx_height

    def fs_tx_hashes_at_blockheight(self, block_height):
        '''Return a list of tx_hashes at given block height,
        in the same order as in the block.
        '''
        if block_height > self.state.height:
            raise self.DBError(f'block {block_height:,d} not on disk (>{self.state.height:,d})')
        assert block_height >= 0
        if block_height > 0:
            first_tx_num = self.tx_counts[block_height - 1]
        else:
            first_tx_num = 0
        num_txs_in_block = self.tx_counts[block_height] - first_tx_num
        tx_hashes = self.hashes_file.read(first_tx_num * 32, num_txs_in_block * 32)
        assert num_txs_in_block == len(tx_hashes) // 32
        return [tx_hashes[idx * 32: (idx+1) * 32] for idx in range(num_txs_in_block)]

    async def tx_hashes_at_blockheight(self, block_height):
        return await run_in_thread(self.fs_tx_hashes_at_blockheight, block_height)

    async def fs_block_hashes(self, height, count):
        coin = self.coin

        def _read_and_hash():
            disk_count = max(0, min(count, self.state.height + 1 - height))
            if disk_count != count:
                raise self.DBError(f'only got {disk_count:,d} headers starting at {height:,d}, '
                                   f'not {count:,d}')
            if disk_count == 0:
                return []
            offset = self.header_offset(height)
            size = self.header_offset(height + disk_count) - offset
            headers_concat = self.headers_file.read(offset, size)
            off = 0
            result = []
            for n in range(disk_count):
                hlen = self.header_len(height + n)
                result.append(coin.header_hash(headers_concat[off:off + hlen]))
                off += hlen
            return result

        return await run_in_thread(_read_and_hash)

    async def limited_history(self, hashX, *, limit=1000):
        '''Return an unpruned, sorted list of (tx_hash, height) tuples of
        confirmed transactions that touched the address, earliest in
        the blockchain first.  Includes both spending and receiving
        transactions.  By default returns at most 1000 entries.  Set
        limit to None to get them all.
        '''
        def read_history():
            tx_nums = list(self.history.get_txnums(hashX, limit))
            fs_tx_hash = self.fs_tx_hash
            return [fs_tx_hash(tx_num) for tx_num in tx_nums]

        while True:
            history = await run_in_thread(read_history)
            if all(hash is not None for hash, height in history):
                return history
            self.logger.warning('limited_history: tx hash not found (reorg?), retrying...')
            await sleep(0.25)

    # -- Undo information
    
    def min_undo_height(self, max_height):
        '''Returns a height from which we should store undo info.'''
        return max_height - self.env.reorg_limit + 1

    def undo_key(self, prefix: bytes, height: int):
        return prefix + pack_be_uint32(height)

    def read_utxo_undo_info(self, height):
        '''Read undo information from a file for the current height.'''
        return self.utxo_db.get(self.undo_key(PREFIX_UTXO_UNDO, height))
    
    def read_asset_id_undo_info(self, height):
        return self.suid_db.get(self.undo_key(PREFIX_ASSET_ID_UNDO, height))
    
    def read_h160_id_undo_info(self, height):
        return self.suid_db.get(self.undo_key(PREFIX_H160_ID_UNDO, height))
    
    def read_metadata_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_METADATA_UNDO, height))
    
    def read_metadata_history_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_METADATA_HISTORY_UNDO, height))

    def read_broadcast_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_BROADCAST_UNDO, height))

    def read_tag_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_TAG_CURRENT_UNDO, height))
    
    def read_tag_history_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_TAG_HISTORY_UNDO, height))

    def read_verifier_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_VERIFIER_CURRENT_UNDO, height))
    
    def read_verifier_history_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_VERIFIER_HISTORY_UNDO, height))

    def read_association_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_ASSOCIATION_CURRENT_UNDO, height))
    
    def read_association_history_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_ASSOCIATION_HISTORY_UNDO, height))

    def read_freeze_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_FREEZE_CURRENT_UNDO, height))
    
    def read_freeze_history_undo_info(self, height):
        return self.asset_db.get(self.undo_key(PREFIX_FREEZE_HISTORY_UNDO, height))

    def flush_undo_infos(self, batch_put, prefix, undo_infos):
        '''undo_infos is a list of (undo_info, height) pairs.'''
        for undo_info, height in undo_infos:
            batch_put(self.undo_key(prefix, height), b''.join(undo_info))

    def clear_suid_undo_info(self, height: int, verbose=True):
        min_height = self.min_undo_height(self.state.height)
        keys = []
        for prefix in [PREFIX_ASSET_ID_UNDO,
                       PREFIX_H160_ID_UNDO]:
            for key, _hist in self.suid_db.iterator(prefix=prefix):
                height, = unpack_be_uint32(key[-4:])
                if height >= min_height:
                    break
                keys.append(key)

        if keys:
            with self.suid_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            if verbose:
                self.logger.info(f'deleted {len(keys):,d} stale sequential unique id undo entries')

    def clear_asset_undo_info(self, height: int, verbose=True):
        min_height = self.min_undo_height(self.state.height)
        keys = []
        for prefix in [PREFIX_METADATA_UNDO,
                       PREFIX_METADATA_HISTORY_UNDO,
                       PREFIX_BROADCAST_UNDO,
                       PREFIX_TAG_HISTORY_UNDO,
                       PREFIX_TAG_CURRENT_UNDO,
                       PREFIX_FREEZE_CURRENT_UNDO,
                       PREFIX_FREEZE_HISTORY_UNDO,
                       PREFIX_VERIFIER_CURRENT_UNDO,
                       PREFIX_VERIFIER_HISTORY_UNDO,
                       PREFIX_ASSOCIATION_CURRENT_UNDO,
                       PREFIX_ASSOCIATION_HISTORY_UNDO]:
            for key, _hist in self.asset_db.iterator(prefix=prefix):
                height, = unpack_be_uint32(key[-4:])
                if height >= min_height:
                    break
                keys.append(key)

        if keys:
            with self.asset_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            if verbose:
                self.logger.info(f'deleted {len(keys):,d} stale asset undo entries')

    def clear_excess_undo_info(self, verbose=True):
        '''Clear excess undo info.  Only most recent N are kept.'''
        min_height = self.min_undo_height(self.state.height)
        keys = []
        for key, _hist in self.utxo_db.iterator(prefix=PREFIX_UTXO_UNDO):
            height, = unpack_be_uint32(key[-4:])
            if height >= min_height:
                break
            keys.append(key)

        if keys:
            with self.utxo_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            if verbose:
                self.logger.info(f'deleted {len(keys):,d} stale undo entries')

        self.clear_asset_undo_info(min_height, verbose)
        self.clear_suid_undo_info(min_height, verbose)

    # -- UTXO database

    def read_utxo_state(self):

        def count_utxos():
            count = 0
            for db_key, db_value in self.utxo_db.iterator(prefix=PREFIX_HASHX_LOOKUP):
                count += 1
            return count

        now = time.time()
        state = self.utxo_db.get(b'state')
        if not state:
            state = ChainState(height=-1, tx_count=0, asset_count=0, h160_count=0, 
                    chain_size=0, tip=bytes(32),
                    flush_count=0, sync_time=0, flush_time=now,
                    first_sync=True, db_version=max(self.DB_VERSIONS),
                    utxo_count=0)
        else:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from DB')
            
            if state['genesis'] != self.coin.GENESIS_HASH:
                raise self.DBError(f'DB genesis hash {state["genesis"]} does not match '
                                   f'coin {self.coin.GENESIS_HASH}')

            state = ChainState(
                height=state['height'],
                tx_count=state['tx_count'],
                asset_count=state['asset_count'],
                h160_count=state['h160_count'],
                chain_size=state.get('chain_size', 0),
                tip=state['tip'],
                flush_count=state['utxo_flush_count'],
                sync_time=state['wall_time'],
                flush_time=now,
                first_sync=state['first_sync'],
                db_version=state['db_version'],
                utxo_count=state.get('utxo_count', -1)
            )

        self.state = state
        if state.db_version not in self.DB_VERSIONS:
            raise self.DBError(f'your UTXO DB version is {state.db_version} but this '
                               f'software only handles versions {self.DB_VERSIONS}')

        if self.state.utxo_count == -1:
            self.logger.info('counting UTXOs, please wait...')
            self.state.utxo_count = count_utxos()

        self.last_flush_state = state.copy()

        # These are as we flush data to disk ahead of DB state
        self.fs_height = state.height
        self.fs_tx_count = state.tx_count
        self.fs_asset_count = state.asset_count
        self.fs_h160_count = state.h160_count

        last_asset_id = pack_le_uint32(state.asset_count)
        assert self.suid_db.get(PREFIX_ID_TO_ASSET + last_asset_id) is None, 'asset id counter corrupted'
            
        last_h160_id = pack_le_uint32(state.h160_count)
        assert self.suid_db.get(PREFIX_ID_TO_H160 + last_h160_id) is None, 'h160 id counter corrupted'
            
        # Log some stats
        self.logger.info('UTXO DB version: {:d}'.format(state.db_version))
        self.logger.info('coin: {}'.format(self.coin.NAME))
        self.logger.info(f'height: {state.height:,d}')
        self.logger.info(f'tip: {hash_to_hex_str(state.tip)}')
        self.logger.info(f'tx count: {state.tx_count:,d}')
        self.logger.info(f'utxo count: {state.utxo_count:,d}')
        self.logger.info(f'chain size: {state.chain_size // 1_000_000_000} GB '
                         f'({state.chain_size:,d} bytes)')
        self.logger.info('VOUT debugging: {}'.format(self.env.write_bad_vouts_to_file))
        if self.utxo_db.for_sync:
            self.logger.info(f'flushing DB cache at {self.env.cache_MB:,d} MB')
        if self.state.first_sync:
            self.logger.info(f'sync time so far: {util.formatted_time(state.sync_time)}')

    def write_utxo_state(self, batch):
        '''Write (UTXO) state to the batch.'''
        state = {
            'genesis': self.coin.GENESIS_HASH,
            'height': self.state.height,
            'tx_count': self.state.tx_count,
            'asset_count': self.state.asset_count,
            'h160_count': self.state.h160_count,
            'chain_size': self.state.chain_size,
            'tip': self.state.tip,
            'utxo_flush_count': self.state.flush_count,
            'wall_time': self.state.sync_time,
            'first_sync': self.state.first_sync,
            'db_version': self.state.db_version,
            'utxo_count': self.state.utxo_count,
        }
        batch.put(b'state', repr(state).encode())

    def set_flush_count(self, count):
        self.state.flush_count = count
        self.write_utxo_state(self.utxo_db)

    def get_id_for_asset(self, asset: bytes) -> Optional[bytes]:
        return self.suid_db.get(PREFIX_ASSET_TO_ID + asset, None)
    
    def get_asset_for_id(self, id: bytes) -> Optional[bytes]:
        if id == NULL_U32: return None
        return self.suid_db.get(PREFIX_ID_TO_ASSET + id, None)

    def get_id_for_h160(self, h160: bytes) -> Optional[bytes]:
        return self.suid_db.get(PREFIX_H160_TO_ID + h160, None)
    
    def get_h160_for_id(self, id: bytes) -> Optional[bytes]:
        return self.suid_db.get(PREFIX_ID_TO_H160 + id, None)

    async def all_utxos(self, hashX, asset):
        '''Return all UTXOs for an address sorted in no particular order.'''

        if asset is False or asset is None:
            asset_ids = [NULL_U32]
        elif asset is True:
            asset_ids = [b'']
        elif isinstance(asset, str):
            asset_id = self.get_id_for_asset(asset.encode())
            if asset_id is None:
                return []
            asset_ids = [asset_id]
        else:
            asset_name_to_id = dict()
            for asset_name in asset:
                if asset_name is None:
                    asset_name_to_id[None] = NULL_U32
                    continue
                if asset_name in asset_name_to_id: continue
                idb = self.get_id_for_asset(asset_name.encode())
                if idb is None: continue
                asset_name_to_id[asset_name] = idb
            asset_ids = asset_name_to_id.values()

        def read_utxos():
            utxos = []
            utxos_append = utxos.append
            # Key: b'u' + address_hashX + asset_id + tx_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            for asset_id in asset_ids:
                prefix = PREFIX_HASHX_LOOKUP + hashX + asset_id
                for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                    value, = unpack_le_uint64(db_value)
                    if value > 0:
                        tx_pos, = unpack_le_uint32(db_key[-9:-5])
                        tx_num, = unpack_le_uint64(db_key[-5:] + bytes(3))
                        tx_hash, height = self.fs_tx_hash(tx_num)
                        asset_id = db_key[-13:-9]
                        asset_b = self.get_asset_for_id(asset_id)
                        asset_str = None if asset_b is None else asset_b.decode()
                        utxos_append(UTXO(tx_num, tx_pos, tx_hash, height, asset_str, value))
            return utxos

        while True:
            utxos = await run_in_thread(read_utxos)
            if all(utxo.tx_hash is not None for utxo in utxos):
                return utxos
            self.logger.warning('all_utxos: tx hash not found (reorg?), retrying...')
            await sleep(0.25)

    async def lookup_utxos(self, prevouts):
        '''For each prevout, lookup it up in the DB and return a (hashX, asset, value) pair or None if not found.

        Used by the mempool code.
        '''

        def lookup_hashXs():
            '''Return (hashX, suffix) pairs, or None if not found,
            for each prevout.
            '''
            def lookup_hashX(tx_hash, tx_idx):
                idx_packed = pack_le_uint32(tx_idx)

                # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
                # Value: hashX
                prefix = PREFIX_UTXO_HISTORY + tx_hash[:4] + idx_packed

                # Find which entry, if any, the TX_HASH matches.
                for db_key, db_val in self.utxo_db.iterator(prefix=prefix):
                    hashX = db_val[:HASHX_LEN]
                    asset_id = db_val[HASHX_LEN:]
                    tx_num_packed = db_key[-5:]
                    tx_num, = unpack_le_uint64(tx_num_packed + bytes(3))
                    fs_hash, _height = self.fs_tx_hash(tx_num)
                    if fs_hash == tx_hash:
                        return hashX, asset_id, idx_packed + tx_num_packed
                return None, None, None
            return [lookup_hashX(*prevout) for prevout in prevouts]

        def lookup_utxos(hashX_pairs):
            def lookup_utxo(hashX, asset_id, suffix):
                if not hashX:
                    # This can happen when the daemon is a block ahead
                    # of us and has mempool txs spending outputs from
                    # that new block
                    return None
                # Key: b'u' + address_hashX + tx_idx + tx_num
                # Value: the UTXO value as a 64-bit unsigned integer
                key = PREFIX_HASHX_LOOKUP + hashX + asset_id + suffix
                db_value = self.utxo_db.get(key)
                if not db_value:
                    # This can happen if the DB was updated between
                    # getting the hashXs and getting the UTXOs
                    return None
                value, = unpack_le_uint64(db_value)
                asset_b = self.get_asset_for_id(asset_id)
                asset_str = None if asset_b is None else asset_b.decode()
                return hashX, asset_str, value
            return [lookup_utxo(*hashX_pair) for hashX_pair in hashX_pairs]

        hashX_pairs = await run_in_thread(lookup_hashXs)
        return [i for i in await run_in_thread(lookup_utxos, hashX_pairs) if i]

    # For external use
    
    async def is_h160_qualified(self, h160: bytes, qualifier: bytes):
        def lookup_h160():
            h160_id = self.get_id_for_h160(h160)
            if h160_id is None:
                return {}
            qualifier_id = self.get_id_for_asset(qualifier)
            if qualifier_id is None:
                return {}
            current_lookup_key = PREFIX_H160_TAG_CURRENT + h160_id + qualifier_id
            latest_tag_id = self.asset_db.get(current_lookup_key, None)
            if latest_tag_id is None:
                return {}
            current_entry_key = PREFIX_H160_TAG_HISTORY + h160_id + latest_tag_id
            db_ret = self.asset_db.get(current_entry_key, None)
            assert db_ret
            assert db_ret[:4] == qualifier_id
            flag = db_ret[4]

            ret_val = {}
            tx_pos, = unpack_le_uint32(current_lookup_key[:4])
            tx_num, = unpack_le_uint64(current_lookup_key[4:9] + bytes(3))
            tx_hash, height = self.fs_tx_hash(tx_num)
            flag = db_ret[-1]
            ret_val['flag'] = True if flag != 0 else False
            ret_val['height'] = height
            ret_val['tx_hash'] = hash_to_hex_str(tx_hash)
            ret_val['tx_pos'] = tx_pos
            return ret_val
        return await run_in_thread(lookup_h160)

    async def qualifications_for_h160_history(self, h160: bytes):
        def lookup_quals_history():
            history_items = []
            h160_id = self.get_id_for_h160(h160)
            if h160_id is None:
                return []
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_H160_TAG_HISTORY + h160_id):
                idx_b = db_key[5:9]
                tx_num_b = db_key[9:14]
                asset_id = db_value[:4]
                flag = db_value[4]
                asset_b = self.get_asset_for_id(asset_id)
                assert asset_b

                tx_pos, = unpack_le_uint32(idx_b)
                tx_num, = unpack_le_uint64(tx_num_b + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)

                history_items.append({
                    'asset': asset_b.decode(),
                    'flag': True if flag != 0 else False,
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'tx_pos': tx_pos,
                    'height': height,
                })
            return sorted(history_items, key=lambda x: (x['height'], x['tx_hash']))
        return await run_in_thread(lookup_quals_history)

    async def qualifications_for_h160(self, h160: bytes):
        def lookup_quals():
            h160_id = self.get_id_for_h160(h160)
            if h160_id is None:
                return {}
            ret_val = {}
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_H160_TAG_CURRENT + h160_id):
                asset_id = db_key[-4:]
                asset_id_and_flag = self.asset_db.get(PREFIX_H160_TAG_HISTORY + h160_id + db_value, None)
                assert asset_id_and_flag
                assert asset_id == asset_id_and_flag[:4]
            
                tx_pos, = unpack_le_uint32(db_value[:4])
                tx_num, = unpack_le_uint64(db_value[4:9] + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)
            
                flag = asset_id_and_flag[4]
                
                asset_name = self.get_asset_for_id(asset_id)
                assert asset_name

                ret_val[asset_name.decode()] = {
                    'flag': True if flag != 0 else False,
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'tx_pos': tx_pos,
                    'height': height,
                }
            return ret_val
        return await run_in_thread(lookup_quals)

    async def qualifications_for_qualifier_history(self, asset: bytes):
        def lookup_quals_history():
            history_items = []
            asset_id = self.get_id_for_asset(asset)
            if asset_id is None:
                return []
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_ASSET_TAG_HISTORY + asset_id):
                idx_b = db_key[5:9]
                tx_num_b = db_key[9:14]
                h160_id = db_value[:4]
                flag = db_value[4]
                h160_b = self.get_h160_for_id(h160_id)
                assert h160_b

                tx_pos, = unpack_le_uint32(idx_b)
                tx_num, = unpack_le_uint64(tx_num_b + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)

                history_items.append({
                    'h160': h160_b.hex(),
                    'flag': True if flag != 0 else False,
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'tx_pos': tx_pos,
                    'height': height,
                })
            return sorted(history_items, key=lambda x: (x['height'], x['tx_hash']))
        return await run_in_thread(lookup_quals_history)

    async def qualifications_for_qualifier(self, asset: bytes):
        def lookup_quals():
            asset_id = self.get_id_for_asset(asset)
            if asset_id is None:
                return {}
            ret_val = {}
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_ASSET_TAG_CURRENT + asset_id):
                h160_id = db_key[-4:]
                h160_id_and_flag = self.asset_db.get(PREFIX_ASSET_TAG_HISTORY + asset_id + db_value, None)
                assert h160_id_and_flag
                assert h160_id == h160_id_and_flag[:4]
            
                tx_pos, = unpack_le_uint32(db_value[:4])
                tx_num, = unpack_le_uint64(db_value[4:9] + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)
            
                flag = h160_id_and_flag[4]
                
                h160_b = self.get_h160_for_id(h160_id)
                assert h160_b

                ret_val[h160_b.hex()] = {
                    'flag': True if flag != 0 else False,
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'tx_pos': tx_pos,
                    'height': height,
                }
            return ret_val
        return await run_in_thread(lookup_quals)

    async def restricted_frozen_history(self, asset: bytes):
        def lookup_restricted_history():
            history_items = []
            asset_id = self.get_id_for_asset(asset)
            if asset_id is None:
                return []
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_FREEZE_HISTORY+asset_id):
                idx_b = db_key[5:9]
                tx_num_b = db_key[9:14]

                tx_pos, = unpack_le_uint32(idx_b)
                tx_num, = unpack_le_uint64(tx_num_b + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)

                history_items.append({
                    'frozen': True if db_value[0] != 0 else False,
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'tx_pos': tx_pos,
                    'height': height,
                })
            return sorted(history_items, key=lambda x: (x['height'], x['tx_hash']))
        return await run_in_thread(lookup_restricted_history)

    async def is_restricted_frozen(self, asset: bytes):
        def lookup_restricted():
            asset_id = self.get_id_for_asset(asset)
            if asset_id is None:
                return {}
            current_lookup_key = PREFIX_FREEZE_CURRENT + asset_id
            latest_tag_id = self.asset_db.get(current_lookup_key, None)
            if latest_tag_id is None:
                return {}
            current_entry_key = PREFIX_FREEZE_HISTORY + asset_id + latest_tag_id
            db_ret = self.asset_db.get(current_entry_key, None)
            assert db_ret
            flag = db_ret[0]

            tx_pos, = unpack_le_uint32(latest_tag_id[:4])
            tx_num, = unpack_le_uint64(latest_tag_id[4:9] + bytes(3))
            tx_hash, height = self.fs_tx_hash(tx_num)
            flag = db_ret[-1]

            ret_val = {}
            ret_val['frozen'] = True if flag != 0 else False
            ret_val['height'] = height
            ret_val['tx_hash'] = hash_to_hex_str(tx_hash)
            ret_val['tx_pos'] = tx_pos
            return ret_val
        return await run_in_thread(lookup_restricted)

    async def get_restricted_string_history(self, asset: bytes):
        def lookup_restricted_history():
            history_items = []
            asset_id = self.get_id_for_asset(asset)
            if asset_id is None:
                return []
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_VERIFIER_HISTORY+asset_id):
                restricted_idx_b = db_key[5:9]
                qualifier_idx_b = db_key[9:13]
                tx_num_b = db_key[13:18]

                res_source_tx_pos, = unpack_le_uint32(restricted_idx_b)
                qual_source_tx_pos, = unpack_le_uint32(qualifier_idx_b)
                source_tx_num, = unpack_le_uint64(tx_num_b + bytes(3))
                source_tx_hash, source_height = self.fs_tx_hash(source_tx_num)
                history_items.append({
                    'string': db_value.decode(),
                    'tx_hash': hash_to_hex_str(source_tx_hash),
                    'restricted_tx_pos': res_source_tx_pos,
                    'qualifying_tx_pos': qual_source_tx_pos,
                    'height': source_height
                })
            return sorted(history_items, key=lambda x: (x['height'], x['tx_hash']))
        return await run_in_thread(lookup_restricted_history)


    async def get_restricted_string(self, asset: bytes):
        def lookup_restricted():
            asset_id = self.get_id_for_asset(asset)
            if asset_id is None:
                return {}
            current_lookup_key = PREFIX_VERIFIER_CURRENT + asset_id
            latest_tag_id = self.asset_db.get(current_lookup_key, None)
            if latest_tag_id is None:
                return {}
            current_entry_key = PREFIX_VERIFIER_HISTORY + asset_id + latest_tag_id
            db_ret = self.asset_db.get(current_entry_key, None)
            assert db_ret

            ret_val = {}
            restricted_tx_pos, = unpack_le_uint32(latest_tag_id[:4])
            qualifying_tx_pos, = unpack_le_uint32(latest_tag_id[4:8])
            tx_num, = unpack_le_uint64(latest_tag_id[8:13] + bytes(3))
            tx_hash, height = self.fs_tx_hash(tx_num)
            string = db_ret.decode()
            ret_val['string'] = string
            ret_val['height'] = height
            ret_val['tx_hash'] = hash_to_hex_str(tx_hash)
            ret_val['restricted_tx_pos'] = restricted_tx_pos
            ret_val['qualifying_tx_pos'] = qualifying_tx_pos
            return ret_val
        return await run_in_thread(lookup_restricted)

    async def lookup_qualifier_associations_history(self, asset: bytes):
        def lookup_associations_history():
            history_items = []
            qualifier_id = self.get_id_for_asset(asset)
            if qualifier_id is None:
                return []
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_ASSOCIATION_HISTORY+qualifier_id):
                res_asset_id = db_key[5:9]
                res_idx_b = db_key[9:13]
                qual_idx_b = db_key[13:17]
                tx_num_b = db_key[17:22]

                res_asset_b = self.get_asset_for_id(res_asset_id)
                assert res_asset_b

                restricted_tx_pos, = unpack_le_uint32(res_idx_b)
                qualifying_tx_pos, = unpack_le_uint32(qual_idx_b)
                tx_num, = unpack_le_uint64(tx_num_b + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)    

                history_items.append({
                    'asset': res_asset_b.decode(),
                    'associated': True if db_value[0] != 0 else False,
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'restricted_tx_pos': restricted_tx_pos,
                    'qualifying_tx_pos': qualifying_tx_pos,
                    'height': height,
                })
            return sorted(history_items, key=lambda x: (x['height'], x['tx_hash']))
        return await run_in_thread(lookup_associations_history)

    async def lookup_qualifier_associations(self, asset: bytes):
        def lookup_associations():
            qualifier_id = self.get_id_for_asset(asset)
            if qualifier_id is None:
                return {}

            ret_val = {}
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_ASSOCIATION_CURRENT + qualifier_id):
                restricted_asset_id = db_key[-4:]
                flag_b = self.asset_db.get(PREFIX_ASSOCIATION_HISTORY + qualifier_id + restricted_asset_id + db_value, None)
                assert flag_b
                flag = flag_b[0]
                
                restricted_tx_pos, = unpack_le_uint32(db_value[:4])
                qualifying_tx_pos, = unpack_le_uint32(db_value[4:8])
                tx_num, = unpack_le_uint64(db_value[8:13] + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)

                restricted_asset = self.get_asset_for_id(restricted_asset_id)
                assert restricted_asset
                
                asset_name = restricted_asset.decode()
                ret_val[asset_name] = {
                    'associated': True if flag != 0 else False,
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'restricted_tx_pos': restricted_tx_pos,
                    'qualifying_tx_pos': qualifying_tx_pos,
                    'height': height,
                }
            return ret_val
        return await run_in_thread(lookup_associations)

    async def lookup_messages(self, asset_name: bytes):
        def read_messages():
            asset_id = self.get_id_for_asset(asset_name)
            if asset_id is None:
                return []

            ret_val = []
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_BROADCAST + asset_id):
                tx_pos, = unpack_le_uint32(db_key[-9:-5])
                tx_num, = unpack_le_uint64(db_key[-5:] + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)
                hash = db_value[:34]
                expire = None
                if len(db_value) > 34:
                    expire, = unpack_le_uint64(db_value[34:])
                ret_val.append({
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'data': base_encode(hash, 58),
                    'expiration': expire,
                    'height': height,
                    'tx_pos': tx_pos,
                })
            return ret_val
        return await run_in_thread(read_messages)

    async def get_assets_with_prefix(self, prefix: bytes):
        def find_assets():
            return [asset.decode('ascii') for asset, _ in self.suid_db.iterator(prefix=PREFIX_ASSET_TO_ID+prefix)]
        return await run_in_thread(find_assets)

    async def lookup_asset_meta_history(self, asset_name: bytes):
        def read_asset_meta_history():
            history_items = []
            asset_id = self.get_id_for_asset(asset_name)
            if asset_id is None:
                return []
            for db_key, db_value in self.asset_db.iterator(prefix=PREFIX_METADATA_HISTORY+asset_id):
                value_parser = util.DataParser(db_value)
                idx_b = db_key[5:9]
                tx_num_b = db_key[9:14]
                sats_b = value_parser.read_bytes(8)
                divisions = value_parser.read_int()
                associated_data = None
                if not value_parser.is_finished():
                    associated_data = value_parser.read_bytes(34)    
                source_tx_pos, = unpack_le_uint32(idx_b)
                source_tx_num, = unpack_le_uint64(tx_num_b + bytes(3))
                sats, = unpack_le_uint64(sats_b)
                source_tx_hash, source_height = self.fs_tx_hash(source_tx_num)
                history_items.append({
                    'sats': sats,
                    'divisions': divisions,
                    'has_ipfs': True if associated_data else False,
                    'ipfs': base_encode(associated_data, 58) if associated_data else None,
                    'tx_hash': hash_to_hex_str(source_tx_hash),
                    'tx_pos': source_tx_pos,
                    'height': source_height
                })
            return sorted(history_items, key=lambda x: (x['height'], x['tx_hash']))
        
        return await run_in_thread(read_asset_meta_history)


    async def lookup_asset_meta(self, asset_name: bytes):
        def read_assets_meta():
            asset_id = self.get_id_for_asset(asset_name)
            if asset_id is None:
                return {}
            b = self.asset_db.get(PREFIX_METADATA+asset_id)
            if not b:
                return {}
            data_parser = util.DataParser(b)
            sats_in_circulation = data_parser.read_bytes(8)
            div_amt = data_parser.read_int()
            reissuable = data_parser.read_boolean()
            has_ipfs = data_parser.read_boolean()
            to_ret = {
                'sats_in_circulation': int.from_bytes(sats_in_circulation, 'little', signed=False),
                'divisions': div_amt,
                'reissuable': reissuable,
                'has_ipfs': has_ipfs
            }
            if has_ipfs:
                ipfs_data = data_parser.read_bytes(34)
                to_ret['ipfs'] = base_encode(ipfs_data, 58)

            source_idx = data_parser.read_bytes(4)
            source_tx_numb = data_parser.read_bytes(5)

            source_tx_pos, = unpack_le_uint32(source_idx)
            source_tx_num, = unpack_le_uint64(source_tx_numb + bytes(3))
            source_tx_hash, source_height = self.fs_tx_hash(source_tx_num)
            to_ret['source'] = {
                'tx_hash': hash_to_hex_str(source_tx_hash),
                'tx_pos': source_tx_pos,
                'height': source_height
            }

            while not data_parser.is_finished():
                outpoint_type = data_parser.read_int()
                idx = data_parser.read_bytes(4)
                tx_numb = data_parser.read_bytes(5)

                tx_pos, = unpack_le_uint32(idx)
                tx_num, = unpack_le_uint64(tx_numb + bytes(3))
                tx_hash, height = self.fs_tx_hash(tx_num)

                if outpoint_type == 0:
                    key = 'source_divisions'
                elif outpoint_type == 1:
                    key = 'source_ipfs'
                else:
                    key = 'unknown_outpoint'

                to_ret[key] = {
                    'tx_hash': hash_to_hex_str(tx_hash),
                    'tx_pos': tx_pos,
                    'height': height
                }

            return to_ret
        return await run_in_thread(read_assets_meta)
