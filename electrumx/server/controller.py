# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.
from asyncio import Event

from aiorpcx import _version as aiorpcx_version, TaskGroup

import electrumx
import electrumx.server.block_processor as block_proc
from electrumx.lib.server_base import ServerBase
from electrumx.lib.util import version_string
from electrumx.server.daemon import Daemon
from electrumx.server.db import DB
from electrumx.server.mempool import MemPool, MemPoolAPI
from electrumx.server.session import SessionManager


class Notifications(object):
    # hashX notifications come from two sources: new blocks and
    # mempool refreshes.
    #
    # A user with a pending transaction is notified after the block it
    # gets in is processed.  Block processing can take an extended
    # time, and the prefetcher might poll the daemon after the mempool
    # code in any case.  In such cases the transaction will not be in
    # the mempool after the mempool refresh.  We want to avoid
    # notifying clients twice - for the mempool refresh and when the
    # block is done.  This object handles that logic by deferring
    # notifications appropriately.

    # pylint:disable=E0202

    def __init__(self):
        self._touched_bp = {}
        self._reissued_assets_bp = {}
        self._qualifier_touched_bp = {}
        self._h160_touched_bp = {}
        self._broadcast_touched_bp = {}
        self._frozen_touched_bp = {}
        self._validator_touched_bp = {}
        self._qualifier_association_touched_bp = {}
        
        self._touched_mp = {}
        self._reissued_assets_mp = {}
        self._qualifier_touched_mp = {}
        self._h160_touched_mp = {}
        self._broadcast_touched_mp = {}
        self._frozen_touched_mp = {}
        self._validator_touched_mp = {}
        self._qualifier_association_touched_mp = {}
        
        self._highest_block = -1

    async def _maybe_notify(self):
        tmp, tbp, tassetsmp, tassetsbp = self._touched_mp, self._touched_bp, self._reissued_assets_mp, self._reissued_assets_bp
        tqtbp, thtbp, tbtbp, tftbp, tvtbp, tqatbp = self._qualifier_touched_bp, self._h160_touched_bp, self._broadcast_touched_bp, self._frozen_touched_bp, self._validator_touched_bp, self._qualifier_association_touched_bp
        tqtmp, thtmp, tbtmp, tftmp, tvtmp, tqatmp = self._qualifier_touched_mp, self._h160_touched_mp, self._broadcast_touched_mp, self._frozen_touched_mp, self._validator_touched_mp, self._qualifier_association_touched_mp

        common = set(tmp).intersection(tbp)
        if common:
            height = max(common)
        elif tmp and max(tmp) == self._highest_block:
            height = self._highest_block
        else:
            # Either we are processing a block and waiting for it to
            # come in, or we have not yet had a mempool update for the
            # new block height
            return
        
        touched = tmp.pop(height, {})
        for old in [h for h in tmp if h <= height]:
            del tmp[old]
        for old in [h for h in tbp if h <= height]:
            touched.update(tbp.pop(old))

        touched_assets = tassetsmp.pop(height, {})
        for old in [h for h in tassetsmp if h <= height]:
            del tassetsmp[old]
        for old in [h for h in tassetsbp if h <= height]:
            touched_assets.update(tassetsbp.pop(old))

        touched_qualifiers_that_tagged = tqtmp.pop(height, {})
        for old in [h for h in tqtmp if h <= height]:
            del tqtmp[old]
        for old in [h for h in tqtbp if h <= height]:
            touched_qualifiers_that_tagged.update(tqtbp.pop(old))

        touched_h160s_that_were_tagged = thtmp.pop(height, {})
        for old in [h for h in thtmp if h <= height]:
            del thtmp[old]
        for old in [h for h in thtbp if h <= height]:
            touched_h160s_that_were_tagged.update(thtbp.pop(old))

        touched_assets_that_made_broadcasts = tbtmp.pop(height, {})
        for old in [h for h in tbtmp if h <= height]:
            del tbtmp[old]
        for old in [h for h in tbtbp if h <= height]:
            touched_assets_that_made_broadcasts.update(tbtbp.pop(old))

        touched_assets_that_were_frozen = tftmp.pop(height, {})
        for old in [h for h in tftmp if h <= height]:
            del tftmp[old]
        for old in [h for h in tftbp if h <= height]:
            touched_assets_that_were_frozen.update(tftbp.pop(old))

        touched_assets_that_validator_changed = tvtmp.pop(height, {})
        for old in [h for h in tvtmp if h <= height]:
            del tvtmp[old]
        for old in [h for h in tvtbp if h <= height]:
            touched_assets_that_validator_changed.update(tvtbp.pop(old))

        touched_qualifiers_that_are_in_validator = tqatmp.pop(height, {})
        for old in [h for h in tqatmp if h <= height]:
            del tqatmp[old]
        for old in [h for h in tqatbp if h <= height]:
            touched_qualifiers_that_are_in_validator.update(tqatbp.pop(old))

        await self.notify(height, touched, touched_assets, touched_qualifiers_that_tagged, touched_h160s_that_were_tagged,
                          touched_assets_that_made_broadcasts, touched_assets_that_were_frozen, touched_assets_that_validator_changed,
                          touched_qualifiers_that_are_in_validator)

    async def notify(self, height, touched, assets, q, h, b, f, v, qv):
        pass

    async def start(self, height, notify_func):
        self._highest_block = height
        self.notify = notify_func
        await self.notify(height, *(set() for _ in range(8)))

    async def on_mempool(self, touched, height, reissued,
                         tag_qualifiers_touched, tag_h160_touched, broadcasts_asset_touched,
                         freezes_asset_touched, verifier_string_asset_touched, restricted_qualifier_touched):
        self._touched_mp[height] = touched
        self._reissued_assets_mp[height] = reissued
        self._qualifier_touched_mp[height] = tag_qualifiers_touched
        self._h160_touched_mp[height] = tag_h160_touched
        self._broadcast_touched_mp[height] = broadcasts_asset_touched
        self._frozen_touched_mp[height] = freezes_asset_touched
        self._validator_touched_mp[height] = verifier_string_asset_touched
        self._qualifier_association_touched_mp[height] = restricted_qualifier_touched
        await self._maybe_notify()

    async def on_block(self, touched, height, reissued,
                       qualifier_touched, h160_touched, broadcast_touched,
                        frozen_touched, validator_touched, qualifier_association_touched):
        self._touched_bp[height] = touched
        self._reissued_assets_bp[height] = reissued
        self._qualifier_touched_bp[height] = qualifier_touched
        self._h160_touched_bp[height] = h160_touched
        self._broadcast_touched_bp[height] = broadcast_touched
        self._frozen_touched_bp[height] = frozen_touched
        self._validator_touched_bp[height] = frozen_touched
        self._validator_touched_bp[height] = validator_touched
        self._qualifier_association_touched_bp[height] = qualifier_association_touched
        self._highest_block = height
        await self._maybe_notify()

# pylint:disable=W0201


class Controller(ServerBase):
    '''Manages server initialisation and stutdown.

    Servers are started once the mempool is synced after the block
    processor first catches up with the daemon.
    '''
    async def serve(self, shutdown_event):
        '''Start the RPC server and wait for the mempool to synchronize.  Then
        start serving external clients.
        '''
        if not (0, 22) <= aiorpcx_version < (0, 23):
            raise RuntimeError('aiorpcX version 0.22.x is required')

        env = self.env
        min_str, max_str = env.coin.SESSIONCLS.protocol_min_max_strings()
        self.logger.info(f'software version: {electrumx.version}')
        self.logger.info(f'aiorpcX version: {version_string(aiorpcx_version)}')
        self.logger.info(f'supported protocol versions: {min_str}-{max_str}')
        self.logger.info(f'event loop policy: {env.loop_policy}')
        self.logger.info(f'reorg limit is {env.reorg_limit:,d} blocks')

        notifications = Notifications()
    
        async with Daemon(env.coin, env.daemon_url) as daemon:
            db = DB(env)
            bp = block_proc.BlockProcessor(env, db, daemon, notifications)

            # Set notifications up to implement the MemPoolAPI
            def get_db_height():
                return db.state.height
            notifications.height = daemon.height
            notifications.db_height = get_db_height
            notifications.cached_height = daemon.cached_height
            notifications.mempool_hashes = daemon.mempool_hashes
            notifications.raw_transactions = daemon.getrawtransactions
            notifications.lookup_utxos = db.lookup_utxos
            MemPoolAPI.register(Notifications)
            mempool = MemPool(env, notifications)

            session_mgr = SessionManager(env, db, bp, daemon, mempool,
                                         shutdown_event)

            # Test daemon authentication, and also ensure it has a cached
            # height.  Do this before entering the task group.
            await daemon.height()

            caught_up_event = Event()
            mempool_event = Event()

            async def wait_for_catchup():
                await caught_up_event.wait()
                await group.spawn(db.populate_header_merkle_cache())
                await group.spawn(mempool.keep_synchronized(mempool_event))

            async with TaskGroup() as group:
                await group.spawn(session_mgr.serve(notifications, mempool_event))
                await group.spawn(bp.fetch_and_process_blocks(caught_up_event, shutdown_event))
                await group.spawn(bp.check_cache_size_loop())
                await group.spawn(wait_for_catchup())

                async for task in group:
                    if not task.cancelled():
                        task.result()
