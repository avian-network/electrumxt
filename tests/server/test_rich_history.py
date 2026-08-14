import pytest
from aiorpcx import RPCError

from electrumx.lib.coins import Avian
from electrumx.lib.hash import hash_to_hex_str, double_sha256
from electrumx.lib.script import OpCodes, ScriptPubKey
from electrumx.lib.tx import Tx, TxInput, TxOutput
from electrumx.lib.util import pack_le_uint32
from electrumx.server.rich_history import (MAX_PAGE_SIZE, Prevout, RichHistory,
                                           classify_tx, script_hashX_and_address,
                                           validate_page_args)

coin = Avian

OURS_H160 = bytes(range(20))
THEIRS_H160 = bytes(range(20, 40))
SEQUENCE = 4294967295


def p2pkh(hash160):
    return ScriptPubKey.P2PKH_script(hash160)


def hashX(script):
    return coin.hashX_from_script(script)


def address(script):
    return script_hashX_and_address(coin, script)[1]


OURS = p2pkh(OURS_H160)
THEIRS = p2pkh(THEIRS_H160)
OURS_HASHX = hashX(OURS)
OURS_ADDRESS = address(OURS)
THEIRS_ADDRESS = address(THEIRS)


def tx_of(inputs, outputs):
    '''Return a (tx, tx_hash, raw_tx) triple.'''
    tx = Tx(1, inputs, outputs, 0, None)
    raw_tx = tx.serialize()
    return tx, double_sha256(raw_tx), raw_tx


def spend(tx_hash, idx):
    return TxInput(tx_hash, idx, b'', SEQUENCE)


def generation():
    return TxInput(bytes(32), SEQUENCE, b'', SEQUENCE)


#
# Script parsing
#

def test_p2pkh_address():
    script_hashX, addr = script_hashX_and_address(coin, OURS)
    assert script_hashX == OURS_HASHX
    assert addr == OURS_ADDRESS
    assert coin.pay_to_address_script(addr) == OURS


def test_avian_addresses_are_r_prefixed():
    '''Avian's PUBKEY_ADDRESS prefix is 60, so counterparties read as R...'''
    assert OURS_ADDRESS.startswith('R')


def test_p2sh_address():
    script = ScriptPubKey.P2SH_script(THEIRS_H160)
    script_hashX, addr = script_hashX_and_address(coin, script)
    assert script_hashX == hashX(script)
    assert coin.pay_to_address_script(addr) == script


def test_p2wpkh_address():
    script = ScriptPubKey.P2WPKH_script(OURS_H160)
    script_hashX, addr = script_hashX_and_address(coin, script)
    assert script_hashX == hashX(script)
    assert addr.startswith(coin.SEGWIT_HRP + '1')
    assert coin.pay_to_address_script(addr) == script


def test_p2wsh_address():
    script = ScriptPubKey.P2WSH_script(bytes(range(32)))
    _script_hashX, addr = script_hashX_and_address(coin, script)
    assert coin.pay_to_address_script(addr) == script


def test_p2pk_address():
    pubkey = bytes([2]) + bytes(range(32))
    script = bytes([len(pubkey)]) + pubkey + bytes([OpCodes.OP_CHECKSIG])
    script_hashX, addr = script_hashX_and_address(coin, script)
    assert script_hashX == hashX(script)
    # A pubkey pays to the address of its hash160
    assert coin.pay_to_address_script(addr) != script
    assert addr is not None


def test_asset_payload_is_stripped():
    '''An asset output belongs to the address in front of its payload.'''
    payload = b'rvnt\x07AVIAN' + bytes(8)
    script = OURS + bytes([OpCodes.OP_RVN_ASSET, len(payload)]) + payload + b'\x75'
    script_hashX, addr = script_hashX_and_address(coin, script)
    assert script_hashX == OURS_HASHX
    assert addr == OURS_ADDRESS


def test_unparseable_script_hashes_as_is():
    script = bytes([OpCodes.OP_DUP, OpCodes.OP_HASH160, 20]) + bytes(3)
    script_hashX, addr = script_hashX_and_address(coin, script)
    assert script_hashX == hashX(script)
    assert addr is None


def test_nonstandard_script_has_no_address():
    script = bytes([OpCodes.OP_RETURN, 2, 0xff, 0xff])
    script_hashX, addr = script_hashX_and_address(coin, script)
    assert script_hashX == hashX(script)
    assert addr is None


#
# Classification
#

def test_classify_receive():
    parent_hash = bytes(range(32))
    tx, _tx_hash, _raw = tx_of([spend(parent_hash, 0)],
                               [TxOutput(1_000, OURS), TxOutput(4_000, THEIRS)])
    prevouts = {(parent_hash, 0): Prevout(hashX(THEIRS), 5_100, THEIRS_ADDRESS)}
    assert classify_tx(coin, OURS_HASHX, tx, prevouts) == \
        ('receive', 1_000, THEIRS_ADDRESS, 100, False)


def test_classify_send_nets_change_and_includes_fee():
    parent_hash = bytes(range(32))
    tx, _tx_hash, _raw = tx_of([spend(parent_hash, 0)],
                               [TxOutput(600, THEIRS), TxOutput(300, OURS)])
    prevouts = {(parent_hash, 0): Prevout(OURS_HASHX, 1_000, OURS_ADDRESS)}
    # 600 paid away plus the 100 fee left the address
    assert classify_tx(coin, OURS_HASHX, tx, prevouts) == \
        ('send', 700, THEIRS_ADDRESS, 100, False)


def test_classify_counterparty_is_the_largest_output():
    parent_hash = bytes(range(32))
    other = p2pkh(bytes(range(40, 60)))
    tx, _tx_hash, _raw = tx_of([spend(parent_hash, 0)],
                               [TxOutput(100, THEIRS), TxOutput(800, other)])
    prevouts = {(parent_hash, 0): Prevout(OURS_HASHX, 1_000, OURS_ADDRESS)}
    _kind, _amount, counterparty, _fee, _cb = classify_tx(coin, OURS_HASHX, tx, prevouts)
    assert counterparty == address(other)


def test_classify_self_send_costs_the_fee():
    parent_hash = bytes(range(32))
    tx, _tx_hash, _raw = tx_of([spend(parent_hash, 0)], [TxOutput(900, OURS)])
    prevouts = {(parent_hash, 0): Prevout(OURS_HASHX, 1_000, OURS_ADDRESS)}
    assert classify_tx(coin, OURS_HASHX, tx, prevouts) == \
        ('send', 100, OURS_ADDRESS, 100, False)


def test_classify_coinbase():
    tx, _tx_hash, _raw = tx_of([generation()], [TxOutput(5_000, OURS)])
    assert classify_tx(coin, OURS_HASHX, tx, {}) == ('receive', 5_000, None, 0, True)


def test_classify_coinbase_has_no_counterparty():
    '''A solo-mined block pays the miner and the dev fee; nobody sent either.'''
    dev_fee = ScriptPubKey.P2SH_script(bytes(range(60, 80)))
    tx, _tx_hash, _raw = tx_of([generation()],
                               [TxOutput(59_375_000_000, OURS),
                                TxOutput(3_125_000_000, dev_fee)])
    kind, amount, counterparty, fee, coinbase = classify_tx(coin, OURS_HASHX, tx, {})
    assert (kind, amount, fee) == ('receive', 59_375_000_000, 0)
    # The dev fee output is not a sender, so there is nobody to name
    assert counterparty is None
    assert coinbase is True


def test_classify_unresolved_parent_leaves_the_fee_unknown():
    parent_hash = bytes(range(32))
    tx, _tx_hash, _raw = tx_of([spend(parent_hash, 0), spend(parent_hash, 1)],
                               [TxOutput(1_000, OURS)])
    prevouts = {(parent_hash, 0): Prevout(hashX(THEIRS), 700, THEIRS_ADDRESS),
                (parent_hash, 1): None}
    kind, amount, counterparty, fee, _cb = classify_tx(coin, OURS_HASHX, tx, prevouts)
    assert (kind, amount, counterparty) == ('receive', 1_000, THEIRS_ADDRESS)
    assert fee is None


def test_classify_ignores_asset_payloads_in_the_amount():
    '''An asset transfer moves no AVN, so only the fee leaves the address.'''
    parent_hash = bytes(range(32))
    payload = b'rvnt\x07AVIAN' + bytes(8)
    asset_out = THEIRS + bytes([OpCodes.OP_RVN_ASSET, len(payload)]) + payload + b'\x75'
    tx, _tx_hash, _raw = tx_of([spend(parent_hash, 0)],
                               [TxOutput(0, asset_out), TxOutput(900, OURS)])
    prevouts = {(parent_hash, 0): Prevout(OURS_HASHX, 1_000, OURS_ADDRESS)}
    assert classify_tx(coin, OURS_HASHX, tx, prevouts) == \
        ('send', 100, THEIRS_ADDRESS, 100, False)


#
# Argument validation
#

def test_validate_page_args():
    assert validate_page_args(0, 25, 'newest') == (0, 25, 'newest')
    assert validate_page_args('3', '10', 'oldest') == (3, 10, 'oldest')
    for bad in ((-1, 25, 'newest'), (0, 0, 'newest'), (0, MAX_PAGE_SIZE + 1, 'newest'),
                (0, 25, 'sideways'), ('x', 25, 'newest')):
        with pytest.raises(RPCError):
            validate_page_args(*bad)


#
# A whole page, end to end
#

class FakeDaemon:
    def __init__(self, raw_txs):
        self.raw_txs = raw_txs
        self.calls = 0

    async def getrawtransactions(self, hex_hashes, replace_errs=True):
        self.calls += 1
        return [self.raw_txs.get(hex_hash) for hex_hash in hex_hashes]


class FakeDB:
    class State:
        height = 20

    state = State()

    async def raw_header(self, height):
        return bytes(68) + pack_le_uint32(1_700_000_000 + height) + bytes(8)


class FakeMemPool:
    def __init__(self, summaries):
        self.summaries = summaries

    async def transaction_summaries(self, hashX):
        return self.summaries


class FakeSummary:
    def __init__(self, tx_hash, fee):
        self.hash = tx_hash
        self.fee = fee
        self.has_unconfirmed_inputs = False


class FakeSessionManager:
    def __init__(self, history, daemon, mempool):
        self.env = type('env', (), {'coin': coin})()
        self.db = FakeDB()
        self.daemon = daemon
        self.mempool = mempool
        self.history = history

    async def limited_history(self, hashX):
        return self.history, 0.1


@pytest.fixture
def chain():
    '''A coinbase paying us, a spend of it, and a mempool spend of the change.'''
    coinbase, coinbase_hash, coinbase_raw = tx_of(
        [generation()], [TxOutput(1_000, OURS)])
    spend_tx, spend_hash, spend_raw = tx_of(
        [spend(coinbase_hash, 0)], [TxOutput(600, THEIRS), TxOutput(300, OURS)])
    mempool_tx, mempool_hash, mempool_raw = tx_of(
        [spend(spend_hash, 1)], [TxOutput(250, THEIRS)])

    raw_txs = {hash_to_hex_str(coinbase_hash): coinbase_raw,
               hash_to_hex_str(spend_hash): spend_raw,
               hash_to_hex_str(mempool_hash): mempool_raw}
    daemon = FakeDaemon(raw_txs)
    mempool = FakeMemPool([FakeSummary(mempool_hash, 50)])
    session_mgr = FakeSessionManager([(coinbase_hash, 10), (spend_hash, 11)],
                                     daemon, mempool)
    return RichHistory(session_mgr), daemon, (coinbase_hash, spend_hash, mempool_hash)


@pytest.mark.asyncio
async def test_page_is_newest_first(chain):
    rich_history, _daemon, (coinbase_hash, spend_hash, mempool_hash) = chain
    result, cost = await rich_history.history_page(OURS_HASHX, 0, 25, 'newest')

    assert cost > 0
    assert result['total'] == 3
    assert result['page'] == 0
    assert result['page_size'] == 25
    assert [row['txid'] for row in result['txs']] == \
        [hash_to_hex_str(mempool_hash), hash_to_hex_str(spend_hash),
         hash_to_hex_str(coinbase_hash)]


@pytest.mark.asyncio
async def test_page_rows_are_classified(chain):
    rich_history, _daemon, (coinbase_hash, spend_hash, mempool_hash) = chain
    result, _cost = await rich_history.history_page(OURS_HASHX, 0, 25, 'newest')
    mempool_row, spend_row, coinbase_row = result['txs']

    assert coinbase_row == {
        'txid': hash_to_hex_str(coinbase_hash),
        'height': 10,
        'time': 1_700_000_010,
        'type': 'receive',
        'coinbase': True,
        'amount': 1_000,
        'counterparty': None,
        'fee': 0,
        'confirmations': 11,
    }
    assert spend_row['coinbase'] is False
    assert spend_row['type'] == 'send'
    # 600 paid away plus the 100 fee
    assert spend_row['amount'] == 700
    assert spend_row['counterparty'] == THEIRS_ADDRESS
    assert spend_row['fee'] == 100
    assert spend_row['confirmations'] == 10

    assert mempool_row['height'] == 0
    assert mempool_row['confirmations'] == 0
    assert mempool_row['type'] == 'send'
    assert mempool_row['amount'] == 300
    assert mempool_row['fee'] == 50
    assert mempool_row['time'] is not None


@pytest.mark.asyncio
async def test_pagination_and_ordering(chain):
    rich_history, _daemon, (coinbase_hash, spend_hash, mempool_hash) = chain

    first, _cost = await rich_history.history_page(OURS_HASHX, 0, 2, 'newest')
    second, _cost = await rich_history.history_page(OURS_HASHX, 1, 2, 'newest')
    assert [row['txid'] for row in first['txs']] == \
        [hash_to_hex_str(mempool_hash), hash_to_hex_str(spend_hash)]
    assert [row['txid'] for row in second['txs']] == [hash_to_hex_str(coinbase_hash)]
    assert first['total'] == second['total'] == 3

    beyond, _cost = await rich_history.history_page(OURS_HASHX, 7, 2, 'newest')
    assert beyond['txs'] == []

    oldest, _cost = await rich_history.history_page(OURS_HASHX, 0, 25, 'oldest')
    assert [row['txid'] for row in oldest['txs']] == \
        [hash_to_hex_str(coinbase_hash), hash_to_hex_str(spend_hash),
         hash_to_hex_str(mempool_hash)]


@pytest.mark.asyncio
async def test_rows_are_cached(chain):
    rich_history, daemon, _hashes = chain
    first, first_cost = await rich_history.history_page(OURS_HASHX, 0, 25, 'newest')
    calls = daemon.calls
    second, second_cost = await rich_history.history_page(OURS_HASHX, 0, 25, 'newest')

    assert daemon.calls == calls, 'a cached page should not hit the daemon'
    assert second == first
    assert second_cost < first_cost


@pytest.mark.asyncio
async def test_confirmations_follow_the_chain(chain):
    rich_history, _daemon, _hashes = chain
    result, _cost = await rich_history.history_page(OURS_HASHX, 0, 25, 'newest')
    assert result['txs'][-1]['confirmations'] == 11

    rich_history.db.state.height = 30
    result, _cost = await rich_history.history_page(OURS_HASHX, 0, 25, 'newest')
    assert result['txs'][-1]['confirmations'] == 21


@pytest.mark.asyncio
async def test_missing_transaction_is_an_error(chain):
    rich_history, daemon, _hashes = chain
    daemon.raw_txs = {}
    with pytest.raises(RPCError) as e:
        await rich_history.history_page(OURS_HASHX, 0, 25, 'newest')
    assert 'txindex' in str(e.value)
