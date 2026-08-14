# Proposal: a rich, paginated transaction-history RPC on our ElectrumX servers

- **Status:** proposed (2026-08-13)
- **Area:** the ElectrumX servers we run (`electrum-{us,eu,ca}.avn.network`) **and** the client
  (`src/services/wallet/WalletService.ts` sync, `src/services/core/ElectrumService.ts` transport).
- **Builds on:** the concurrent + cached sync (#45), newest-first ordering (#47), and the
  resilience work (#52 — fail-fast + retry against rate-limiting drops). This proposal removes the
  need for most of that machinery on our own servers by moving the work server-side.
- **Risk:** medium. Additive and feature-detected — the client keeps its standard trustless path as
  a fallback, so a bug in the new path (or a third-party server) never breaks history. The main
  costs are a maintained ElectrumX patch and a display-only trust boundary (below).

## Motivation

Reconstructing history on the client is inherently expensive because the standard Electrum protocol
hands back raw pieces and makes the client reassemble them. For one address with ~5,000
transactions the client does:

1. `blockchain.scripthash.get_history` → `[{ tx_hash, height }]` — just IDs.
2. per transaction → `blockchain.transaction.get` (verbose) — the full tx.
3. per **input** → fetch the *parent* transaction, because Avian tx inputs carry neither the sender
   address nor the input value; both come from the referenced prevout.
4. the client then classifies send vs receive, nets the amount to/from the address, and picks the
   counterparty.

That is `~5,000 + (inputs × 5,000)` round-trips over a single WebSocket that public ElectrumX nodes
**rate-limit per connection and drop under a burst**. We have already spent three PRs making this
survivable (concurrency cap, fail-fast on drop, retry-with-reconnect, newest-first so recent
activity shows first) — but it is still thousands of round-trips for something the server can answer
from its own index without a single network hop.

Since **we run the servers**, we can add one method that returns exactly what the wallet displays.

## Goals

- One request (per page) returns **display-ready, classified** history rows for an address:
  direction, net amount, counterparty, fee, height/time/confirmations.
- **Server-side pagination**, newest-first, so the initial screen is a single small call and older
  history loads on demand — the lazy-paging UX we scoped and shelved becomes trivial.
- **Feature-detected with a fallback**: the client uses the rich method when the server advertises
  it, and otherwise uses today's standard path unchanged. FlightDeck keeps working against any
  ElectrumX, including third-party servers a user might point it at.
- **No new trust dependency for spending.** History is display data; sends are still built and
  signed from `listunspent` UTXOs the client fetches and verifies itself.

## Non-goals

- Replacing the standard sync. It stays as the fallback and the trustless path.
- Changing how balances or UTXOs are fetched (`get_balance`, `listunspent` are untouched).
- Locking the client to our fork — detection + fallback is a hard requirement, not a nicety.

## Design

### 1. The method

A new RPC, namespaced so it can't collide with a future standard method — e.g.
`blockchain.scripthash.get_history_rich`:

**Request**

```
blockchain.scripthash.get_history_rich(scripthash, page=0, page_size=25, order="newest")
```

**Response**

```json
{
  "total": 5247,
  "page": 0,
  "page_size": 25,
  "txs": [
    {
      "txid": "…",
      "height": 0,
      "time": 1723500000,
      "type": "send",
      "amount": 500000000,
      "counterparty": "R…",
      "fee": 22600,
      "confirmations": 0
    }
  ]
}
```

Notes:

- `type` / `amount` / `counterparty` are relative to the queried address. `amount` is the **net**
  satoshis moving to (receive) or from (send) this address, matching how the client fills
  `TransactionData` today.
- `height <= 0` is mempool; the server sorts **mempool first, then descending block height** —
  identical to `sortHistoryNewestFirst` on the client, so ordering is consistent whichever path
  runs.
- `total` drives pagination in the UI without walking the whole history.
- `page_size` is capped server-side (e.g. ≤ 100) so one request can't ask the server to classify
  the entire history at once.

### 2. Feature detection + fallback

The client already calls `server.features` (`ElectrumService.getServerFeatures`). Our servers add a
capability flag there, e.g.:

```json
{ "…": "…", "avn_rich_history": 1 }
```

On connect the client reads it once and records whether the rich path is available for the current
server. `WalletService.processTransactionHistory` branches:

- **rich available** → call `get_history_rich` page by page, map each row straight to
  `TransactionData`, persist. No `transaction.get`, no parent fetches, no client classification.
- **not available** (third-party server, or the flag absent) → today's standard path, unchanged.

Because it is feature-detected, this ships inert and turns on only once the servers expose it — no
coordinated release needed.

### 3. Trust boundary (the important part)

Classifying server-side means the client trusts the server for the **displayed** direction, amount,
and counterparty. That is acceptable here, deliberately:

- **History is informational.** A wrong row can mislead the user; it cannot move coins.
- **Spending stays trustless.** Sends are constructed from `listunspent` UTXOs the client fetches
  and verifies when building and signing — never from the history rows.
- **The fallback is trustless.** Any server that doesn't advertise the flag (or if we ever distrust
  a result) uses the standard path, which derives everything from raw tx data.

Optional hardening if we want it later: have the rich row also carry the minimal raw fields
(`vin`/`vout` digests) for the client to spot-check a sample, or verify the newest N rows against a
standard `transaction.get`. Not required for v1.

### 4. Server side (ElectrumX patch outline)

ElectrumX already maintains the history index and has fast prevout access, so the method is mostly
assembling data it holds:

1. Look up the address history (the same source `get_history` uses), sorted newest-first, sliced to
   the requested page.
2. For each txid on the page, load the tx and resolve each input's prevout (address + value) from
   the index — the step the client currently pays N network hops for, done locally.
3. Classify against the queried scripthash (inputs from us ⇒ send; outputs to us with no inputs from
   us ⇒ receive), net the amount, pick the counterparty, compute the fee.
4. Return the page plus `total`.

Considerations to note in the patch:

- **Cost is centralised.** Per-request prevout resolution + classification is real CPU/IO. Page-size
  caps bound it; a short-lived per-(scripthash,page) cache blunts repeat calls (e.g. during
  scrolling). Worth a cache-invalidation-on-new-block note.
- **Maintenance.** It's a patch carried across ElectrumX releases. Keep it a small, self-contained
  handler so rebases are cheap.

### 5. What it lets us delete / simplify on the client

On our servers, the rich path makes most of the recent sync machinery unnecessary (it stays only for
the fallback): the per-tx and per-parent fetch loop, the prevout cache, the concurrency pool, and
the retry-on-drop wrapper all collapse into "fetch page, map rows, persist." It also delivers the
**true lazy-paging** load strategy (fetch only the page you view) that we scoped but deferred,
without the partial-local-history downside — because a page is cheap, backfilling the rest for
backup/search is also cheap.

## Rollout

1. Land the **client** feature-detection + rich path + fallback behind detection (inert until the
   servers advertise the flag). Ships safely on its own.
2. Patch **one** ElectrumX server, flip its flag, point a test build at it, verify parity with the
   standard path (same rows, same amounts, same order).
3. Roll the patch to the remaining servers.
4. Optionally add the spot-check verification and the lazy-paging UI once the path is proven.

## Open questions

- **Method namespace / flag name** — `blockchain.scripthash.get_history_rich` + `avn_rich_history`,
  or something else you prefer for the fork.
- **Page size default** — 25 for the first screen matches the earlier UX discussion; confirm the
  server cap (100?).
- **Counterparty for multi-party txs** — which address to surface when a tx touches several
  (largest non-self output? first?). The client uses a single `address`/`fromAddress` today; keep
  that convention.
- **Verification appetite** — ship v1 trusting the server for display, or include spot-check fields
  from the start?

## Testing

- **Client, fallback intact:** existing `transactionClassification.test.ts` continues to exercise
  the standard path (server without the flag).
- **Client, rich path:** stub a server that advertises the flag and returns fixed rich pages; assert
  the rows map to the same `TransactionData` the standard path produces for the same fixtures, and
  that pagination requests the right pages.
- **Parity check (manual/integration):** for a known heavy address, diff rich-path output against
  standard-path output — same set, amounts, directions, order.
