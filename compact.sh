#!/bin/sh

# configure electrumx
export COIN=Avian
export DB_DIRECTORY=/home/electrumx/.electrumx/db2/

# run electrumx
./electrumx_compact_history
