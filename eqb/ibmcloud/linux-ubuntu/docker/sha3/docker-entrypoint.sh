#!/bin/sh
set -e

if [ $(echo "$1" | cut -c1) = "-" ]; then
  echo "$0: assuming arguments for equibitd"

  set -- equibitd "$@"
fi

if [ $(echo "$1" | cut -c1) = "-" ] || [ "$1" = "equibitd" ]; then
  mkdir -p "$EQUIBIT_DATA"
  chmod 700 "$EQUIBIT_DATA"
  chown -R equibit "$EQUIBIT_DATA"

  echo "$0: setting data directory to $EQUIBIT_DATA"

  set -- "$@" -datadir="$EQUIBIT_DATA"
fi

if [ "$1" = "equibitd" ] || [ "$1" = "equibit-cli" ] || [ "$1" = "equibit-tx" ]; then
  echo
  exec gosu equibit "$@"
fi

echo
exec "$@"
