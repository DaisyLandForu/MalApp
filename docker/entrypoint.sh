#!/bin/sh
set -eu

data_dir="${MALAPP_DATA_DIR:-/var/lib/malapp}"
seed_dir="/opt/malapp-seed"

mkdir -p "$data_dir/eval"

for file in schema.json field_mapping.json sample_conflict.json; do
    if [ ! -f "$data_dir/$file" ]; then
        cp "$seed_dir/$file" "$data_dir/$file"
    fi
done

if [ ! -f "$data_dir/eval/best_params.json" ]; then
    cp "$seed_dir/eval/best_params.json" "$data_dir/eval/best_params.json"
fi

exec "$@"
