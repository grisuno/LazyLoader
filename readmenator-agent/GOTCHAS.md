# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `main.c` (score: 3.40)
- `aes.py` (score: 0.20)
- `app.py` (score: 0.00)
- `install.sh` (score: 0.00)

## Hotspots (complexity + centrality)

- `main.c` -- complexity: 1.0, centrality: 1.0, combined: 1.0
- `aes.py` -- complexity: 0.1, centrality: 0.6, combined: 0.4
- `app.py` -- complexity: 0.0, centrality: 0.1, combined: 0.1
- `install.sh` -- complexity: 0.0, centrality: 0.0, combined: 0.0

## Dataflow Issues (INFERRED, review each lead)

- `aes.py:25` `dropFile` [UNCHECKED_ALLOC] `file`: Result of allocator stored in `file` is never checked against NULL.
- `main.c:681` `main` [UNCHECKED_ALLOC] `whost`: Result of allocator stored in `whost` is never checked against NULL.
- `main.c:685` `main` [UNCHECKED_ALLOC] `wpe`: Result of allocator stored in `wpe` is never checked against NULL.
- `main.c:689` `main` [UNCHECKED_ALLOC] `wkey`: Result of allocator stored in `wkey` is never checked against NULL.
