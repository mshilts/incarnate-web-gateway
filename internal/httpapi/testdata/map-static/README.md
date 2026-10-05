# `map_static` forwarding fixtures

These newline-delimited JSON frames were captured from the local Java
`Game.loadAll()` map exporter at Incarnate source commit
`3d3ac3d8f38f66a00e9c7899f71c6fc6f526872b`. They contain static map cells only;
the frames have no account, credential, entity, or player-view data. The map
cells retain the exporter fields `x`, `y`, `tile`, `blocking`, `tags`, and
`ambientLight`.

The tests embed the gzip files, decompress each capture, and compare the full
frame forwarded by the gateway byte-for-byte. The recorded uncompressed byte
counts include the final JSONL newline; the WebSocket message omits that line
delimiter.

| Capture | Map dimensions | Uncompressed bytes | JSONL SHA-256 | Gzip bytes | Gzip SHA-256 |
| --- | ---: | ---: | --- | ---: | --- |
| `maze-map_static.jsonl.gz` | 208 × 164 | 3,398,219 | `227023cb5e961afd0d6e793dd281388776151188663671a14898a5c4de76a299` | 163,613 | `d96113a87221c52bc6aedd4fbd49141803a88703afc0344b81033dccd93e0a2d` |
| `dungeon-map_static.jsonl.gz` | 200 × 200 | 3,785,680 | `287f296be049bfd15394fb4d1df756ef51470f69b822cb2bedfeb2eeffe08cb1` | 192,319 | `d47a93f40a143fa99b52f9a069a7fff6eca90ec86166e30a221c7ecd533e7c51` |
