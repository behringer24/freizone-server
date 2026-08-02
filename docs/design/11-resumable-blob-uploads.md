# Design: Resumable/chunked blob uploads

Status: **planned** · Roadmap: [SRV-11](../ROADMAP.md)

Split out of SRV-07, which shipped without it. A blob upload is one shot
today: `POST /v1/blobs` streams the whole ciphertext in a single request,
verified against the `Blob-Digest` the client signed up front (PROTOCOL §3,
§10). That is fine for photos — they are capped at a few MiB after the
downscale — but a video is large enough that a dropped connection at 90%
means starting over, and mobile connections drop.

Needs a protocol addition, not just a server change: some way to open an
upload, send ranges, and commit it, while keeping SRV-07's two guarantees —
that the signature is verified *before* any bytes are written, so a forged
upload costs no disk, and that the stored bytes are exactly what was signed.
A per-range digest, or a session whose overall digest is stated at open time
and enforced at commit, are the obvious candidates. The abandoned-upload
sweep that already exists (hourly ticker) is what would reclaim a session
the client never commits.

Deliberately not started: it is only worth designing alongside video
(APP-04 phase 2), since the chunk size and resume semantics should be driven
by a real payload rather than guessed at.
