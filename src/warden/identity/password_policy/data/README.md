# The built-in common-password list

`common-passwords.sha1.gz` is warden's built-in watch list of common
passwords (ruling PW12 of 10 November 2026). The seeded default password
policy checks it, and a refused password is told "This password is too
common".

## What the file holds

The SHA-1 digest of each password, as the 20 raw bytes, sorted in ascending
order with duplicates removed, concatenated, and compressed with gzip (header
time zero, so a rebuild is byte-for-byte identical). No password is stored in
plain text.

- Entries: 99,999 distinct digests (the source has 100,000 lines, one of them
  repeated).
- Uncompressed: 1,999,980 bytes, SHA-256
  `0a64e8f8d92d17ad510a2565ab2ca4d6a070da2486b3bb4ccd21afcafcaf9e0a`.
- Compressed (this file): 1,987,218 bytes, SHA-256
  `4000cf37f52ea34a75886b14f1b0e0050271582f489192f267ca065a19d56f29`.

## Source and provenance

- Project: SecLists by Daniel Miessler and contributors,
  <https://github.com/danielmiessler/SecLists>.
- Commit: `a1a06ab57c3f4efc450d80738a72c11597aac81a` (9 November 2026).
- File: `Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt`,
  781,879 bytes, SHA-256
  `1472aafa2561df5e3293aee252aee3ca660c12b399a283cf808bb01b39be388b`. These
  are the 100,000 most frequent passwords of Mark Burnett's ten million
  password dataset, published on xato.net in 2015. SecLists earlier carried
  the same list as `10-million-password-list-top-100000.txt`, removed as a
  duplicate in May 2025.

To rebuild: split the file on line feeds, drop a trailing carriage return
from each line, skip empty lines, take the SHA-1 of each line's bytes, then
sort, de-duplicate, concatenate and gzip with header time zero.

## Licence

SecLists is distributed under the MIT License, reproduced below. The licence
audit (`scripts/licence_audit.py`) names this file as a reviewed data
exception; its source was agreed in Skuld question 33 on 10 November 2026.

```
MIT License

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
