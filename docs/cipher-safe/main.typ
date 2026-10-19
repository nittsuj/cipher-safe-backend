#import "@preview/latexlike-report:1.0.0": *
#show: latexlike-report.with(

 // ======== Cover ============
 //Use content [] or none, except in author.
  author: "Justin Valentino", // must be a string ("")
  title: [Assignment Report I],
  subtitle: [
    Baskoro Adi Pratomo, S.Kom., M.Kom., Ph.D.
  ],

  participants: [
    5025241234 \
    Indra Wahyu Tirtayasa \
    5025241108 \
    Raymond Julius Pardosi \
    5025241268 \
    Denzel Daniels \
    5025241228
  ], // In case of several authors (the name in author parameter will go first) Use content [] or none.

  affiliation: [Institut Teknologi Sepuluh Nopember],
  year: [2026],
  class: [INFORMATION SECURITY - IUP],
  other: none,
  //date: [#datetime.today().display()], // You could use #datetime.today().display() for the date.
  date: [2026-10-21],
  logo: block(width: 100%, align(center, image("Images/its-logo.svg", width: 45%))),
  //==========Theme ===============
  theme-color: rgb("#0f2787"),
  lang: "en",
   participants-supplement: "Author:", //Change it if you change the language


  //=========Font =================
  title-font: "New Computer Modern",
  font: "New Computer Modern",
  font-size : 13pt,
  font-weight: 400,
  //============ Math =============
  math-font: "New Computer Modern Math",
  math-weight: 400,
  math-ref-supplement: auto, //Use none for no supplement, auto for language based or any other function or string you like
  math-numbering: "(1.1)", // The numbering style you like

  // ---- Equate package ---
  // For more information, you can refer to equate documentation

  math-number-mode: "label", //Can be "label" or "line"
  math-sub-numbering: true,  // true or false
  //===========Page style===============
  pagebreak-section: true, //For pagebreak after adding a new level one heading (=)
  show-outline:true, //true or false
  page-paper:"a4",
  //-----chic header package----
  // customize the left/center/right header and left/center/right footer
  // you can add images, text, the number of the current page, etc, or put none if you don't want some part of the header or footer.
  //some usefull function: chic-page-number(), chic-heading-name()

  h-l : [#smallcaps[Assignment Report I]],
  h-r :[#image("Images/its-logo.svg",width: 14%)],
  h-c : none,
  f-l : [],
  f-r : [],
  f-c : chic-page-number(),
  //=======================================
  //For more customitation you can check the documentation. !! Enjoy :D !!
)

= Introduction

== Background

The General Data Protection Regulation (GDPR) and Indonesia's Undang-Undang
Pelindungan Data Pribadi (UU PDP No. 27/2022) both require that personal data be
protected by appropriate technical measures, and both name encryption as a
primary example of such a measure. A system that stores identity documents,
national identification numbers or scanned records in plaintext fails that
requirement regardless of how well its perimeter is defended: a single database
dump or a stolen disk image exposes everything at once.

This report documents *Cipher Safe*, a web application built for this
assignment. It stores a user's private data --- personally identifiable
information (PII), ID card images, PDF/DOC/XLS documents and video files ---
with every item encrypted using *AES*, *DES* and *RC4*. Access requires a
username and password, and every retrieval is timed so that the three
algorithms can be compared on identical data.

== Objectives

The system was built to satisfy the following requirements:

#enum(
  [Store private data of several kinds: PII fields, ID card images, office
   documents and video files.],
  [Encrypt every stored item with AES, DES and RC4.],
  [Use a non-ECB mode of operation for the block ciphers.],
  [Require username and password authentication before any data is accessible.],
  [Allow retrieval (decryption) of the stored data under a chosen algorithm.],
  [Download the data repeatedly, measure the running time of each retrieval,
   and compare the algorithms.],
)

== System overview

Cipher Safe is split into two deployable parts:

#table(
  columns: (auto, 1fr),
  align: (left + top, left + top),
  table.header([*Component*], [*Responsibility*]),
  [`cipher-safe-backend`],
  [Django 6 + Django REST Framework API. Owns authentication, the cipher
   implementations, the database schema and the timing measurements.
   PostgreSQL stores metadata and PII ciphertext; file ciphertext blobs are
   written under `media/`.],
  [`cipher-safe-frontend`],
  [Vue 3 + TypeScript single-page application. Provides sign-in, personal-data
   forms, file upload and download, and the analysis views. Holds no secrets
   on disk.],
)

The backend exposes a JSON API under `/api/`. Authenticated requests carry a
JWT bearer token; requests that need to encrypt or decrypt additionally carry
the user's password, which is the source of every encryption key.

== Data model

Each item of private data is stored *three times*, once per algorithm, so that
the same plaintext can be recovered through any of the three ciphers and the
three can be compared on exactly the same input.

#table(
  columns: (auto, 1fr),
  align: (left + top, left + top),
  table.header([*Model*], [*Purpose*]),
  [`User`],
  [Authentication credentials only. Django's password hasher stores a PBKDF2
   hash; no personal data is kept here.],
  [`PersonalData`],
  [Container owned one-to-one by a user; holds no plaintext itself.],
  [`EncryptedValue`],
  [One PII field encrypted under one algorithm. The ciphertext is stored inline
   in the database because the values are small.],
  [`StoredFile`],
  [Metadata for an uploaded file: category, original name, content type and
   plaintext size.],
  [`FileCiphertext`],
  [One encrypted copy of a `StoredFile`. The ciphertext is a blob on disk so
   that large video files do not bloat the database.],
  [`DownloadEvent`],
  [An audit row appended on every decryption, carrying the measured key
   derivation and cipher times. This table is the raw data for the analysis in
   @sec-analysis.],
)

`EncryptedValue` and `FileCiphertext` share an abstract parent,
`EncryptionEnvelope`, which carries the fields that any ciphertext needs ---
algorithm, mode, salt, IV and the two timing values --- together with the logic
to be populated from a cipher result and to be decrypted again. The two
subclasses differ only in *where* the ciphertext bytes live.

= Justification

This section explains why each cryptographic and architectural decision was
made, since the assignment is as much about justifying the choices as about
making the code run.

== Deriving keys from the password

A password cannot be used directly as a cipher key: AES-256 needs exactly 32
bytes, DES needs 8, and a password is an arbitrary-length string with low
entropy per character. Every operation therefore derives its key with
*PBKDF2-HMAC-SHA256* over a fresh random 16-byte salt:

```python
SALT_SIZE = 16
PBKDF2_ROUNDS = 600_000

def derive_key(password: str, salt: bytes, length: int) -> bytes:
    return PBKDF2(password, salt, dkLen=length,
                  count=PBKDF2_ROUNDS, hmac_hash_module=SHA256)
```

Three properties follow from this choice:

/ Cost: 600,000 iterations make an offline guessing attack against the password
  expensive, because each candidate password costs the attacker the same
  derivation work that it costs the server.
/ Uniqueness: a fresh salt per operation means the same password never produces
  the same key twice, so identical plaintexts never encrypt to identical
  ciphertexts --- not even across two users who happen to share a password.
/ Reuse: because the function is told the target length, one implementation
  serves all three algorithms.

The derived key is never stored, and neither is the password: it is verified
against the Django password hash before any cryptographic work begins, and
discarded when the request ends. The practical consequence is that a database
dump on its own is useless to an attacker, because the key material is not in
it.

== Choosing AES, DES and RC4

The three algorithms are required by the assignment, but they are not
equivalent and the system does not present them as if they were.

#table(
  columns: (auto, auto, auto, auto, 1fr),
  align: (left + top, left + top, left + top, left + top, left + top),
  table.header([*Algorithm*], [*Type*], [*Key*], [*Block / IV*], [*Status*]),
  [AES], [block], [32 B (AES-256)], [16 B],
  [Current standard; the algorithm a real deployment should use.],
  [DES], [block], [8 B (56 effective bits)], [8 B],
  [Legacy. The key space is small enough to brute-force with modern hardware;
   included only for comparison.],
  [RC4], [stream], [32 B], [none],
  [Legacy. Its keystream has documented statistical biases and it is prohibited
   in TLS; included only for comparison.],
)

AES-256 was chosen over AES-128 so that the key length matches the 32 bytes
derived for RC4. That keeps the key-derivation cost identical between the two
and isolates the measured difference to the cipher itself.

== Avoiding ECB

ECB mode encrypts identical plaintext blocks to identical ciphertext blocks.
Structure in the plaintext therefore survives into the ciphertext, which is
visible to the naked eye on bitmap images and is exactly the failure that the
assignment's non-ECB requirement guards against. The block ciphers consequently
support four non-ECB modes:

#table(
  columns: (auto, auto, auto, 1fr),
  align: (left + top, center + top, center + top, left + top),
  table.header([*Mode*], [*IV*], [*Padding*], [*Effect on the block cipher*]),
  [CBC], [yes], [yes], [Chains blocks; remains a block mode.],
  [CFB], [yes], [no], [Turns it into a self-synchronising stream cipher.],
  [OFB], [yes], [no], [Turns it into a synchronous stream cipher.],
  [CTR], [yes (as nonce)], [no], [Encrypts a counter; parallelisable.],
)

CBC is the default. The initialisation vector is freshly random for every
operation and stored alongside the ciphertext; it is not secret, but it must
never be reused with the same key. For CTR, PyCryptodome takes no `iv`
argument, so the random IV is supplied as the initial counter value.

RC4 appears in no row of that table on purpose: it is a stream cipher, so a
mode of operation does not apply to it, and it needs neither an IV nor padding.
The code reflects this by normalising RC4's mode to the empty string rather
than storing a mode that would be meaningless.

== Padding only where it is needed

Only CBC requires the plaintext length to be a multiple of the block size.
PKCS\#7 padding is therefore applied *for CBC alone*; CFB, OFB, CTR and RC4
operate on the exact plaintext length. Padding unconditionally would have
inflated every ciphertext and would have made the size comparison between modes
misleading. Note that PKCS\#7 always adds at least one byte, so an input whose
length is already a multiple of the block size gains a full extra block.

== What must be stored per ciphertext

To decrypt later, everything except the key is needed. Each envelope row
therefore persists:

#table(
  columns: (auto, 1fr),
  align: (left + top, left + top),
  table.header([*Field*], [*Why it is needed*]),
  [`algorithm`], [Selects the cipher on retrieval.],
  [`mode`], [CBC / CFB / OFB / CTR; blank for RC4.],
  [`salt`], [16 bytes; required to re-derive the same key from the password.],
  [`iv`], [16 bytes (AES) or 8 bytes (DES); null for RC4.],
  [`ciphertext`], [The encrypted bytes, inline or as a blob on disk.],
  [`key_derivation_ms`, `cipher_ms`], [The measurements used in @sec-analysis.],
)

== Authentication and password transport

Authentication uses a username and password pair, as required, and issues a
JWT access/refresh token pair on success. Access tokens live 15 minutes;
refresh tokens live one day, rotate on every use, and the superseded token is
blacklisted, so a captured refresh token cannot be replayed once the legitimate
client has used it. Logout blacklists the presented refresh token.

The encryption password must reach the server on every cryptographic request,
and the transport was chosen deliberately:

/ Header (`X-Cipher-Password`): the preferred channel.
/ Request body: accepted as a fallback for form submissions.
/ Query string: *rejected*. URLs are recorded in server access logs, browser
  history and `Referer` headers, so a password in the query string would be
  persisted in several places outside the application's control.

On the client the password and both tokens are held in memory only, in the
Pinia store; nothing is written to `localStorage` or `sessionStorage`. Reloading
the page therefore signs the user out. This is a deliberate trade of
convenience for the guarantee that the key-deriving secret never touches the
user's disk.

== Separating the cipher core from the framework

The cipher implementation lives in a `core/crypto/` package that imports no
Django code: `keys.py` for derivation, `algorithms.py` for the ciphers and
`constants.py` for the supported algorithm and mode sets. The Django models,
the service layer and the API views sit on top of it.

This separation was worth the extra package for two reasons. It makes the
primitives unit-testable in isolation, so the round-trip tests construct no
database rows at all; and it keeps the algorithm and mode sets in one place.
The model and serializer `choices` are derived from those constants, so adding
a mode is a one-line change in the cipher layer rather than an edit spread
across the schema.

== Known limitations

Stating these is part of an honest justification:

#enum(
  [*No authenticity.* All three ciphers provide confidentiality only. There is
   no MAC and no AEAD construction, so modification of a stored ciphertext is
   not detected: an attacker with write access to the database could flip bits
   and the system would return corrupted plaintext. A production design would
   use AES-GCM or encrypt-then-MAC.],
  [*DES and RC4 are not secure.* They are implemented for the required
   comparison, not as options a user should reasonably choose.],
  [*The password is a single point of failure.* Because keys derive from it and
   are never escrowed, a forgotten password means permanently unreadable data.
   There is no recovery path, by design.],
  [*Confidentiality depends on HTTPS.* The password is transmitted on crypto
   requests; over plain HTTP it would be exposed in transit.],
  [*Throttle counters are per-process.* The rate limits use Django's default
   in-memory cache, so a multi-worker deployment would need a shared backend
   such as Redis for the limits to apply globally.],
  [*CFB uses PyCryptodome's default segment size.* `_block_cipher` does not
   pass `segment_size`, so CFB operates on 8-bit segments rather than full
   blocks. This is correct but about ten times slower than CFB-128; see
   @sec-analysis for the measurement.],
)

= Analysis <sec-analysis>

== What is measured

Every encryption and decryption records two separate durations, measured with
`time.perf_counter()`:

/ `key_derivation_ms`: the PBKDF2 derivation of the key from the password.
/ `cipher_ms`: the cipher operation itself, including padding for CBC.

They are kept apart rather than summed because PBKDF2 at 600,000 iterations
costs the same for all three algorithms and is expected to dominate the total.
Reporting only a total would therefore show three nearly identical numbers and
hide the actual differences between AES, DES and RC4. The split makes the
comparison visible: `cipher_ms` is the algorithm-dependent term, while
`key_derivation_ms` is the constant overhead that the password-based design
imposes.

== How the measurements are collected

Three mechanisms feed the analysis, in increasing order of control:

#table(
  columns: (auto, 1fr),
  align: (left + top, left + top),
  table.header([*Source*], [*Description*]),
  [Encryption timings],
  [Recorded once per algorithm when an item is stored, on the `FileCiphertext`
   or `EncryptedValue` row itself.],
  [`DownloadEvent` rows],
  [Appended on every retrieval through
   `GET /api/files/{id}/download/?algorithm=…`. This is the "download the data
   several times and measure the running time" path, and it includes request
   handling and blob I/O.],
  [Benchmark endpoint],
  [`GET /api/files/{id}/benchmark/?algorithm=…&runs=N` performs $N$ decryptions
   server-side (up to 50) and returns every sample together with the minimum,
   maximum and mean. This isolates the decrypt path from HTTP overhead and so
   gives the cleanest comparison of the three algorithms.],
)

The aggregate endpoint `GET /api/analysis/timings/` groups both the encryption
rows and the successful download events by algorithm and returns the run count,
minimum, maximum and mean for each. That is the source of @tbl-results.

== Procedure

The figures reported here were obtained by driving `core/crypto` directly: for
each payload size and algorithm, one `encrypt` call followed by ten `decrypt`
calls, asserting on every iteration that the recovered plaintext equals the
input, so that no timing is reported for an operation that did not actually
round-trip. Because the cipher core imports no Django code, this needs neither
a database nor a running server.

To reproduce the same comparison end-to-end through the API instead, which
additionally includes request handling and blob I/O:

#enum(
  [Start PostgreSQL and the backend, then register a user and sign in.],
  [Upload one file per category under a chosen mode: an ID card image, a
   PDF/DOC/XLS document and a video file. Each upload stores three
   ciphertexts.],
  [For each file and each algorithm, call the benchmark endpoint with
   `runs=10`, and separately download the file several times so that
   `DownloadEvent` rows accumulate.],
  [Read `GET /api/analysis/timings/`, or open the Analysis view in the SPA.],
  [Repeat for the other modes of operation to reproduce @tbl-modes.],
)

Payloads were generated as a non-repeating byte sequence (`bytes(range(256))`
tiled to length) rather than a constant fill or random data, so that the input
is neither trivially compressible nor dependent on the system entropy source.

The harness used is kept beside this report as `bench_crypto.py`, and the raw
measurements it produced --- including the per-run samples summarised in
@tbl-results --- are in `bench_results.json`:

```bash
python docs/cipher-safe/bench_crypto.py . > docs/cipher-safe/bench_results.json
```

Because the ciphertext size differs per algorithm --- CBC pads, the stream
modes do not, and DES pads to an 8-byte rather than a 16-byte boundary --- the
ciphertext size is recorded alongside the timings, so that throughput can be
compared rather than raw duration alone.

== Results

The figures below were measured against the `core/crypto` package directly,
which is the same code path the benchmark endpoint exercises in its inner loop,
with HTTP handling and blob I/O excluded so that the cipher cost is not hidden
by request overhead. Each case decrypts one ciphertext ten times and reports
the mean.

#table(
  columns: (auto, 1fr),
  align: (left + top, left + top),
  table.header([*Parameter*], [*Value*]),
  [Host], [AMD64, AMD Family 23 Model 104 (Zen / Zen+ mobile)],
  [OS], [Windows 11 (10.0.26200)],
  [Runtime], [CPython 3.13.4, PyCryptodome 3.23.0],
  [Key derivation], [PBKDF2-HMAC-SHA256, 600,000 rounds],
  [Mode], [CBC (the default) for @tbl-results; all four modes in @tbl-modes],
  [Runs per case], [10 (3 for @tbl-modes)],
)

#figure(
  table(
    columns: (auto, auto, auto, auto, auto, auto, auto),
    align: (left + top, right + top, left + top, right + top, right + top, right + top, right + top),
    table.header(
      [*Payload*], [*Size*], [*Alg.*], [*KDF (ms)*], [*Cipher (ms)*],
      [*Total (ms)*], [*MB/s*],
    ),

    [PII field], [64 B], [AES], [392.37], [0.103], [392.47], [0.6],
    [], [], [DES], [377.23], [0.106], [377.34], [0.6],
    [], [], [RC4], [365.26], [0.055], [365.31], [1.1],

    [ID card], [512 KiB], [AES], [382.24], [1.613], [383.85], [310.0],
    [], [], [DES], [371.38], [7.748], [379.13], [64.5],
    [], [], [RC4], [365.21], [1.808], [367.02], [276.5],

    [Document], [4 MiB], [AES], [378.27], [12.788], [391.06], [312.8],
    [], [], [DES], [378.78], [61.985], [440.77], [64.5],
    [], [], [RC4], [383.85], [14.829], [398.68], [269.7],

    [Video], [32 MiB], [AES], [397.49], [102.136], [499.62], [313.3],
    [], [], [DES], [373.42], [479.705], [853.12], [66.7],
    [], [], [RC4], [366.25], [112.138], [478.39], [285.4],
  ),
  caption: [Mean decryption time per algorithm across the four data categories,
    CBC mode, 10 runs per case. Throughput is computed from the cipher term
    only.],
) <tbl-results>

Ciphertext expansion was as the design predicts: for a 32 MiB input, AES-CBC
produced 33,554,448 B (+16), DES-CBC produced 33,554,440 B (+8) and RC4
produced exactly 33,554,432 B (+0). The padding overhead is one block, and only
for CBC.

#figure(
  table(
    columns: (auto, auto, auto, auto, auto),
    align: (left + top, left + top, right + top, right + top, right + top),
    table.header(
      [*Alg.*], [*Mode*], [*Cipher (ms)*], [*MB/s*], [*Expansion (B)*],
    ),
    [AES], [CBC], [14.240], [280.9], [+16],
    [], [CFB], [119.909], [33.4], [0],
    [], [OFB], [12.510], [319.7], [0],
    [], [CTR], [3.773], [1060.2], [0],
    [DES], [CBC], [55.788], [71.7], [+8],
    [], [CFB], [431.489], [9.3], [0],
    [], [OFB], [59.219], [67.5], [0],
    [], [CTR], [52.208], [76.6], [0],
  ),
  caption: [Cipher time per mode of operation on a 4 MiB payload, 3 runs per
    case. The key-derivation term is identical across modes and is omitted.],
) <tbl-modes>

== Interpretation

Four of the measured results are worth drawing out, and two of them contradict
the intuitive prediction.

/ Key derivation dominates, as designed: PBKDF2 costs 365--397 ms regardless of
  algorithm or input size. For a 64-byte PII field the cipher accounts for
  roughly 0.03% of the total; even for a 32 MiB video under AES it is only
  about 20%. Timings taken on small inputs
  therefore measure PBKDF2, not the cipher, which is precisely why the two
  terms are recorded separately and why the video category matters for the
  comparison.
/ AES is roughly 4.7#sym.times faster than DES: 313 MB/s against 67 MB/s on the
  32 MiB payload. DES has the smaller key and block, so this is not a work
  argument but a hardware one: PyCryptodome dispatches AES to AES-NI
  instructions, while DES runs its S-box permutations in software. The
  measurement also holds at every size tested, with DES steady near 65 MB/s.
/ RC4 is *not* the fastest, contrary to expectation: at 280--285 MB/s it sits
  behind AES-CBC on the 32 MiB payload, and further behind AES in the faster
  modes. The margin is not stable --- across two full runs AES-CBC measured
  313 MB/s and 375 MB/s against RC4's 285 MB/s and 281 MB/s, so AES led by
  between 10% and 34% --- but the ordering AES #sym.gt RC4 #sym.gt DES held in
  both, and DES was reproducible to within 1%. RC4 only wins on the 64-byte
  field (0.055 ms against 0.103 ms),
  where the figure reflects fixed per-call setup rather than throughput --- RC4
  needs no IV generation and no padding. The intuition that a software stream
  cipher must beat a block cipher is simply obsolete once the block cipher has
  a dedicated instruction set. The conclusion is therefore stronger than
  "speed is not security": here the insecure algorithm is not even faster.
/ Mode of operation affects speed far more than size: the spread across modes
  (3.8#sym.times between AES-CTR and AES-CBC, and 32#sym.times between AES-CTR
  and AES-CFB) dwarfs the differences between the algorithms themselves. CTR is
  the fastest because it encrypts a counter block independently of the data,
  which both parallelises and pipelines well.

The AES-CFB figure of 33 MB/s deserves a caveat, because it is an artefact of
the implementation rather than a property of the mode. PyCryptodome's
`MODE_CFB` defaults to `segment_size=8`, meaning 8-*bit* segments: it enciphers
one byte per block-cipher invocation and discards fifteen sixteenths of each
keystream block. Passing `segment_size=128` for full-block CFB-128 was measured
at 11.19 ms (357 MB/s) for the same 4 MiB payload --- a 10.7#sym.times
improvement --- which puts CFB in line with OFB, as theory predicts. The
current code does not set `segment_size`, so the reported CFB numbers are the
cost of that default. This is the one concrete performance defect the analysis
uncovered.

Run-to-run variance in the key-derivation term was 22--29 ms of standard
deviation on a mean near 375 ms, roughly 6--8%, attributable to scheduling on a
non-isolated desktop. Cipher times varied more widely in relative terms on the
32 MiB payload (AES 86.6--163.0 ms), which is why the benchmark endpoint
returns every individual sample rather than a mean alone.

== Verification

Correctness is checked by the test suite rather than asserted:

```bash
python manage.py test core
```

It verifies that every algorithm and every mode round-trips for payloads
ranging from empty to multi-kilobyte, that an input whose length is an exact
multiple of the block size is handled, that a wrong password and an unknown
algorithm are rejected, and that an uploaded file downloads back byte-for-byte
identical under each of the three algorithms. The last of these is the
end-to-end guarantee that matters: the comparison in @tbl-results is only
meaningful if all three paths return the original data.

== Conclusion

The system meets the assignment's requirements. Private data of four categories
is stored encrypted under AES, DES and RC4; the block ciphers use non-ECB modes
of operation; access requires username and password authentication; data can be
retrieved under any chosen algorithm; and every retrieval is timed and recorded
so that the algorithms can be compared.

The measurements support a conclusion that the requirement list does not state
outright, and one that is stronger than the usual "security costs
performance" framing. In a password-based design the cipher is not the
bottleneck at all --- key derivation is, at 365--397 ms against 102 ms for
AES on a 32 MiB file --- so the cost of choosing the secure algorithm is
negligible in the first place. More pointedly, AES-256 was measured as the
*fastest* of the three --- roughly 4.7#sym.times ahead of DES, and ahead of
RC4 in every run --- because hardware AES instructions have overturned the old
assumption that a software stream cipher is cheaper than a block cipher.
Neither legacy algorithm
offers a performance argument for its continued use; their presence in
deployed systems is inertia.

Two findings point at follow-up work. First, the choice of mode of operation
matters more for throughput than the choice of algorithm, with a
32#sym.times spread across the AES modes, so a system of this kind should
select its mode deliberately rather than default to CBC. Second, the CFB
implementation inherits PyCryptodome's 8-bit `segment_size` default and is
about ten times slower than it needs to be; setting `segment_size=128` in
`_block_cipher` would fix it without changing the stored format. Beyond
performance, the clearest security improvement would be to add authenticity:
all three ciphers as used here provide confidentiality only, and an
authenticated mode such as AES-GCM would let the system detect tampering with
stored ciphertext rather than silently returning corrupted plaintext.

= References

#enum(
  [European Parliament and Council of the European Union, _Regulation (EU)
   2016/679 (General Data Protection Regulation)_, Art. 32: Security of
   processing, 2016.],
  [Republic of Indonesia, _Undang-Undang Nomor 27 Tahun 2022 tentang
   Pelindungan Data Pribadi_, 2022.],
  [National Institute of Standards and Technology, _FIPS PUB 197: Advanced
   Encryption Standard (AES)_, 2001.],
  [National Institute of Standards and Technology, _FIPS PUB 46-3: Data
   Encryption Standard (DES)_, 1999 (withdrawn 2005).],
  [M. Dworkin, _NIST SP 800-38A: Recommendation for Block Cipher Modes of
   Operation --- Methods and Techniques_, 2001.],
  [M. Sönmez Turan et al., _NIST SP 800-132: Recommendation for Password-Based
   Key Derivation, Part 1: Storage Applications_, 2010.],
  [A. Popov, _RFC 7465: Prohibiting RC4 Cipher Suites_, Internet Engineering
   Task Force, 2015.],
  [N. AlFardan, D. J. Bernstein, K. G. Paterson, B. Poettering and
   J. C. N. Schuldt, "On the Security of RC4 in TLS," in _Proc. 22nd USENIX
   Security Symposium_, 2013.],
  [OWASP Foundation, _Password Storage Cheat Sheet_, 2024.],
  [Legrandin et al., _PyCryptodome Documentation_, version 3.x.
   #link("https://pycryptodome.readthedocs.io/")],
  [`ukassu`, _lab-session-information-security_ (`crypto_tool.py`), GitHub.
   #link("https://github.com/ukassu/lab-session-information-security") ---
   the reference implementation this project's cipher core is adapted from.],
)
