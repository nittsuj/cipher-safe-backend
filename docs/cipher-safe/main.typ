// Cipher Safe: Assignment Report I, Information Security (IUP), ITS.
// Two A4 pages maximum.

#let accent = rgb("#0f2787")
#let soft = rgb("#eef1fa")

#set document(title: "Cipher Safe: Assignment Report I")
#set page(paper: "a4", margin: (x: 1.8cm, top: 1.6cm, bottom: 1.6cm),
  footer: context [
    #set text(8pt, fill: luma(120))
    Cipher Safe · Information Security (IUP) #h(1fr) Page #counter(page).display() of 2
  ])
#set text(font: "New Computer Modern", size: 10pt, lang: "en")
#set par(justify: true, leading: 0.55em, spacing: 0.75em)
#set list(indent: 0.4em, spacing: 0.5em)

#set heading(numbering: "1.")
#show heading.where(level: 1): it => block(above: 1em, below: 0.5em, width: 100%)[
  #set text(11.5pt, weight: "bold", fill: accent)
  #counter(heading).display(it.numbering) #it.body
  #v(-0.6em)
  #line(length: 100%, stroke: 0.6pt + accent)
]
#show heading.where(level: 2): it => block(above: 0.8em, below: 0.4em,
  text(10pt, weight: "bold", it.body))

#set table(stroke: 0.4pt + luma(170), inset: (x: 5pt, y: 3.5pt),
  fill: (_, y) => if y == 0 { accent } else if calc.even(y) { soft })
#show table: set text(9pt)
#show table: set par(justify: false)
#show table.cell.where(y: 0): set text(fill: white, weight: "bold")
#show raw: set text(size: 8.5pt)
#set figure(gap: 0.4em)
#show figure: set block(above: 0.7em, below: 0.8em, breakable: true)
#show figure.where(kind: table): set figure.caption(position: top)
#show figure.caption: set text(8.5pt, style: "italic")

// ---------------------------------------------------------------- Header
#grid(columns: (auto, 1fr), column-gutter: 1em, align: (horizon, left + horizon),
  image("Images/its-logo.svg", height: 1.6cm),
  [
    #text(15pt, weight: "bold", fill: accent)[Cipher Safe: Patient-Held Medical Records Vault] \
    #text(10pt)[Assignment Report I · Information Security (IUP) · Institut Teknologi Sepuluh Nopember] \
    #text(9pt, fill: luma(80))[Lecturer: Baskoro Adi Pratomo, S.Kom., M.Kom., Ph.D. · October 2026]
  ],
)
#v(0.3em)
#block(fill: soft, inset: (x: 8pt, y: 5pt), radius: 3pt, width: 100%)[
  #set text(9pt)
  #grid(columns: (1fr, auto, 1.4em, 1fr, auto), row-gutter: 0.35em,
    [Justin Valentino], [5025241234], [], [Raymond Julius Pardosi], [5025241268],
    [Indra Wahyu Tirtayasa], [5025241108], [], [Denzel Daniels], [5025241228],
  )
]

// ---------------------------------------------------------------- 1
= Scenario
Indonesian patients are treated at Puskesmas, clinics and hospitals that do not
share records, so patients carry their own history: KTP and BPJS cards, lab
results, referral letters, a medication log, and ultrasound or endoscopy
recordings handed over on a disc. Most of it ends up unencrypted in a phone
gallery or a chat app.

*Cipher Safe* is a web vault where the patient (the only user role) stores this
history and opens it at the next appointment. Only the owner, signed in with a
username and password, can get a record back, and it must come back exactly as
stored: a silently altered allergy or lab value is a clinical risk, not only a
privacy one.

== Which data is private
Health data is _specific_ personal data under UU PDP No. 27/2022 Art. 4(2) and a
_special category_ under GDPR Art. 9(1). Identity fields are general data, but
we encrypt them as well because they link the health data to a real person.

#figure(
  table(columns: (2.6cm, 1fr, 2.6cm, 1.8cm), align: (left, left, left, center),
    [Item], [Content], [Category], [Encrypted],
    [Patient profile], [blood type, allergies, chronic conditions, medications], [Specific (health)], [Yes],
    [], [NIK, BPJS number, name, date of birth, address, phone, emergency contact], [General], [Yes],
    [Card scans], [KTP and BPJS card images], [General], [Yes],
    [Medical documents], [lab results, referral letters, medication logs (PDF / DOC / XLS)], [Specific (health)], [Yes],
    [Medical videos], [ultrasound, echocardiogram, endoscopy], [Specific (health)], [Yes],
    [File name and type], [e.g. "HIV-test.pdf" reveals health data by itself], [Specific (health)], [Yes],
    [File metadata], [category, size, upload date (needed to list records)], [General], [No],
  ),
  caption: [Data classification. Every encrypted item is stored three times: AES, DES and RC4.],
)

// ---------------------------------------------------------------- 2
= Design Decisions

#figure(
  table(columns: (2.3cm, 4.3cm, 1fr), align: left,
    [Decision], [Choice], [Justification],
    [Architecture], [Django REST API, PostgreSQL, Vue SPA; crypto in its own package],
      [The crypto package has no Django dependency, so it is unit-tested and benchmarked directly, and the benchmark runs the same code as the API. Encrypted files go to disk because each video is stored three times; the database keeps only salt, IV, tag and timings.],
    [Key handling], [PBKDF2-HMAC-SHA256, 600,000 rounds, new 16-byte salt per item],
      [No key is ever stored, so a stolen database or disk cannot be decrypted without the password. The iteration count follows OWASP's current advice. Trade-off: a forgotten password cannot be recovered.],
    [Mode (AES, DES)], [CTR for both; RC4 has no mode],
      [ECB leaks image structure in card scans. CTR needs no padding (each of the 3 copies is exactly the file size), is fast, and allows streaming video from any point. Using one mode for both makes the AES-vs-DES comparison about the cipher only. A fresh key per item means the counter never repeats.],
    [Integrity], [HMAC-SHA256 (encrypt-then-MAC) over algorithm, mode, salt, IV, ciphertext],
      [The ciphers alone cannot detect changes; in CTR and RC4 a flipped bit or wrong key silently gives wrong data. The tag is checked before decryption and a mismatch returns HTTP 409, so data comes back intact or not at all. The MAC key comes from the same PBKDF2 run, so it adds no extra derivation.],
    [Password transport], [Checked against the Django hash; sent in a header; kept in memory on the client],
      [A wrong password is rejected before any crypto runs. A URL would be written to server logs and browser history; memory-only storage keeps it off the patient's disk.],
    [Profile and file names], [Profile: one encrypted JSON record per cipher. File name and type: a separate encrypted label per cipher],
      [Saving the profile costs 3 PBKDF2 runs instead of 33 (11 fields × 3) and hides which fields are filled in. File names are encrypted because a name alone can reveal a diagnosis; listing records costs one key derivation per file.],
  ),
  caption: [Main design decisions and why they were made.],
)

// ---------------------------------------------------------------- 3
= Analysis

== What we measured and why
A patient waits at two moments: *opening* a record at the clinic (one
decryption) and *uploading* it (three encryptions). We therefore timed
decryption for one realistic size per data type, splitting each time into key
derivation (KDF), cipher and MAC. A single total would hide the cipher, because
key derivation costs the same for every algorithm.

== How
Each case was encrypted once and decrypted 10 times with `time.perf_counter`,
checking every run returned the original bytes (Intel laptop, Windows 11,
Python 3.12, PyCryptodome; raw data in `bench_results.json`). One slow first RC4
call on the 512 B record (29.7 ms) was a warm-up effect, so its minimum is shown.

#figure(
  table(columns: (auto, auto, 1fr, 1fr, 1fr, 1fr, 1fr), align: (left, left, right, right, right, right, right),
    [Data], [Cipher], [KDF (ms)], [Cipher (ms)], [MAC (ms)], [Total (ms)], [Cipher MB/s],
    [Profile (512 B)], [AES], [163], [0.11], [0.05], [163], [–],
    [], [DES], [159], [0.11], [0.04], [159], [–],
    [], [RC4], [162], [0.04], [0.04], [162], [–],
    [Lab PDF (4 MiB)], [AES], [171], [2.9], [5.6], [180], [1387],
    [], [DES], [194], [307], [6.3], [507], [13],
    [], [RC4], [203], [14.6], [7.2], [225], [274],
    [Video (32 MiB)], [AES], [197], [35.7], [54.1], [286], [895],
    [], [DES], [150], [1506], [38.0], [1694], [21],
    [], [RC4], [128], [99.2], [32.6], [260], [323],
  ),
  caption: [Mean decryption time over 10 runs; AES and DES in CTR mode.],
)

== What the results mean for the patient
- *AES opens every record in under 0.3 s*; anything smaller than a video takes
  about 0.17 s, almost all of it PBKDF2. The wait comes from key derivation, which
  is the cost of never storing keys, not from the cipher.
- *DES is the only cipher a patient would notice*: 1.7 s for the 32 MiB video
  versus 0.29 s for AES. It is 40–100× slower, most likely because AES uses the
  CPU's AES-NI instructions and DES runs in software. With a 56-bit key it is
  also the weakest of the three.
- *RC4 is slower than AES* on every real file (274–323 vs 895–1387 MB/s), so it
  has no speed advantage to offset its known weaknesses.
- *The integrity check is cheap but not free*: 54 ms on the video, slightly more
  than AES itself.
- *Uploading is where the three-cipher rule costs most*: a 32 MiB video takes
  about 2.6 s to encrypt three times (1.8 s of it DES) and uses 3× the storage.

#figure(
  table(columns: (auto, 1fr, 1fr, 1fr, 1fr), align: (left, right, right, right, right),
    [MB/s (4 MiB)], [CBC], [CFB], [OFB], [CTR],
    [AES], [547], [527], [551], [*1708*],
    [DES], [24], [23], [23], [23],
  ),
  caption: [Throughput per mode. CTR is about 3× faster for AES and no slower for DES, which supports choosing it.],
)
