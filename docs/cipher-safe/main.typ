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
stored. If an allergy or a lab value were changed without anyone noticing, a
doctor could act on wrong information.

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
      [The ciphers alone cannot detect changes; in CTR and RC4 a flipped bit or wrong key silently gives wrong data. The tag is checked before decryption. If it does not match, the API returns HTTP 409 and no data. The MAC key comes from the same PBKDF2 run, so it adds no extra derivation.],
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
A patient waits at two moments: *uploading* a record (the app encrypts it three
times, once per cipher) and *opening* it at the clinic (one decryption). We timed
both, for one realistic size per data type, and split each time into key
derivation (KDF), cipher and MAC. A single total would hide the cipher, because
key derivation does the same work for every algorithm.

== How we made the numbers reliable
Each case ran one untimed warm-up round, then 15 timed rounds. Every round
encrypted and decrypted with all three ciphers in a rotating order (AES→DES→RC4,
then DES→RC4→AES, …), so slow drift on the laptop is shared fairly, and every
decryption was checked to return the original bytes. We report the *median* with
the min–max range, because a single slow run pulls the mean but not the median
(Intel laptop, Windows 11, Python 3.12, PyCryptodome; all samples in
`bench_results.json`). The KDF also shows how noisy the machine is: it is identical work
every time, yet it varied from 117 to 176 ms. We therefore treat differences
smaller than about 25 ms as noise.

#figure(
  table(columns: (auto, auto, 1fr, 1fr, 1fr, 1.6fr, 1fr), align: (left, left, right, right, right, right, right),
    [Data], [Cipher], [KDF], [Cipher], [MAC], [Open (range)], [Cipher MB/s],
    [Profile (512 B)], [AES], [139], [0.11], [0.05], [139 (122–176)], [–],
    [], [DES], [141], [0.13], [0.05], [142 (117–172)], [–],
    [], [RC4], [143], [0.04], [0.05], [143 (119–175)], [–],
    [Lab PDF (4 MiB)], [AES], [126], [2.0], [4.0], [134 (124–152)], [1960],
    [], [DES], [128], [183], [4.1], [317 (284–354)], [22],
    [], [RC4], [130], [11.8], [4.0], [146 (133–165)], [339],
    [Video (32 MiB)], [AES], [126], [15.9], [32.1], [176 (162–219)], [2018],
    [], [DES], [124], [1430], [30.8], [1584 (1465–1648)], [22],
    [], [RC4], [125], [97.1], [30.6], [254 (239–294)], [329],
  ),
  caption: [Time to open (decrypt) one copy, in ms: median of 15 runs, range in brackets. AES and DES use CTR.],
)

#figure(
  table(columns: (auto, 1fr, 1fr, 1fr, 1fr), align: (left, right, right, right, right),
    [Upload (ms)], [AES], [DES], [RC4], [All three],
    [Profile (512 B)], [150], [148], [149], [448],
    [KTP scan (512 KiB)], [131], [162], [133], [426],
    [Lab PDF (4 MiB)], [134], [332], [140], [606],
    [Video (32 MiB)], [181], [1617], [254], [2051],
  ),
  caption: [Time to encrypt one item with each cipher (median of 15 runs). An upload does all three.],
)

== What the results mean for the patient
- With AES, every record opens in under 0.2 s. Almost all of that time is PBKDF2
  key derivation, which we accept because keys are never stored. For small items
  (profile, card scans) the three ciphers take the same time within the noise.
- DES makes a visible difference only for large files. Opening the 32 MiB video
  takes 1.6 s with DES and 0.18 s with AES. DES reaches 22 MB/s against about
  2,000 MB/s for AES, roughly 90 times slower. The likely reason is that AES uses
  the CPU's AES-NI instructions and DES runs in software. DES also has the
  shortest key (56 bits).
- RC4 was slower than AES for every real file (about 330 against 1,400–2,000
  MB/s), so using it does not save time either.
- The HMAC check took 32 ms on the video, twice the AES cipher time (16 ms). In
  total it adds about 0.03 s to opening the video.
- Uploading the video takes about 2.1 s, of which 1.6 s is the DES copy. Each
  item also takes three times the storage space, because it is stored once per
  cipher.
- Listing records decrypts the name of each file, which takes one key derivation
  (about 0.14 s, see the profile row) per file.

#figure(
  table(columns: (auto, 1fr, 1fr, 1fr, 1fr), align: (left, right, right, right, right),
    [MB/s (4 MiB)], [CBC], [CFB], [OFB], [CTR],
    [AES], [611], [565], [544], [*1933*],
    [DES], [22], [23], [22], [24],
  ),
  caption: [Cipher throughput per mode (median of 5 runs). CTR is about 3× faster for AES and no slower for DES, which supports choosing it.],
)

= References
#image("Images/scenario.png")

= Links
+ https://github.com/nittsuj/cipher-safe-backend
+ https://github.com/nittsuj/cipher-safe-frontend