# Submission notes

The payload beside this file is the draft for the one unrepeatable POST to
`https://nearhackathon.com/api/applications`. It is held until Lydia says go.

- `requestId` was generated once and lives in the payload; reuse it verbatim
  on any retry (400 and 503 retry with the same id; 201 means saved; 409
  means the repository or email has already been used).
- `nearAddress` is blank: it must be Lydia's existing lowercase mainnet
  account, and nobody else can supply it.
- The `website` field is deliberately absent from the payload. Any non-empty
  value rejects the submission; absent is the safe shape.
- `tracks` is `open` alone. Nothing else in the track list honestly fits a
  passkey migration tool, and padding reads as padding.
- Before sending: the repository must be public, the demo post must be live,
  and the hosted demo must be up.
- The hosted demo's stable URL is `https://lideeyah.github.io/redirect/`. It
  forwards to the current tunnel and repoints itself whenever the tunnel
  address changes, so it is the address to put in the submission and the demo
  post. It stays up as long as the Mac running the launchd agent
  `com.lideeyah.thine-demo` is powered on.
