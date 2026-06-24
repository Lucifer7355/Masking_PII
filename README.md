# PII Masking API

Small Go service I put together to mask Indian PII before data hits logs, support tickets, or non-prod environments. Handy when you're working around payment/KYC flows and don't want raw PAN or Aadhaar sitting in plaintext anywhere downstream.

Built this after running into the same masking logic copy-pasted across a few internal tools — figured a single HTTP service with predictable output formats would be easier to reuse.

## What it supports

| Type    | Input example        | Masked output        |
|---------|----------------------|----------------------|
| `pan`   | `ABCDE1234F`         | `ABXXX1234F`         |
| `aadhaar` | `1234-5678-9012`   | `XXXX-XXXX-9012`     |
| `phone` | `9876543210`         | `98*****210`         |
| `email` | `ankit@example.com`  | `a***@example.com`   |
| `gstin` | `22AAAAA0000A1Z5`    | `22AAA*****0A1Z5`     |

Validation runs before masking — bad input returns `400`, not a half-masked string.

## Run locally

```bash
git clone https://github.com/Lucifer7355/Masking_PII.git
cd Masking_PII
go run .
```

Server listens on `:8080`.

## API

### Health check

```bash
curl http://localhost:8080/health
```

### Mask a single value

```bash
curl -X POST http://localhost:8080/mask \
  -H "Content-Type: application/json" \
  -d '{"type":"pan","value":"ABCDE1234F"}'
```

Response:

```json
{"masked":"ABXXX1234F"}
```

### Bulk mask

```bash
curl -X POST http://localhost:8080/bulk \
  -H "Content-Type: application/json" \
  -d '[
    {"type":"phone","value":"9876543210"},
    {"type":"email","value":"ankit@example.com"}
  ]'
```

### Validate without masking

```bash
curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{"type":"pan","value":"ABCDE1234F"}'
```

### Auto-detect type

```bash
curl -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -d '{"value":"9876543210"}'
```

Returns `{"type":"phone"}` or `{}` if nothing matches.

## Docker

```bash
docker build -t pii-masker .
docker run -p 8080:8080 pii-masker
```

## Tests

```bash
go test ./...
```

## Notes

- Stateless — no DB, no Redis. Just drop it behind your API gateway or call it from a log scrubber.
- Regex-based validation. Good enough for format checks before masking; not a full KYC verifier.
- If you need card numbers or custom field types, the `ApplyMask` switch in `masking.go` is the place to extend.

## Author

Ankit Kumar Srivastava — [GitHub](https://github.com/Lucifer7355) · [Portfolio](https://lucifer7355.github.io)
