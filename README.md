# cf-worker-emailer

A cloudflare worker to handle website form

## Required Secrets

- TO_EMAIL
- FROM_EMAIL
- RESEND_API_KEY
- TURNSTILE_SECRET

## Required Vars

(see wrangler.toml)

- ALLOWED_ORIGIN = "/mydomain.tld"
- THANKYOU_URL = "/contact/thanks/"
- ERROR_URL = "/contact/error/"

## Process

- Receive POST
- Validate JSON
- Reject invalid requests
- Verify Turnstile
- Rate limit
- Honeypot check
- Send email
- Return success
