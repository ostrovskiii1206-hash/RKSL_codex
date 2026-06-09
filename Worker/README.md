# RKSL Cloudflare Worker gateway

Use the Worker as the public entrypoint:

- Loader key check: `POST https://api.yourdomain.com/verify-key`
- Site/key landing: `https://api.yourdomain.com/`
- LootLabs destination URL: `https://api.yourdomain.com/lootlabs-claim?click_id={click_id}&unique_id={unique_id}&ip={ip}&secret=YOUR_LOOTLABS_POSTBACK_SECRET`
- Linkvertise destination URL: `https://api.yourdomain.com/linkvertise-claim?script=NBTF_ACTIVE&hash={hash}`

The Worker chooses a Railway backend from `RKSL_BACKENDS`, signs every proxied request with HMAC headers, and adds `X-RKSL-Selected-Backend` to the response for loader diagnostics.

Backend env to enable strict Worker-only checks:

```env
WORKER_HMAC_SECRET=the-same-secret-as-worker
REQUIRE_WORKER_SIGNATURE=true
TRUST_PROXY_HEADERS=true
```
