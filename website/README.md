# OmniRelay showcase

Public, static showcase for OmniRelay. It contains no Android or relay-backend source.

## Vercel

Create the Vercel project with **Root Directory** set to `website`. The checked-in
`vercel.json` then builds only this directory and publishes only `website/dist`.

The release buttons default to:

`https://github.com/0xmdrakib/OmniRelay/releases/latest`

Set `VITE_RELEASE_URL` in Vercel only if the public release location changes. A release in
a private GitHub repository is not accessible to public visitors, so the release repository
or release asset must be public before launch.

Set `VITE_PUBLIC_SITE_URL` to the final Vercel or custom HTTPS origin so Open Graph and X
preview images use the correct absolute URL. It defaults to `https://omnirelay.rakibhq.xyz`.
