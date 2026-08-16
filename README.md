# 🛡️ Web Shield Check

A tiny, dependency-free web app that checks a public website for HTTPS and common browser security headers. It is intentionally easy to run, audit, contribute to, and self-host.

## Features

- Checks HTTPS, HSTS, CSP, MIME sniffing, referrer, permissions, and cross-origin opener policies
- Gives a simple score and readable recommendations
- Blocks private/local network targets to reduce SSRF risk
- Uses only Node.js built-ins—zero production dependencies
- Responsive browser interface

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/web-shield-check.git
cd web-shield-check
npm start
```

Open `http://localhost:3000`. Requires Node.js 20 or newer.

## Tests

```bash
npm test
```

## Responsible use

Only check systems you own or have explicit permission to test. This project performs a small HTTP request and evaluates response headers; it is not a vulnerability scanner or a substitute for a professional security assessment.

## Contributing and sponsorship

Issues, small improvements, new header rules, documentation, and accessibility fixes are welcome. If this tool saves you time, you can support its maintenance through the **Sponsor** button on GitHub once the maintainer adds a funding handle in `.github/FUNDING.yml`.

## License

[MIT](LICENSE)
