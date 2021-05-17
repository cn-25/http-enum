# http-enum
This is a blue-team tool for use specifically only for domains that you administer.
This script will bulk-enumerate all hosts specified in "hosts.txt", scanning the HTTP headers to enumerate information such as:
- security headers:
  - Content-Security Policy, Referrer policy, X-Frame options, X-XSS protection, Strict-Transport-Security, X-Content-Type Options, etc.
- HTTP Headers:
  - Server, X-Powered-By, etc. to determine what web server or frameworks are in use
- WAF
  - Cloudflare, etc.
- Which cloud provider is used
- Are legacy protocols active (SSLv2/3, & TLSv1.0/1.1)
