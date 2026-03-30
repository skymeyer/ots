# One-Time Secret Sharing

A secure, lightweight, and modern One-Time Secret sharing application. It enables users to securely transmit sensitive information via self-destructing links. 

Built with a fast **Go (Golang)** backend and a zero-dependency **Vanilla Javascript** frontend (SPA) featuring a sleek, responsive dark-mode glassmorphism UI.

## Features

- **End-to-End Security**: Envelope encryption powered by **Google Cloud KMS**.
- **Ephemeral Storage**: Secrets are physically stored in **Google Cloud Storage (GCS)** and are permanently deleted ("burned") immediately upon the first view.
- **Identity & Access Management**: Fully integrated **Google OAuth2** (with strict CSRF & PKCE protection) to gate access for secret creation.
- **Access Controls**: Authorize specific domains or specific email addresses via static lists or dynamic feature flagging.
- **DDoS Mitigation**: Native IP-based token-bucket rate limiting to protect unauthenticated endpoints.
- **Malicious IP Blocking**: Aggressively block bad actors globally via explicit IPs or CIDR boundaries.
- **Dynamic Configuration**: Hot-reloadable feature flags integrated via `go-feature-flag` utilizing a GCS state file.
- **Analytics & SEO**: User-consented Google Analytics insertion and well-defined scraping boundaries via `robots.txt`.

## Getting Started

The application is built to run cleanly in cloud-native environments (such as Kubernetes or Google Cloud Run) but can be easily executed locally for debugging.

### Prerequisites
- Go 1.21+
- A Google Cloud Platform (GCP) project with the following configured:
  - Cloud Storage Bucket
  - Cloud KMS Key Ring & Crypto Key
  - Secret Manager (for DEK storage)
  - Google OAuth2 Client ID/Secret

### Compilation
```bash
go build -o server
./server [flags]
```

## Configuration

The application natively supports executing configuration through either explicit Command Line Flags, or identically prefixed environmentally sourced variables (`OTS_`). If both are present, CLI flags natively take precedence.

| Environment Variable | CLI Flag | Default | Description |
|----------------------|----------|---------|-------------|
| `OTS_DEV` | `--dev` | `false` | Enable dev mode for human-readable logging formatting |
| `OTS_LOG_LEVEL` | `--log-level` | `info` | Filter log outputs (`debug`, `info`, `warn`, `error`, `fatal`) |
| `OTS_PORT` | `--port` | `8080` | Port for the HTTP server to listen on |
| `OTS_PUBLIC_URL` | `--public-url` | `http://localhost:8080` | The public facing root URL. Heavily relied upon for OAuth Callbacks and UI Links |
| `OTS_SESSION_SECRET` | `--session-secret` | *Dynamic* | Secret cryptographic key applied for MAC signing OAuth cookies. Automatically injects a random sequence if left blank in `--dev`. |

### Google Cloud Infrastructure
| Environment Variable | CLI Flag | Description |
|----------------------|----------|-------------|
| `OTS_PROJECT_ID` | `--project-id` | Your globally unique Google Cloud Project ID |
| `OTS_KMS_LOCATION` | `--kms-location` | Your Google Cloud KMS physical location (e.g. `global`) |
| `OTS_KMS_KEY_RING` | `--kms-key-ring` | The KMS Key Ring identifier hosting your key |
| `OTS_KMS_KEY` | `--kms-key` | The specific KMS Key identifier encrypting the DEK |
| `OTS_DEK_SECRET` | `--dek-secret` | Name of the payload registered in GCP Secret Manager holding your primary Data Encryption Key |
| `OTS_BUCKET` | `--bucket` | Name of the GCS bucket reserved for encrypting payload objects |

### Authentication & Authorization (OAuth2)
| Environment Variable | CLI Flag | Description |
|----------------------|----------|-------------|
| `OTS_GOOGLE_CLIENT_ID` | `--google-client-id` | Your issued Google OAuth2 Application Client ID |
| `OTS_GOOGLE_CLIENT_SECRET`| `--google-client-secret` | Your issued Google OAuth2 Application Client Secret |
| `OTS_ALLOWED_EMAILS` | `--allowed-emails` | Comma-separated list of strictly allowed email addresses (e.g., `admin@example.com`) |
| `OTS_ALLOWED_DOMAINS` | `--allowed-domains` | Comma-separated list of authorized organizational Google domains (e.g., `example.com`) |
| `OTS_BLOCKED_EMAILS` | `--blocked-emails` | Comma-separated list of strictly banned email addresses |

### Application Limits & Throttling
| Environment Variable | CLI Flag | Default | Description |
|----------------------|----------|---------|-------------|
| `OTS_MAX_SECRET_LENGTH` | `--max-secret-length` | `1024` | Maximum allowable characters limits per secret text block |
| `OTS_DEFAULT_TTL` | `--default-ttl` | `24` | Default expiration lifecycle bounds in **hours** initially highlighted |
| `OTS_MAX_TTL` | `--max-ttl` | `168` | Hard architectural capability ceiling bounds for maximum TTL |
| `OTS_RATE_LIMIT_REQUESTS` | `--rate-limit-requests` | `10` | The number of active hits unauthenticated IP scopes have before throttling |
| `OTS_RATE_LIMIT_WINDOW`| `--rate-limit-window` | `1m` | The window timing algorithm bounds before IP block resets natively |
| `OTS_BLOCKED_IPS` | `--blocked-ips` | `""` | Comma-separated list of globally blacklisted IPS that should instantly be locked out |

### Dynamic Feature Flags (`go-feature-flag`)
| Environment Variable | CLI Flag | Default | Description |
|----------------------|----------|---------|-------------|
| `OTS_FF_FILE` | `--ff-file` | `""` | Optional GCS bucket route path for a remote `.yaml` containing boolean feature rules |
| `OTS_FF_REFRESH_SECONDS`| `--ff-refresh-seconds`| `300` | Pull/Refresh timing schedule applied natively to synchronization cycles |
| `OTS_FF_AUTHZ_DOMAINS` | `--ff-authz-domains` | `""` | Active flag identifying explicit domain allowances mathematically in `go-feature-flag` |
| `OTS_FF_AUTHZ_EMAILS` | `--ff-authz-emails` | `""` | Active flag identifying explicit email allowances |
| `OTS_FF_BLOCK_EMAILS` | `--ff-block-emails` | `""` | Active flag identifying user bans |
| `OTS_FF_BLOCKED_IPS` | `--ff-blocked-ips` | `""` | Active flag identifying IP bounds limits |

### UI Enhancements
| Environment Variable | CLI Flag | Default | Description |
|----------------------|----------|---------|-------------|
| `OTS_CONTACT_EMAIL` | `--contact-email` | `""` | Support pathway address explicitly shown globally inside permission block pages |
| `OTS_HIDE_FOOTER` | `--hide-footer` | `false` | When passed, this natively strips the HTML footer UI component cleanly from rendering |
| `OTS_GOOGLE_TAG_ID` | `--google-tag-id` | `""` | Instantly inserts Google Analytics telemetry securely tied behind user cookie acceptances |
