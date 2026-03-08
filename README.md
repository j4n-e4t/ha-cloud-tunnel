# HA Cloud Tunnel

Secure remote access to Home Assistant via a reverse TCP tunnel.

## Architecture

```
[Public Internet]
       ↓ (your-domain.com:80)
[Server on Railway]
       ↓ (Reverse Tunnel on :7000)
[Client Add-on]
       ↓ (homeassistant:8123)
[Home Assistant]
```

## Deployment

### Server (Railway.app)

1. Create a new Railway project
2. Deploy the `server/` directory
3. Add a persistent volume mounted at `/data`
4. Expose ports: `80` (public), `7000` (tunnel), `8080` (info)
5. Copy the setup token from logs or visit the info page on port 8080

### Client (Home Assistant Add-on)

1. Add this repository to Home Assistant add-on store
2. Install "HA Cloud Tunnel" add-on
3. Configure:
   - `server_addr`: Your Railway server address with port 7777 (e.g., `your-app.railway.app:7777`)
   - `token`: The 32-character setup token from the server
4. Start the add-on

## Local Testing

```bash
# Start all services
docker compose up --build

# Get the token from server logs
docker compose logs server | grep TOKEN

# Set the token and restart client
TOKEN=<your-token> docker compose up client
```

Then access:
- Server info: http://localhost:8080
- Client info: http://localhost:8099
- Proxied traffic: http://localhost:8000

## Configuration

### Server Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| (none)   | Token is auto-generated and stored in `/data/token.txt` | - |

### Client Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_ADDR` | Server address with tunnel port | Required |
| `TOKEN` | 32-character setup token | Required |
| `TARGET` | Proxy target address | `homeassistant:8123` |

## Ports

### Server
- `80` - Public ingress (HTTP traffic to proxy)
- `7777` - Tunnel connections from client
- `8080` - Info/status web interface

### Client
- `8099` - Info/status web interface
