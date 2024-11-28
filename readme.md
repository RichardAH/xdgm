# XRPL DataGram Monitor (XDGM)

A terminal-based dashboard for monitoring XRPL (XRP Ledger) server datagrams in real-time. This tool listens for UDP packets containing server information and displays them in an interactive terminal interface.

## Features

- Real-time monitoring of multiple XRPL servers
- Display of key metrics including:
  - Server status and synchronization state
  - Peer count and network ID
  - Memory usage and system load
  - Network and disk I/O rates
  - Complete ledger ranges
- Interactive server details view
- Alert system for warnings and server status changes
- Support for both IPv4 and IPv6 addresses
- Auto-detection of stale/AWOL servers

## Installation

```bash
# Clone the repository
git clone [repository-url]
cd xrpl-datagram-monitor

# Install dependencies
npm install
```

## Usage

```bash
# Start the monitor
npm start
```

The monitor listens on port 12345 for UDP packets from XRPL servers.

### Controls

- `Q` or `Ctrl-C`: Quit the application
- Click on a server card: View detailed server information
- `ESC` or `Q`: Close the details view
- Click `[X]`: Close the details view

## Dependencies

- blessed: Terminal interface library
- moment: Time formatting

## Requirements

- Node.js >= 14.0.0

## License

MIT
