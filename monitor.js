const dgram = require('dgram');
const blessed = require('blessed');
const moment = require('moment');
const { encodeNodePublic } = require('ripple-address-codec');

// Constants from original code
const SERVER_INFO_MAGIC = 0x4D474458;
const SERVER_INFO_VERSION = 1;
const SERVER_TIMEOUT = 2000;

const WARNING_FLAGS = {
    AMENDMENT_BLOCKED: 1 << 0,
    UNL_BLOCKED: 1 << 1,
    AMENDMENT_WARNED: 1 << 2,
    NOT_SYNCED: 1 << 3
};

// Helper functions
function readUInt64LE(buffer, offset) {
    const low = buffer.readUInt32LE(offset);
    const high = buffer.readUInt32LE(offset + 4);
    return BigInt(high) * BigInt(0x100000000) + BigInt(low);
}

function readDoubleLE(buffer, offset) {
    return buffer.readDoubleLE(offset);
}

function formatBytes(bytes) {
    const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

function formatRate(bytesPerSec) {
    if (bytesPerSec === 0) return '0 B/s';
    const sizes = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s', 'TiB/s'];
    const i = Math.floor(Math.log(bytesPerSec) / Math.log(1024));
    return `${(bytesPerSec / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

function parseRateStats(buffer, offset) {
    return {
        rate_1m: readDoubleLE(buffer, offset),
        rate_5m: readDoubleLE(buffer, offset + 8),
        rate_1h: readDoubleLE(buffer, offset + 16),
        rate_24h: readDoubleLE(buffer, offset + 24)
    };
}

// Create the UI
const screen = blessed.screen({
    smartCSR: true,
    title: 'XDGM - Xahau/XRPL DataGram Monitor Dashboard'
});

// Create a container for the grid
const gridContainer = blessed.box({
    parent: screen,
    top: 1,
    left: 0,
    width: '100%',
    height: '100%-6', // Reduced height to make room for alerts
    style: {
        fg: 'white',
        bg: 'black'
    }
});

// Create header
const header = blessed.box({
    parent: screen,
    top: 0,
    left: 0,
    width: '100%',
    height: 1,
    content: 'XDGM - Xahau/XRPL DataGram Monitor Dashboard - Press Q to quit',
    style: {
        fg: 'white',
        bg: 'blue',
        bold: true
    }
});

// Create alerts panel
const alertsPanel = blessed.box({
    parent: screen,
    bottom: 1,
    left: 0,
    width: '100%',
    height: 4,
    label: ' Alerts ',
    border: {
        type: 'line'
    },
    style: {
        border: {
            fg: 'yellow'
        }
    },
    scrollable: true,
    alwaysScroll: true,
    scrollbar: {
        ch: ' ',
        track: {
            bg: 'cyan'
        },
        style: {
            inverse: true
        }
    }
});

// Create footer
const footer = blessed.box({
    parent: screen,
    bottom: 0,
    left: 0,
    width: '100%',
    height: 1,
    content: ' Active Servers: 0',
    style: {
        fg: 'white',
        bg: 'blue',
        bold: true
    }
});

// Alert management
const alerts = [];
function addAlert(message, serverId) {
    const timestamp = moment().format('HH:mm:ss');
    const alert = `[${timestamp}] ${serverId}: ${message}`;
    alerts.unshift(alert); // Add to beginning
    if (alerts.length > 100) alerts.pop(); // Keep last 100 alerts
    alertsPanel.setContent(alerts.join('\n'));
    screen.render();
}

// Calculate card dimensions
const ROWS = 4;
const COLS = 5;
const CARD_WIDTH = Math.floor(100 / COLS);
const CARD_HEIGHT = Math.floor(100 / ROWS);

// Parse server info header
function parseServerInfoHeader(buffer) {
    if (buffer.length < 8) {
        throw new Error('Packet too small');
    }

    const magic = buffer.readUInt32LE(0);
    if (magic !== SERVER_INFO_MAGIC) {
        throw new Error(`Invalid magic number: ${magic.toString(16)}`);
    }

    const header = {
        magic: magic,
        version: buffer.readUInt32LE(4),
        network_id: buffer.readUInt32LE(8),
        warning_flags: buffer.readUInt16LE(12),  // Now 16-bit
        padding1: buffer.readUInt16LE(14),       // Read padding for completeness
        timestamp: readUInt64LE(buffer, 16),
        uptime: readUInt64LE(buffer, 24),
        io_latency_us: readUInt64LE(buffer, 32),
        validation_quorum: readUInt64LE(buffer, 40),
        peer_count: buffer.readUInt32LE(48),
        node_size: buffer.readUInt32LE(52),
        server_state: buffer.readUInt32LE(56),
        padding2: buffer.readUInt32LE(60),       // Read padding
        fetch_pack_size: readUInt64LE(buffer, 64),
        proposer_count: readUInt64LE(buffer, 72),
        converge_time_ms: readUInt64LE(buffer, 80),
        load_factor: readUInt64LE(buffer, 88),
        load_base: readUInt64LE(buffer, 96),
        reserve_base: readUInt64LE(buffer, 104),
        reserve_inc: readUInt64LE(buffer, 112),
        ledger_seq: readUInt64LE(buffer, 120),
        ledger_hash: buffer.slice(128, 160).toString('hex'),
        node_public_key: buffer.slice(160, 193).toString('hex'),  // Now 33 bytes
        // Skip 7 bytes padding
        ledger_range_count: buffer.readUInt32LE(200),
        
        // System metrics start at offset 208 (aligned)
        process_memory_pages: readUInt64LE(buffer, 208),
        system_memory_total: readUInt64LE(buffer, 216),
        system_memory_free: readUInt64LE(buffer, 224),
        system_memory_used: readUInt64LE(buffer, 232),
        system_disk_total: readUInt64LE(buffer, 240),
        system_disk_free: readUInt64LE(buffer, 248),
        system_disk_used: readUInt64LE(buffer, 256),
        load_avg_1min: readDoubleLE(buffer, 264),
        load_avg_5min: readDoubleLE(buffer, 272),
        load_avg_15min: readDoubleLE(buffer, 280),
        io_wait_time: readUInt64LE(buffer, 288),
        cpu_cores: buffer.readUInt32LE(296),   // New field
        padding4: buffer.readUInt32LE(300),    // New padding field
        
        // Network and disk rates (offset adjusted by 8 bytes for the new fields)
        rates: {
            network_in: parseRateStats(buffer, 304),
            network_out: parseRateStats(buffer, 336),
            disk_read: parseRateStats(buffer, 368),
            disk_write: parseRateStats(buffer, 400)
        }        
    };

    return header;
}

// Calculate size of ServerInfoHeader structure
const HEADER_SIZE = 432; 
function parseLedgerRanges(buffer, header) {
    const ranges = [];
    const rangeSize = 8; // Each range is 2 uint32_t values (start and end)
    const rangeStart = HEADER_SIZE; // Start after the fixed header

    // Use the correct field from header for range count
    for (let i = 0; i < header.ledger_range_count; i++) {
        const offset = rangeStart + (i * rangeSize);
        if (offset + rangeSize > buffer.length) {
            throw new Error('Buffer too small for specified range count');
        }

        ranges.push({
            start: buffer.readUInt32LE(offset),
            end: buffer.readUInt32LE(offset + 4)
        });
    }

    return ranges;
}

function formatAddress(address, port, maxLength = 15) {
    // If address is IPv6, it will contain colons
    const isIPv6 = address.includes(':');
    
    // For IPv6, remove brackets if present
    let ip = address.replace(/^\[|\]$/g, '');
    
    // If the IP is too long, truncate it with ellipsis
    if (ip.length > maxLength) {
        if (isIPv6) {
            // For IPv6, try to keep the start and end parts
            const parts = ip.split(':');
            if (parts.length > 4) {
                ip = parts.slice(0, 2).join(':') + '...' + parts.slice(-2).join(':');
            }
            // If still too long, do a simple truncation
            if (ip.length > maxLength) {
                ip = ip.substring(0, maxLength - 3) + '...';
            }
        } else {
            // For IPv4, simple truncation
            ip = ip.substring(0, maxLength - 3) + '...';
        }
    }
    
    return { ip, port };
}

function bytesToMBps(bytesPerSec) {
    return bytesPerSec / (1024 * 1024);  // Convert bytes/s to MB/s
}

function colorRateNetwork(bytesPerSec) {
    const rate = bytesToMBps(bytesPerSec);
    const formatted = formatRate(bytesPerSec);
    
    if (bytesPerSec === 0) {
        return `{red-fg}${formatted}{/red-fg}`;  // No network activity might indicate issues
    } else if (rate > 120) {
        return `{red-fg}${formatted}{/red-fg}`;  // Over 1Gbps theoretical max
    } else if (rate > 100) {
        return `{yellow-fg}${formatted}{/yellow-fg}`;  // High utilization
    } else {
        return `{green-fg}${formatted}{/green-fg}`;  // Any non-zero traffic is normal
    }
}

function colorRateDisk(bytesPerSec) {
    const rate = bytesToMBps(bytesPerSec);
    const formatted = formatRate(bytesPerSec);
    
    if (bytesPerSec === 0) {
        return `{green-fg}${formatted}{/green-fg}`;  // Memory mode operation
    } else if (rate > 1000) {
        return `{red-fg}${formatted}{/red-fg}`;  // Extremely high for SSD
    } else if (rate > 500) {
        return `{yellow-fg}${formatted}{/yellow-fg}`;  // High utilization
    } else {
        return `{green-fg}${formatted}{/green-fg}`;  // Normal SSD range
    }
}

// Server card class to manage individual server displays
class ServerCard {
    constructor(index) {
        const row = Math.floor(index / COLS);
        const col = index % COLS;
        
        this.lastUpdate = Date.now();
        this.box = blessed.box({
            parent: gridContainer,
            top: `${row * CARD_HEIGHT}%`,
            left: `${col * CARD_WIDTH}%`,
            width: `${CARD_WIDTH}%`,
            height: `${CARD_HEIGHT}%`,
            border: {
                type: 'line'
            },
            style: {
                border: {
                    fg: 'white'
                }
            },
            mouse: true,
            keys: true,
            clickable: true,
            tags: true  // Enable blessed tags for colors
        });

        this.detailsBox = null;
        this.box.on('click', () => this.toggleDetails());
        this.lastUpdate = 0;
        this.isAwol = false;
    }

    getNodeId() {
        if (!this.header) return 'Unknown';
        try {
            // Convert the hex string to buffer
            const pubKeyBuffer = Buffer.from(this.header.node_public_key, 'hex');
            // Encode to node public format (n...)
            return encodeNodePublic(pubKeyBuffer);
        } catch (err) {
            console.error('Error encoding node public key:' + this.header.node_public_key + ' size: ' + this.header.node_public_key.length, err);
            return this.header.node_public_key.substring(0, 8); // Fallback to hex prefix
        }
    }

    getWarnings(header) {
        // Return empty array if header is undefined
        if (!header) return [];
        
        const warnings = [];
        if (header.warning_flags & WARNING_FLAGS.AMENDMENT_BLOCKED) warnings.push('Amendment Blocked');
        if (header.warning_flags & WARNING_FLAGS.UNL_BLOCKED) warnings.push('UNL Blocked');
        if (header.warning_flags & WARNING_FLAGS.AMENDMENT_WARNED) warnings.push('Amendment Warned');
        if (header.warning_flags & WARNING_FLAGS.NOT_SYNCED) warnings.push('NOT SYNCED');
        return warnings;
    }

    update(header, rinfo, ranges) {
        const isFirstUpdate = !this.header;
        const hadWarnings = this.header ? this.getWarnings(this.header).length > 0 : false;
        
        this.lastUpdate = Date.now();
        this.header = header;
        this.rinfo = rinfo;
        this.ranges = ranges;
        
        // Check for new warnings
        const currentWarnings = this.getWarnings(header);
        if (!isFirstUpdate && currentWarnings.length > hadWarnings) {
            currentWarnings.forEach(warning => {
                addAlert(warning, this.getNodeId());
            });
        }

        this.updateDisplay();
        if (this.detailsBox) {
            this.updateDetailsBox();
        }
    }

    updateDisplay() {
        const warnings = this.getWarnings(this.header);
        const nodeId = this.getNodeId();
        this.isAwol = (Date.now() - this.lastUpdate) > SERVER_TIMEOUT;        
        const isNotSynced = !!(this.header.warning_flags & WARNING_FLAGS.NOT_SYNCED);
        const syncStatus = this.isAwol ? 
            '{red-fg}AWOL{/red-fg}' : 
            (this.header.warning_flags & WARNING_FLAGS.NOT_SYNCED) ? 
                '{red-fg}NOT SYNCED{/red-fg}' : 
                '{green-fg}SYNCED{/green-fg}';
    
        const { ip, port } = formatAddress(this.rinfo.address, this.rinfo.port);

        const content = [
            `Node: ${nodeId.slice(0, 6)}...${nodeId.slice(-6)}`,
            `IP: ${ip}`,
            `NetID: ${this.header.network_id}`,
            `Status: ${syncStatus}`,
            `Peers: ${this.header.peer_count}`,
            `Ledger: ${this.header.ledger_seq}`,
            `Load: ${this.header.load_avg_1min.toFixed(2)}`,
            warnings.length > 0 ? `Warnings: ${warnings.join(', ')}` : ''
        ].filter(Boolean).join('\n');

        this.box.setContent(content);

        // Update card color based on warnings and age
        if (this.isAwol) {
            this.box.style.border.fg = 'grey';
            if (!this.lastAwolAlert || Date.now() - this.lastAwolAlert > 300000) { // 5 minutes
                addAlert('Server is AWOL', nodeId);
                this.lastAwolAlert = Date.now();
            }
        } else if (warnings.length > 0) {
            this.box.style.border.fg = 'red';
            if (!this.lastWarningTime || Date.now() - this.lastWarningTime > 300000) { // 5 minutes
                warnings.forEach(warning => addAlert(warning, nodeId));
                this.lastWarningTime = Date.now();
            }
        } else {
            this.box.style.border.fg = 'green';
        }

        screen.render();
    }

    toggleDetails() {
        if (this.detailsBox) {
            this.closeDetails();
        } else {
            this.showDetails();
        }
    }

    closeDetails() {
        if (this.detailsBox) {
            screen.remove(this.detailsBox);
            this.detailsBox = null;
            screen.render();
        }
    }

    showDetails() {
        const nodeId = this.getNodeId();
        
        this.detailsBox = blessed.box({
            parent: screen,
            top: 'center',
            left: 'center',
            width: '80%',
            height: '80%',
            border: {
                type: 'line'
            },
            label: ` Server Details - ${nodeId.slice(0, 6)}...${nodeId.slice(-6)} - Click anywhere to close `,
            style: {
                border: {
                    fg: 'white'
                }
            },
            keys: true,
            mouse: true,
            scrollable: true,
            alwaysScroll: true,
            scrollbar: {
                ch: ' ',
                track: {
                    bg: 'cyan'
                },
                style: {
                    inverse: true
                }
            },
            padding: 1,
            tags: true
        });

        // Click anywhere in the box to close
        this.detailsBox.on('click', () => {
            this.closeDetails();
            screen.render();
        });

        // Add key handlers
        this.detailsBox.key(['escape', 'q'], () => {
            this.closeDetails();
            screen.render();
        });

        this.updateDetailsBox();
        screen.render();
    }


    updateDetailsBox() {

        if (!this.detailsBox) return;

        const warnings = this.getWarnings(this.header);
        const { ip, port } = formatAddress(this.rinfo.address, this.rinfo.port, 45);

        if (this.isAwol) {
            this.detailsBox.setContent(
                'Server Status: {red-fg}AWOL{/red-fg}\n' +
                `Last seen: ${moment(this.lastUpdate).format('YYYY-MM-DD HH:mm:ss')}\n` +
                `IP Address: ${ip}\n` +
                `Port: ${port}\n` +
                `Node ID: ${this.getNodeId()}`
            );
            return;
        }

        const isNotSynced = !!(this.header.warning_flags & WARNING_FLAGS.NOT_SYNCED);
        const syncStatus = isNotSynced ? '{red-fg}NOT SYNCED{/red-fg}' : '{green-fg}SYNCED{/green-fg}';
        const content = [
            `Server: ${this.rinfo.address}:${this.rinfo.port}`,
            `Node ID: ${this.getNodeId()}`,
            `Network ID: ${this.header.network_id}`,
            `Sync Status: ${syncStatus}`,
            `Uptime: ${moment.duration(Number(this.header.uptime), 'seconds').humanize()}`,
            `IO Latency: ${Number(this.header.io_latency_us)}µs`,
            `Peer Count: ${this.header.peer_count}`,
            `Node Size: ${this.header.node_size}`,
            `Server State: ${this.header.server_state}`,
            `Ledger Sequence: ${this.header.ledger_seq}`,
            `Ledger Hash: ${this.header.ledger_hash}`,
            `Node Public Key: ${this.header.node_public_key}`,
            warnings.length > 0 ? `\nWarnings: {red-fg}${warnings.join(', ')}{/red-fg}` : '',
            '',
            'System Metrics:',
            `CPU Cores: ${this.header.cpu_cores}`,
            `Memory Usage: ${formatBytes(Number(this.header.process_memory_pages) * 4096)}`,
            `System Memory: ${formatBytes(Number(this.header.system_memory_used))} / ${formatBytes(Number(this.header.system_memory_total))}`,
            `Disk Usage: ${formatBytes(Number(this.header.system_disk_used))} / ${formatBytes(Number(this.header.system_disk_total))}`,
            `Load Average: ${this.header.load_avg_1min.toFixed(2)}, ${this.header.load_avg_5min.toFixed(2)}, ${this.header.load_avg_15min.toFixed(2)}`,
            '',
            'Network Rates:',
            `In:    1m: ${colorRateNetwork(this.header.rates.network_in.rate_1m).padEnd(20)}  5m: ${colorRateNetwork(this.header.rates.network_in.rate_5m).padEnd(20)}  1h: ${colorRateNetwork(this.header.rates.network_in.rate_1h).padEnd(20)}  24h: ${colorRateNetwork(this.header.rates.network_in.rate_24h)}`,
            `Out:   1m: ${colorRateNetwork(this.header.rates.network_out.rate_1m).padEnd(20)}  5m: ${colorRateNetwork(this.header.rates.network_out.rate_5m).padEnd(20)}  1h: ${colorRateNetwork(this.header.rates.network_out.rate_1h).padEnd(20)}  24h: ${colorRateNetwork(this.header.rates.network_out.rate_24h)}`,
            '',
            'Disk Rates:',
            `Read:  1m: ${colorRateDisk(this.header.rates.disk_read.rate_1m).padEnd(20)}  5m: ${colorRateDisk(this.header.rates.disk_read.rate_5m).padEnd(20)}  1h: ${colorRateDisk(this.header.rates.disk_read.rate_1h).padEnd(20)}  24h: ${colorRateDisk(this.header.rates.disk_read.rate_24h)}`,
            `Write: 1m: ${colorRateDisk(this.header.rates.disk_write.rate_1m).padEnd(20)}  5m: ${colorRateDisk(this.header.rates.disk_write.rate_5m).padEnd(20)}  1h: ${colorRateDisk(this.header.rates.disk_write.rate_1h).padEnd(20)}  24h: ${colorRateDisk(this.header.rates.disk_write.rate_24h)}`,            
            '',
            'Complete Ledger Ranges:',
            ...(this.ranges ? this.ranges.map(range => 
                `${range.start.toLocaleString()} - ${range.end.toLocaleString()}`
            ) : ['No ranges available'])
        ].join('\n');

        this.detailsBox.setContent(content);
        screen.render();
    }
}

// Server management
const servers = new Map();
let nextSlot = 0;

function getNextSlot() {
    if (nextSlot >= 20) return null;
    return nextSlot++;
}

function updateServerCount() {
    footer.setContent(` Active Servers: ${servers.size}`);
    screen.render();
}

// Set up the UDP server
const server = dgram.createSocket('udp4');

server.on('error', (err) => {
    console.error(`Server error:\n${err.stack}`);
    server.close();
});

server.on('message', (msg, rinfo) => {
    try {
        const header = parseServerInfoHeader(msg);
        const serverKey = header.node_public_key;
        
        if (!servers.has(serverKey)) {
            const slot = getNextSlot();
            if (slot !== null) {
                const card = new ServerCard(slot);
                servers.set(serverKey, card);
                updateServerCount();
            }
        }
        
        const card = servers.get(serverKey);
        if (card) {
            const ranges = parseLedgerRanges(msg, header);
            card.update(header, rinfo, ranges);
        }
    } catch (err) {
        console.error('Error parsing packet:', err);
    }
});

// Update cards periodically to show stale status
setInterval(() => {
    for (const card of servers.values()) {
        card.updateDisplay();
        // Add this line to also update details box if it's open
        if (card.detailsBox) {
            card.updateDetailsBox();
        }
    }
}, 1000);

// Quit on Q
screen.key(['q', 'C-c'], () => process.exit(0));

// Start server
server.bind(12345);

// Initial render
screen.render();
