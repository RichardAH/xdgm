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

// Add command line argument parsing
const args = process.argv.slice(2);
const RAW_MODE = args.includes('--raw') || args.includes('-r');

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

// Parse server info header
function parseServerInfoHeader(buffer) {
    if (buffer.length < 8) {
        throw new Error('Packet too small');
    }

    const magic = buffer.readUInt32LE(0);
    if (magic !== SERVER_INFO_MAGIC) {
        throw new Error(`Invalid magic number: ${magic.toString(16)}`);
    }

    function bigIntToNumber(value) {
        return typeof value === 'bigint' ? Number(value) : value;
    }

    let offset = 0;
    const header = {};

    // Fixed header fields (32-bit values)
    header.magic = buffer.readUInt32LE(offset);                    offset += 4;
    header.version = buffer.readUInt32LE(offset);                  offset += 4;
    header.network_id = buffer.readUInt32LE(offset);               offset += 4;
    header.server_state = buffer.readUInt32LE(offset);             offset += 4;
    header.peer_count = buffer.readUInt32LE(offset);               offset += 4;
    header.node_size = buffer.readUInt32LE(offset);                offset += 4;
    header.cpu_cores = buffer.readUInt32LE(offset);                offset += 4;
    header.ledger_range_count = buffer.readUInt32LE(offset);       offset += 4;
    header.warning_flags = buffer.readUInt32LE(offset);            offset += 4;

    offset += 4; // padding alignment

    // 64-bit metrics
    header.timestamp = bigIntToNumber(readUInt64LE(buffer, offset));           offset += 8;
    header.uptime = bigIntToNumber(readUInt64LE(buffer, offset));             offset += 8;
    header.io_latency_us = bigIntToNumber(readUInt64LE(buffer, offset));      offset += 8;
    header.validation_quorum = bigIntToNumber(readUInt64LE(buffer, offset));   offset += 8;
    header.fetch_pack_size = bigIntToNumber(readUInt64LE(buffer, offset));    offset += 8;
    header.proposer_count = bigIntToNumber(readUInt64LE(buffer, offset));     offset += 8;
    header.converge_time_ms = bigIntToNumber(readUInt64LE(buffer, offset));   offset += 8;
    header.load_factor = bigIntToNumber(readUInt64LE(buffer, offset));        offset += 8;
    header.load_base = bigIntToNumber(readUInt64LE(buffer, offset));          offset += 8;
    header.reserve_base = bigIntToNumber(readUInt64LE(buffer, offset));       offset += 8;
    header.reserve_inc = bigIntToNumber(readUInt64LE(buffer, offset));        offset += 8;
    header.ledger_seq = bigIntToNumber(readUInt64LE(buffer, offset));         offset += 8;

    // Fixed-size byte arrays
    header.ledger_hash = buffer.slice(offset, offset + 32).toString('hex');   offset += 32;
    header.node_public_key = buffer.slice(offset, offset + 33).toString('hex'); offset += 33;
    // Skip padding2[7]
    header.padding2 = buffer.slice(offset, offset + 7).toString('hex');       offset += 7;

    // System metrics (64-bit values)
    header.process_memory_pages = bigIntToNumber(readUInt64LE(buffer, offset)); offset += 8;
    header.system_memory_total = bigIntToNumber(readUInt64LE(buffer, offset));  offset += 8;
    header.system_memory_free = bigIntToNumber(readUInt64LE(buffer, offset));   offset += 8;
    header.system_memory_used = bigIntToNumber(readUInt64LE(buffer, offset));   offset += 8;
    header.system_disk_total = bigIntToNumber(readUInt64LE(buffer, offset));    offset += 8;
    header.system_disk_free = bigIntToNumber(readUInt64LE(buffer, offset));     offset += 8;
    header.system_disk_used = bigIntToNumber(readUInt64LE(buffer, offset));     offset += 8;
    header.io_wait_time = bigIntToNumber(readUInt64LE(buffer, offset));         offset += 8;

    // Load averages (doubles)
    header.load_avg_1min = readDoubleLE(buffer, offset);           offset += 8;
    header.load_avg_5min = readDoubleLE(buffer, offset);           offset += 8;
    header.load_avg_15min = readDoubleLE(buffer, offset);          offset += 8;

    // State transitions
    header.state_transitions = new Array(5).fill(0).map(() => {
        const val = bigIntToNumber(readUInt64LE(buffer, offset));
        offset += 8;
        return val;
    });

    // State durations
    header.state_durations = new Array(5).fill(0).map(() => {
        const val = bigIntToNumber(readUInt64LE(buffer, offset));
        offset += 8;
        return val;
    });

    header.initial_sync_us = bigIntToNumber(readUInt64LE(buffer, offset)); offset += 8;

    // Network and disk rates
    header.rates = {}
    header.rates.network_in = parseRateStats(buffer, offset);        offset += 32;
    header.rates.network_out = parseRateStats(buffer, offset);       offset += 32;
    header.rates.disk_read = parseRateStats(buffer, offset);         offset += 32;
    header.rates.disk_write = parseRateStats(buffer, offset);        offset += 32;
        

    // Debug output
    const DEBUG = false;
    if (DEBUG) {
        console.debug(`Total bytes parsed: ${offset}`);
        console.debug("\nKey fields:");
        console.debug(`peer_count: ${header.peer_count}`);
        console.debug(`ledger_range_count: ${header.ledger_range_count}`);
        console.debug(`ledger_seq: ${header.ledger_seq}`);
        console.debug(`node_public_key: ${header.node_public_key}`);
    }

    return header;
}

// Parse ledger ranges
const HEADER_SIZE = 532;
function parseLedgerRanges(buffer, header) {
    try {
        // The range should be at the very end of the packet
        const rangeOffset = buffer.length - 8;
        return [{
            start: buffer.readUInt32LE(rangeOffset),
            end: buffer.readUInt32LE(rangeOffset + 4)
        }];
    } catch (err) {
        console.debug('Error parsing ledger range:', err.message);
        return [];
    }
}

function formatAddress(address, port, maxLength = 15) {
    const isIPv6 = address.includes(':');
    let ip = address.replace(/^\[|\]$/g, '');
    
    if (ip.length > maxLength) {
        if (isIPv6) {
            const parts = ip.split(':');
            if (parts.length > 4) {
                ip = parts.slice(0, 2).join(':') + '...' + parts.slice(-2).join(':');
            }
            if (ip.length > maxLength) {
                ip = ip.substring(0, maxLength - 3) + '...';
            }
        } else {
            ip = ip.substring(0, maxLength - 3) + '...';
        }
    }
    
    return { ip, port };
}

function bytesToMBps(bytesPerSec) {
    return bytesPerSec / (1024 * 1024);
}

function colorRateNetwork(bytesPerSec) {
    const rate = bytesToMBps(bytesPerSec);
    const formatted = formatRate(bytesPerSec);
    
    if (bytesPerSec === 0) {
        return `{red-fg}${formatted}{/red-fg}`;
    } else if (rate > 120) {
        return `{red-fg}${formatted}{/red-fg}`;
    } else if (rate > 100) {
        return `{yellow-fg}${formatted}{/yellow-fg}`;
    } else {
        return `{green-fg}${formatted}{/green-fg}`;
    }
}

function colorRateDisk(bytesPerSec) {
    const rate = bytesToMBps(bytesPerSec);
    const formatted = formatRate(bytesPerSec);
    
    if (bytesPerSec === 0) {
        return `{green-fg}${formatted}{/green-fg}`;
    } else if (rate > 1000) {
        return `{red-fg}${formatted}{/red-fg}`;
    } else if (rate > 500) {
        return `{yellow-fg}${formatted}{/yellow-fg}`;
    } else {
        return `{green-fg}${formatted}{/green-fg}`;
    }
}

function colorLoadAverage(loadAvg, cpuCores) {
    const load = loadAvg.toFixed(2);
    const perCoreLoad = loadAvg / cpuCores;
    
    if (perCoreLoad >= 0.8) {
        return `{red-fg}${load}{/red-fg}`;
    } else if (perCoreLoad >= 0.6) {
        return `{yellow-fg}${load}{/yellow-fg}`;
    } else {
        return `{green-fg}${load}{/green-fg}`;
    }
}

function colorMemoryUsage(used, total) {
    const usedNum = typeof used === 'bigint' ? Number(used) : used;
    const totalNum = typeof total === 'bigint' ? Number(total) : total;
    
    const usagePercent = (usedNum / totalNum) * 100;
    const usageStr = formatBytes(usedNum);
    
    if (usagePercent >= 90) {
        return `{red-fg}${usageStr}{/red-fg}`;
    } else if (usagePercent >= 75) {
        return `{yellow-fg}${usageStr}{/yellow-fg}`;
    } else {
        return `{green-fg}${usageStr}{/green-fg}`;
    }
}

function colorDiskUsage(used, total) {
    const usedNum = typeof used === 'bigint' ? Number(used) : used;
    const totalNum = typeof total === 'bigint' ? Number(total) : total;
    
    const usagePercent = (usedNum / totalNum) * 100;
    const usageStr = formatBytes(usedNum);
    
    if (usagePercent >= 95) {
        return `{red-fg}${usageStr}{/red-fg}`;
    } else if (usagePercent >= 80) {
        return `{yellow-fg}${usageStr}{/yellow-fg}`;
    } else {
        return `{green-fg}${usageStr}{/green-fg}`;
    }
}

// Raw mode packet handler
function handleRawPacket(msg, rinfo) {
    console.log('\n--- New Packet Received ---');
    console.log('From:', rinfo.address, 'Port:', rinfo.port);
    console.log('Raw Hex:', msg.toString('hex'));
    
    try {
        const header = parseServerInfoHeader(msg);
        const ranges = parseLedgerRanges(msg, header);
        
        console.log('\nParsed Header:');
        console.log(JSON.stringify(header, (key, value) => {
            if (typeof value === 'bigint') {
                return value.toString();
            }
            return value;
        }, 2));
        
        console.log('\nLedger Ranges:');
        console.log(JSON.stringify(ranges, null, 2));
        
    } catch (err) {
        console.error('Error parsing packet:', err);
    }
    console.log('-'.repeat(50));
}

function formatDuration(microseconds) {
    if (microseconds === 0) return '0 μs';

    const units = [
        { divisor: 31536000000000, unit: 'year' },
        { divisor: 2592000000000, unit: 'month' },
        { divisor: 86400000000, unit: 'day' },
        { divisor: 3600000000, unit: 'hour' },
        { divisor: 60000000, unit: 'minute' },
        { divisor: 1000000, unit: 'second' },
        { divisor: 1000, unit: 'ms' },
        { divisor: 1, unit: 'μs' }
    ];

    // Find the most appropriate unit
    for (const { divisor, unit } of units) {
        if (microseconds >= divisor) {
            const value = (microseconds / divisor).toFixed(1);
            return `${value} ${unit}${value !== '1' ? 's' : ''}`;
        }
    }
}

if (RAW_MODE) {
    // Raw mode setup
    const server = dgram.createSocket('udp4');
    
    server.on('error', (err) => {
        console.error(`Server error:\n${err.stack}`);
        server.close();
    });
    
    server.on('message', handleRawPacket);
    
    server.bind(12345);
    console.log('XDGM Raw Mode: Listening on port 12345');
    console.log('Press Ctrl+C to exit');
} else {
    // UI Mode
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
        height: '100%-6',
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
        alerts.unshift(alert);
        if (alerts.length > 100) alerts.pop();
        alertsPanel.setContent(alerts.join('\n'));
        screen.render();
    }

    // Calculate card dimensions
    const ROWS = 4;
    const COLS = 5;
    const CARD_WIDTH = Math.floor(100 / COLS);
    const CARD_HEIGHT = Math.floor(100 / ROWS);

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
                tags: true
            });

            this.detailsBox = null;
            this.box.on('click', () => this.toggleDetails());
            this.lastUpdate = 0;
            this.isAwol = false;
        }

        getNodeId() {
            if (!this.header) return 'Unknown';
            try {
                const pubKeyBuffer = Buffer.from(this.header.node_public_key, 'hex');
                return encodeNodePublic(pubKeyBuffer);
            } catch (err) {
                console.error('Error encoding node public key:' + this.header.node_public_key + ' size: ' + this.header.node_public_key.length, err);
                return this.header.node_public_key.substring(0, 8);
            }
        }

        getWarnings(header) {
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
            // If we don't have header data yet, show initializing state
            if (!this.header || !this.rinfo) {
                const content = [
                    'Node: Initializing...',
                    'Status: {yellow-fg}WAITING{/yellow-fg}',
                ].join('\n');

                this.box.setContent(content);
                this.box.style.border.fg = 'yellow';
                screen.render();
                return;
            }

            const warnings = this.getWarnings(this.header);
            const nodeId = this.getNodeId();
            this.isAwol = (Date.now() - this.lastUpdate) > SERVER_TIMEOUT;
            const syncStatus = this.isAwol ?
                '{red-fg}AWOL{/red-fg}' :
                (this.header.warning_flags & WARNING_FLAGS.NOT_SYNCED) ?
                    '{red-fg}NOT SYNCED{/red-fg}' :
                    '{green-fg}SYNCED{/green-fg}';

            const { ip, port } = formatAddress(this.rinfo.address, this.rinfo.port);
            const loadAvgColored = colorLoadAverage(this.header.load_avg_1min, this.header.cpu_cores);

            const content = [
                `Node: ${nodeId.slice(0, 6)}...${nodeId.slice(-6)}`,
                `IP: ${ip}`,
                `NetID: ${this.header.network_id}`,
                `Status: ${syncStatus}`,
                `Peers: ${this.header.peer_count}`,
                `Ledger: ${this.header.ledger_seq}`,
                `Load: ${loadAvgColored}`,
                warnings.length > 0 ? `Warnings: ${warnings.join(', ')}` : ''
            ].filter(Boolean).join('\n');

            this.box.setContent(content);

            // Update card color based on state
            if (this.isAwol) {
                this.box.style.border.fg = 'grey';
                if (!this.lastAwolAlert || Date.now() - this.lastAwolAlert > 300000) {
                    addAlert('Server is AWOL', nodeId);
                    this.lastAwolAlert = Date.now();
                }
            } else if (warnings.length > 0) {
                this.box.style.border.fg = 'red';
                if (!this.lastWarningTime || Date.now() - this.lastWarningTime > 300000) {
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

            this.detailsBox.on('click', () => {
                this.closeDetails();
                screen.render();
            });

            this.detailsBox.key(['escape', 'q'], () => {
                this.closeDetails();
                screen.render();
            });

            this.updateDetailsBox();
            screen.render();
        }

        updateDetailsBox() {
            if (!this.detailsBox) return;

            // If we don't have data yet, show waiting message
            if (!this.header || !this.rinfo) {
                this.detailsBox.setContent('Waiting for server data...');
                screen.render();
                return;
            }

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
            const processMemory = Number(this.header.process_memory_pages) * 4096;

            const periods = ['rate_1m', 'rate_5m', 'rate_1h', 'rate_24h'];
            const formatPeriodHeader = () => {
                return [
                    'Period', ' '.repeat(4),
                    '1m', ' '.repeat(17),
                    '5m', ' '.repeat(17),
                    '1h', ' '.repeat(17),
                    '24h'
                ].join('');
            };

            const formatRateRow = (label, rates, colorFn) => {
                const row = [label, ' '.repeat(10 - label.length)];
                periods.forEach((period, index) => {
                    const rate = rates[period];
                    const formattedRate = colorFn(rate).trim();
                    row.push(formattedRate)
                    row.push(' '.repeat(40 - (''+formattedRate).length));
                });
                return row.join('');
            };

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
                `Memory Usage: ${colorMemoryUsage(processMemory, this.header.system_memory_total)}`,
                `System Memory: ${colorMemoryUsage(this.header.system_memory_used, this.header.system_memory_total)} / ${formatBytes(Number(this.header.system_memory_total))}`,
                `Disk Usage: ${colorDiskUsage(this.header.system_disk_used, this.header.system_disk_total)} / ${formatBytes(Number(this.header.system_disk_total))}`,
                `Load Average: ${colorLoadAverage(this.header.load_avg_1min, this.header.cpu_cores)}, ${colorLoadAverage(this.header.load_avg_5min, this.header.cpu_cores)}, ${colorLoadAverage(this.header.load_avg_15min, this.header.cpu_cores)}`,
                '',
                'Network Rates:',
                formatPeriodHeader(),
                formatRateRow('In: ', this.header.rates.network_in, colorRateNetwork),
                formatRateRow('Out:', this.header.rates.network_out, colorRateNetwork),
                '',
                'Disk Rates:',
                formatPeriodHeader(),
                formatRateRow('Read: ', this.header.rates.disk_read, colorRateDisk),
                formatRateRow('Write:', this.header.rates.disk_write, colorRateDisk),
                '',            
                'Complete Ledger Ranges:',
                ...(this.ranges ? this.ranges.map(range => 
                    `${range.start.toLocaleString()} - ${range.end.toLocaleString()}`
                ) : ['No ranges available']),
                '',
                'State Transitions:',
                this.header.state_transitions.map((count, i) =>
                    `${["Disconnect", "Connect", "Syncing", "Tracking", "Full"][i]}: ${count} transitions, Duration: ${formatDuration(Number(this.header.state_durations[i]))}`
                ).join('\n'),
                `Initial Sync Time: ${formatDuration(Number(this.header.initial_sync_us))}`
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
            // First validate minimum packet size
            if (msg.length < HEADER_SIZE) {
                console.debug(`Packet too small: ${msg.length} bytes (minimum ${HEADER_SIZE} required)`);
                return;
            }

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
                // Get ranges, but don't fail if parsing fails
                let ranges = [];
                try {
                    ranges = parseLedgerRanges(msg, header);
                } catch (err) {
                    console.debug('Failed to parse ledger ranges:', err.message);
                }
                card.update(header, rinfo, ranges);
            }
        } catch (err) {
            console.debug('Error processing packet:', err.message);
            // Don't rethrow - just log and continue
        }
    });

    // Update cards periodically
    setInterval(() => {
        for (const card of servers.values()) {
            card.updateDisplay();
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
}
