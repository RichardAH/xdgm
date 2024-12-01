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

const HEADER_SIZE = 708;

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

function parseObjectCounts(buffer, header) {
    try {
        const objectCountOffset = HEADER_SIZE + (header.ledger_range_count * 8);
        const counts = [];
        const remainingBytes = buffer.length - objectCountOffset;
        const numObjects = Math.floor(remainingBytes / 64); // Each record is 56 + 8 = 64 bytes

        for (let i = 0; i < numObjects; i++) {
            const offset = objectCountOffset + (i * 64);

            // Read the name (56 bytes)
            const nameBuffer = buffer.slice(offset, offset + 56);
            const name = nameBuffer.toString('utf8').replace(/\0+$/, ''); // Remove null padding

            // Read the count (8 bytes) as a 64-bit integer
            const count = Number(readUInt64LE(buffer, offset + 56));

            // Only add non-empty names
            if (name.length > 0) {
                counts.push({ name, count });
            }
        }
        return counts;
    } catch (err) {
        console.debug('Error parsing object counts:', err.message);
        return [];
    }
}

// Parse server info header
function parseServerInfoHeader(buffer) {
//    if (buffer.length < 512) {
//        throw new Error('Packet too small');
//    }

    function bigIntToNumber(value) {
        return typeof value === 'bigint' ? Number(value) : value;
    }

    const header = {};

    // Fixed header fields (32-bit values)
    header.magic = buffer.readUInt32LE(0);                       // 0
    header.version = buffer.readUInt32LE(4);                     // 4
    header.network_id = buffer.readUInt32LE(8);                  // 8
    header.server_state = buffer.readUInt32LE(12);               // 12
    header.peer_count = buffer.readUInt32LE(16);                 // 16
    header.node_size = buffer.readUInt32LE(20);                  // 20
    header.cpu_cores = buffer.readUInt32LE(24);                  // 24
    header.ledger_range_count = buffer.readUInt32LE(28);         // 28
    header.warning_flags = buffer.readUInt32LE(32);              // 32
    
     // padding_1                                                // 36

    // 64-bit metrics starting at offset 40
    header.timestamp = bigIntToNumber(readUInt64LE(buffer, 40));
    header.uptime = bigIntToNumber(readUInt64LE(buffer, 48));
    header.io_latency_us = bigIntToNumber(readUInt64LE(buffer, 56));
    header.validation_quorum = bigIntToNumber(readUInt64LE(buffer, 64));
    header.fetch_pack_size = bigIntToNumber(readUInt64LE(buffer, 72));
    header.proposer_count = bigIntToNumber(readUInt64LE(buffer, 80));
    header.converge_time_ms = bigIntToNumber(readUInt64LE(buffer, 88));
    header.load_factor = bigIntToNumber(readUInt64LE(buffer, 96));
    header.load_base = bigIntToNumber(readUInt64LE(buffer, 104));
    header.reserve_base = bigIntToNumber(readUInt64LE(buffer, 112));
    header.reserve_inc = bigIntToNumber(readUInt64LE(buffer, 120));
    header.ledger_seq = bigIntToNumber(readUInt64LE(buffer, 128));

    // Fixed-size byte arrays
    header.ledger_hash = buffer.slice(136, 168).toString('hex');     // 32 bytes
    header.node_public_key = buffer.slice(168, 201).toString('hex'); // 33 bytes
    // padding 7 bytes
    // Version string (32 bytes) starting at offset 201
    header.version_string = buffer.slice(201, 233).toString('utf8').replace(/\0+$/, ''); // 32 bytes, trim null padding
    
    // System metrics
    header.process_memory_pages = bigIntToNumber(readUInt64LE(buffer, 240));  // 208 + 32
    header.system_memory_total = bigIntToNumber(readUInt64LE(buffer, 248));   // 216 + 32
    header.system_memory_free = bigIntToNumber(readUInt64LE(buffer, 256));    // 224 + 32
    header.system_memory_used = bigIntToNumber(readUInt64LE(buffer, 264));    // 232 + 32
    header.system_disk_total = bigIntToNumber(readUInt64LE(buffer, 272));     // 240 + 32
    header.system_disk_free = bigIntToNumber(readUInt64LE(buffer, 280));      // 248 + 32
    header.system_disk_used = bigIntToNumber(readUInt64LE(buffer, 288));      // 256 + 32
    header.io_wait_time = bigIntToNumber(readUInt64LE(buffer, 296));         // 264 + 32

    // Load averages (doubles)
    header.load_avg_1min = readDoubleLE(buffer, 304);    // 272 + 32
    header.load_avg_5min = readDoubleLE(buffer, 312);    // 280 + 32
    header.load_avg_15min = readDoubleLE(buffer, 320);   // 288 + 32
    
    // State transitions
    header.state_transitions = [];
    for (let i = 0; i < 5; i++) {
        header.state_transitions.push(
            bigIntToNumber(readUInt64LE(buffer, 328 + (i * 8)))  // 296 + 32
        );
    }

    // State durations
    header.state_durations = [];
    for (let i = 0; i < 5; i++) {
        header.state_durations.push(
            bigIntToNumber(readUInt64LE(buffer, 368 + (i * 8)))  // 336 + 32
        );
    }

    header.initial_sync_us = bigIntToNumber(readUInt64LE(buffer, 408));  // 376 + 32
    
    // Network and disk rates
    header.rates = {
        network_in: {
            rate_1m: readDoubleLE(buffer, 416),   // 384 + 32
            rate_5m: readDoubleLE(buffer, 424),   // 392 + 32
            rate_1h: readDoubleLE(buffer, 432),   // 400 + 32
            rate_24h: readDoubleLE(buffer, 440)   // 408 + 32
        },
        network_out: {
            rate_1m: readDoubleLE(buffer, 448),   // 416 + 32
            rate_5m: readDoubleLE(buffer, 456),   // 424 + 32
            rate_1h: readDoubleLE(buffer, 464),   // 432 + 32
            rate_24h: readDoubleLE(buffer, 472)   // 440 + 32
        },
        disk_read: {
            rate_1m: readDoubleLE(buffer, 480),   // 448 + 32
            rate_5m: readDoubleLE(buffer, 488),   // 456 + 32
            rate_1h: readDoubleLE(buffer, 496),   // 464 + 32
            rate_24h: readDoubleLE(buffer, 504)   // 472 + 32
        },
        disk_write: {
            rate_1m: readDoubleLE(buffer, 512),   // 480 + 32
            rate_5m: readDoubleLE(buffer, 520),   // 488 + 32
            rate_1h: readDoubleLE(buffer, 528),   // 496 + 32
            rate_24h: readDoubleLE(buffer, 536)   // 504 + 32
        }
    }


    return header;
}

function bigIntToNumber(x)
{
    return Number(x + '')
}

function parseDebugCounters(buffer) {
    // Start at offset 544 as per specification
    try {
        return {
            dbKBTotal: bigIntToNumber(readUInt64LE(buffer, 544)),
            dbKBLedger: bigIntToNumber(readUInt64LE(buffer, 552)),
            dbKBTransaction: bigIntToNumber(readUInt64LE(buffer, 560)),
            localTxCount: bigIntToNumber(readUInt64LE(buffer, 568)),
            writeLoad: buffer.readUInt32LE(576),
            historicalPerMinute: buffer.readUInt32LE(580),
            sleHitRate: buffer.readUInt32LE(584),
            ledgerHitRate: buffer.readUInt32LE(588),
            alSize: buffer.readUInt32LE(592),
            alHitRate: buffer.readUInt32LE(596),
            fullbelowSize: buffer.readUInt32LE(600),
            treenodeCacheSize: buffer.readUInt32LE(604),
            treenodeTrackSize: buffer.readUInt32LE(608),
            shardFullbelowSize: buffer.readUInt32LE(612),
            shardTreenodeCacheSize: buffer.readUInt32LE(616),
            shardTreenodeTrackSize: buffer.readUInt32LE(620),
            shardWriteLoad: buffer.readUInt32LE(624),
            shardNodeWrites: bigIntToNumber(readUInt64LE(buffer, 628)),
            shardNodeReadsTotal: bigIntToNumber(readUInt64LE(buffer, 636)),
            shardNodeReadsHit: bigIntToNumber(readUInt64LE(buffer, 644)),
            shardNodeWrittenBytes: bigIntToNumber(readUInt64LE(buffer, 652)),
            shardNodeReadBytes: bigIntToNumber(readUInt64LE(buffer, 660)),
            nodeWriteCount: bigIntToNumber(readUInt64LE(buffer, 668)),
            nodeWriteSize: bigIntToNumber(readUInt64LE(buffer, 676)),
            nodeFetchCount: bigIntToNumber(readUInt64LE(buffer, 684)),
            nodeFetchHitCount: bigIntToNumber(readUInt64LE(buffer, 692)),
            nodeFetchSize: bigIntToNumber(readUInt64LE(buffer, 700))
        };
    } catch (err) {
        console.debug('Error parsing debug counters:', err.message);
        return null;
    }
}

function parseLedgerRanges(buffer, header) {
    try {
        const rangeOffset = HEADER_SIZE;
        const ranges = [];
        for (let i = 0; i < header.ledger_range_count; i++) {
            const offset = rangeOffset + (i * 8);
            ranges.push({
                start: buffer.readUInt32LE(offset),
                end: buffer.readUInt32LE(offset + 4)
            });
        }
        return ranges;
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
        const objectCounts = parseObjectCounts(msg, header);
        
        console.log('\nParsed Header:');
        console.log(JSON.stringify(header, (key, value) => {
            if (typeof value === 'bigint') {
                return value.toString();
            }
            return value;
        }, 2));
        
        console.log('\nLedger Ranges:');
        console.log(JSON.stringify(ranges, null, 2));
        
        console.log('\nObject Counts:')
        console.log(JSON.stringify(objectCounts, null, 2));

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

    function formatHitRate(rate) {
        // Convert decimal to percentage with 2 decimal places
        return (rate * 100).toFixed(2) + '%';
    }

    // Calculate card dimensions
    const ROWS = 4;
    const COLS = 5;
    const CARD_WIDTH = Math.floor(100 / COLS);
    const CARD_HEIGHT = Math.floor(100 / ROWS);

    // Server card class to manage individual server displays
    class ServerCard {
        constructor(index) {
            const CARDS_PER_ROW = 5;
            const CARD_HEIGHT_PERCENT = 25; // 25% of visible area for 4 rows
            
            const row = Math.floor(index / CARDS_PER_ROW);
            const col = index % CARDS_PER_ROW;
            
            this.lastUpdate = Date.now();
            this.box = blessed.box({
                parent: gridContainer,
                top: row * CARD_HEIGHT_PERCENT + '%',
                left: col * 20 + '%', // 20% for 5 columns
                width: '20%',
                height: CARD_HEIGHT_PERCENT + '%',
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
            this.objectCounts = [];
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
        
        update(header, rinfo, ranges, objectCounts, debugCounters) {
            const isFirstUpdate = !this.header;
            const hadWarnings = this.header ? this.getWarnings(this.header).length > 0 : false;
            
            this.lastUpdate = Date.now();
            this.header = header;
            this.rinfo = rinfo;
            this.ranges = ranges;
            this.objectCounts = objectCounts || [];
            this.debugCounters = debugCounters;
   
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
                `Ver: ${this.header.version_string.trim()}`,
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
            if (!this.detailsBox || !this.header || !this.rinfo) return;

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

            const debugCounters = this.debugCounters;

            const debugCountersSection = debugCounters ? [
                '',
                'Debug Counters:',
                `Database Size: ${formatBytes(debugCounters.dbKBTotal * 1024)}`,  // Convert KiB to bytes
                `Ledger DB: ${formatBytes(debugCounters.dbKBLedger * 1024)}`,    // Convert KiB to bytes
                `Transaction DB: ${formatBytes(debugCounters.dbKBTransaction * 1024)}`, // Convert KiB to bytes
                `Local Transactions: ${debugCounters.localTxCount.toLocaleString()}`,
                `Write Load: ${debugCounters.writeLoad}`,
                `Historical Per Minute: ${debugCounters.historicalPerMinute}`,
                '',
                'Cache Statistics:',
                `SLE Hit Rate: ${formatHitRate(debugCounters.sleHitRate / 1000)}`,      // Convert to percentage
                `Ledger Hit Rate: ${formatHitRate(debugCounters.ledgerHitRate / 100000)}`, // Convert to percentage
                `AL Size: ${debugCounters.alSize}`,
                `AL Hit Rate: ${formatHitRate(debugCounters.alHitRate / 100000)}`,        // Convert to percentage
                `Fullbelow Size: ${debugCounters.fullbelowSize.toLocaleString()}`,
                `Treenode Cache Size: ${debugCounters.treenodeCacheSize.toLocaleString()}`,
                `Treenode Track Size: ${debugCounters.treenodeTrackSize.toLocaleString()}`,
                '',
                'Node Statistics:',
                `Node Reads Total: ${debugCounters.nodeFetchCount.toLocaleString()}`,
                `Node Read Hits: ${debugCounters.nodeFetchHitCount.toLocaleString()}`,
                `Node Read Bytes: ${formatBytes(debugCounters.nodeFetchSize)}`,
                `Node Writes: ${debugCounters.nodeWriteCount.toLocaleString()}`,
                `Node Written Bytes: ${formatBytes(debugCounters.nodeWriteSize)}`,
                '',
                'Memory Objects:',
                `STObject Count: ${debugCounters.ripple_STObject || 0}`,
                `STArray Count: ${debugCounters.ripple_STArray || 0}`,
                `STAmount Count: ${debugCounters.ripple_STAmount || 0}`,
                `STLedgerEntry Count: ${debugCounters.ripple_STLedgerEntry || 0}`,
                `STTx Count: ${debugCounters.ripple_STTx || 0}`,
                `STValidation Count: ${debugCounters.ripple_STValidation || 0}`,
                '',
                'SHAMap Objects:',
                `Account State Leaf Nodes: ${debugCounters.ripple_SHAMapAccountStateLeafNode || 0}`,
                `Inner Nodes: ${debugCounters.ripple_SHAMapInnerNode || 0}`,
                `Items: ${debugCounters.ripple_SHAMapItem || 0}`,
                `Tx Leaf Nodes: ${debugCounters.ripple_SHAMapTxLeafNode || 0}`,
                `Tx Plus Meta Leaf Nodes: ${debugCounters.ripple_SHAMapTxPlusMetaLeafNode || 0}`,
                '',
                'Other Objects:',
                `Accepted Ledger: ${debugCounters.ripple_AcceptedLedger || 0}`,
                `Accepted LedgerTx: ${debugCounters.ripple_AcceptedLedgerTx || 0}`,
                `HashRouter Entries: ${debugCounters.ripple_HashRouter_Entry || 0}`,
                `Inbound Ledger: ${debugCounters.ripple_InboundLedger || 0}`,
                `Ledger: ${debugCounters.ripple_Ledger || 0}`,
                `Transaction: ${debugCounters.ripple_Transaction || 0}`,
                '',
                'Thread Stats:',
                `Read Queue Size: ${debugCounters.read_queue || 0}`,
                `Read Request Bundle: ${debugCounters.read_request_bundle || 0}`,
                `Read Threads Running: ${debugCounters.read_threads_running || 0}`,
                `Read Threads Total: ${debugCounters.read_threads_total || 0}`
            ].join('\n') : '\nDebug Counters: Not available';            

            const objectCountsSection = [
                '',
                'Object Counts:',
                ...(this.objectCounts && this.objectCounts.length > 0
                    ? this.objectCounts.map(({name, count}) => 
                        `${name}: ${count.toLocaleString()}`)
                    : ['No object counts available'])
            ].join('\n');

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
                `Initial Sync Time: ${formatDuration(Number(this.header.initial_sync_us))}`,
                debugCountersSection,
                objectCountsSection
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
//            if (msg.length < HEADER_SIZE) {
//                console.debug(`Packet too small: ${msg.length} bytes (minimum ${HEADER_SIZE} required)`);
//                return;
//            }

            const header = parseServerInfoHeader(msg);
            const serverKey = header.node_public_key;
            const ranges = parseLedgerRanges(msg, header);
            const debugCounters = parseDebugCounters(msg);
            const objectCounts = parseObjectCounts(msg, header);
        
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
                card.update(header, rinfo, ranges, objectCounts, debugCounters);
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
