'use strict';

const fs = require('node:fs');
const { QUICServer, QUICClient } = require('../lib/transport');

const testcase = process.env.TESTCASE || 'handshake';
const role = (process.env.ROLE || 'server').toLowerCase();
const cert = process.env.CERT || '/certs/cert.pem';
const key = process.env.KEY || '/certs/priv.key';
const hasCert = fs.existsSync(cert) && fs.existsSync(key);
const supported = new Set(['handshake', 'transfer', 'retry', 'multi_connect', 'datagram', 'key_update']);
if(!supported.has(testcase)) process.exit(127);

function load(file) {
	return fs.existsSync(file) ? file : undefined;
}

async function server() {
	const server = new QUICServer({
		host: process.env.HOST || '0.0.0.0',
		port: Number(process.env.PORT || 4433),
		cert: hasCert ? load(cert) : undefined,
		key: hasCert ? load(key) : undefined,
		noPsk: hasCert,
		alpn: process.env.ALPN || 'hq-interop',
		qlog: process.env.QLOGDIR ? {
			directory: process.env.QLOGDIR
		} : false
	});
	server.on('error', error => console.error(error));
	server.on('connection', connection => {
		connection.on('data', data => {
			if(testcase === 'transfer') connection.write(data, {
				streamId: 0n
			});
		});
		if(testcase === 'datagram') connection.on('datagram', d => {
			try {
				connection.sendDatagram(d);
			} catch {}
		});
		if(testcase === 'key_update') {
			connection.once('ready', () => {
				setTimeout(() => {
					try {
						connection.updateKeys();
					} catch {}
				}, 50);
			});
		}
	});
	
	await server.listen();
	console.log(JSON.stringify({
		ready: true,
		address: server.addressInfo,
		testcase
	}));
}

async function client() {
		const client = new QUICClient({
			host: process.env.SERVER_ADDR || 'server',
			port: Number(process.env.SERVER_PORT || 4433),
			alpn: process.env.ALPN || 'hq-interop',
			servername: process.env.SERVER_NAME || 'server',
			ca: load('/certs/cert.pem'),
			noPsk: hasCert,
			qlog: process.env.QLOGDIR ? {
				directory: process.env.QLOGDIR
			} : false
		});
		client.on('error', error => console.error(error));
		const connection = await client.connect();
		if(testcase === 'transfer') {
			const stream = connection.openStream();
			stream.end(Buffer.from('xof-interop\n'));
		}
		if(testcase === 'datagram') {
			try {
				connection.sendDatagram(Buffer.from('xof-dgram'));
			} catch {}
		}
		if(testcase === 'key_update') {
			setTimeout(() => {
				try {
					connection.updateKeys();
				} catch {}
			}, 50);
		}
	}
	
	(role === 'client' ? client : server)().catch(error => {
		console.error(error.stack || error);
		process.exit(1);
	});