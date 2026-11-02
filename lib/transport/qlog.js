'use strict';

const { EventEmitter } = require('node:events');
class QLog extends EventEmitter {
	constructor({ odcid = null, groupId = null, version = 'draft-29', maxEvents = 10000 } = {}) {
		super();
		this.maxEvents = Math.max(100, Number(maxEvents) || 10000);
		this.events = [];
		this.start = process.hrtime.bigint();
		this.odcid = odcid ? Buffer.from(odcid).toString('hex') : null;
		this.groupId = groupId || null;
		this.version = String(version);
	}
	add(name, data = {}) {
		if(this.events.length >= this.maxEvents) this.events.shift();
		const us = Number(process.hrtime.bigint() - this.start) / 1000;
		const ev = {
			time: us,
			name: String(name),
			data: data || {}
		};
		this.events.push(ev);
		this.emit('event', ev);
		return ev;
	}
	packet(direction, packetType, packetNumber, extra = {}) {
		return this.add(direction === 'tx' ? 'transport:packet_sent' : 'transport:packet_received', {
			header: {
				packet_type: packetType,
				packet_number: packetNumber === undefined ? undefined : String(packetNumber),
				...extra
			}
		});
	}
	toJSON() {
		return {
			qlog_version: '0.4',
			title: 'XOF QUIC',
			traces: [{
				vantage_point: {
					type: 'transport'
				},
				common_fields: {
					protocol_type: 'QUIC',
					ODCID: this.odcid,
					group_id: this.groupId,
					version: this.version
				},
				events: this.events
			}]
		};
	}
	stringify() {
		return JSON.stringify(this.toJSON(), null, 2);
	}
	clear() {
		this.events.length = 0;
	}
}

function createQLog(options) {
	return new QLog(options);
}

module.exports = {
	QLog,
	createQLog
};