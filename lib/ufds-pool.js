/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Joyent, Inc.
 */

module.exports = createUfdsPool;

var mod_stream = require('stream');
var mod_util = require('util');
var mod_assert = require('assert-plus');
var mod_bunyan = require('bunyan');
var mod_sshpk = require('sshpk');
var mod_qs = require('querystring');
var EventEmitter = require('events').EventEmitter;

var mod_cueball = require('cueball');
var mod_ldapjs = require('ldapjs');

function createUfdsPool(opts) {
	mod_assert.object(opts, 'options');

	mod_assert.optionalObject(opts.log, 'options.log');
	var log = opts.log ||
	    mod_bunyan.createLogger({name: 'ufds-terror-alert'});
	log = log.child({component: 'UfdsPool'});

	mod_assert.object(opts.config, 'options.config');
	var conf = opts.config;

	var fp = mod_sshpk.parseFingerprint(conf.ufds_key_fp);

	var poolOpts = {};
	poolOpts.resolvers = [conf.binder_domain];
	poolOpts.domain = conf.ufds_domain;
	poolOpts.service = '_ldap._tcp';
	poolOpts.defaultPort = 636;
	poolOpts.spares = opts.ufds_connections || 2;
	poolOpts.maximum = 10;
	poolOpts.log = log;
	poolOpts.recovery = {
		default: {
			timeout: 2000,
			retries: 5,
			delay: 250,
			maxDelay: 1000
		}
	};

	poolOpts.constructor = function (backend) {
		var client = mod_ldapjs.createClient({
			url: 'ldaps://' + backend.address + ':' + backend.port,
			log: log,
			queueDisable: true,
			reconnect: false,
			tlsOptions: conf.ufds_tls_options
		});
		client.on('setup', function (cl, cb) {
			var pc = client._socket.getPeerCertificate();
			var cert = mod_sshpk.parseCertificate(pc.raw, 'x509');
			var key = cert.subjectKey;
			if (!fp.matches(key)) {
				opts.notifier.ufdsKeyMismatch(fp, key);
				cb(new Error('UFDS key does not match config ' +
				    '(their fp = ' +
				    key.fingerprint().toString() + ')'));
				return;
			}
			cl.bind(conf.ufds_bind_dn, conf.ufds_bind_pw, cb);
		});
		client.ref = function () {
			return (this._socket.ref());
		};
		client.unref = function () {
			return (this._socket.unref());
		};
		return (client);
	};

	var pool = new mod_cueball.ConnectionPool(poolOpts);

	return (pool);
}
