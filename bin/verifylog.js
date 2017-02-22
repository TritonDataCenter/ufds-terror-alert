#!/usr/bin/env node
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent, Inc.
 */

var mod_fs = require('fs');
var mod_byline = require('byline');
var mod_dashdash = require('dashdash');
var mod_path = require('path');
var mod_cproc = require('child_process');
var mod_crypto = require('crypto');
var mod_secrets = require('secrets.js');

var options = [
	{
		names: ['yubikey', 'y'],
		type: 'bool',
		help: 'Use secret from yubikey'
	},
	{
		names: ['secret', 's'],
		type: 'string',
		help: 'Supply secret as hex string, or comma-separated pieces'
	},
	{
		names: ['help', 'h'],
		type: 'bool',
		help: 'Shows this help text'
	}
];

if (require.main !== module)
	return;

var parser = mod_dashdash.createParser({ options: options });

try {
	var opts = parser.parse(process.argv);
} catch (e) {
	console.error('verifylog: error: %s', e.message);
	process.exit(1);
}

if (opts.help || opts._args.length !== 1 || (!opts.yubikey && !opts.secret)) {
	var help = parser.help({}).trimRight();
	console.error('verifylog: verify a hash-chain signed UFDS log');
	console.error('usage: ./verifylog [options] ufds_log.jsonl\n');
	console.error(help);
	console.error('one of the --yubikey|-y or --secret|-s options must ' +
	    'be supplied');
	process.exit(1);
}

var logFile = opts._args[0];
var log = mod_fs.createReadStream(logFile, { encoding: 'utf-8' });
var linest = new mod_byline.LineStream();
linest.encoding = 'utf-8';
log.pipe(linest);

var challenge, secret, psecret, phmac, lineno = 1;

if (opts.secret) {
	var parts = opts.secret.split(',');
	if (parts.length > 1) {
		opts.secret = mod_secrets.combine(parts);
	}
	opts.secret = new Buffer(opts.secret, 'hex');
}

linest.on('readable', readMore);
linest.on('end', function () {
	console.error('Log validated ok');
	process.exit(0);
});

function readMore() {
	var line;
	while ((line = linest.read()) !== null) {
		var obj = JSON.parse(line);
		if (secret === undefined && challenge === undefined) {
			challenge = new Buffer(obj.challenge, 'hex');
			if (opts.secret) {
				var h = mod_crypto.createHmac('sha1',
				    opts.secret);
				h.update(challenge);
				secret = h.digest();
			} else if (opts.yubikey) {
				var args = ['-2', '-H', '-x'];
				args.push(challenge.toString('hex'));
				console.error('If YubiKey is flashing, ' +
				    'please press the button');
				var copts = {};
				copts.stdio = ['pipe', 'pipe', 'inherit'];
				var res = mod_cproc.spawnSync('ykchalresp',
				    args, copts);
				if (res.status !== 0)
					process.exit(1);
				var out = res.stdout.toString('ascii').trim();
				secret = new Buffer(out, 'hex');
			}
		} else {
			verifyLogEntry(obj);
		}
		++lineno;
	}
}

function nextSecret(sec) {
	var h = mod_crypto.createHash('sha1');
	h.update(sec);
	return (h.digest());
}

function verifyLogEntry(obj) {
	var step = 0, valid = false;

	var hmac = obj.hmac;
	var ourHmac;
	delete (obj.hmac);
	var blob = new Buffer(JSON.stringify(obj), 'utf-8');

	var h = mod_crypto.createHmac('sha256', secret);
	h.update(blob);
	ourHmac = h.digest().toString('base64');
	valid = (ourHmac == hmac);

	if (!valid && psecret !== undefined) {
		var h = mod_crypto.createHmac('sha256', psecret);
		h.update(blob);
		ourHmac = h.digest().toString('base64');
		if (ourHmac == hmac) {
			if (phmac === hmac)
				return;
			console.error('WARNING: re-used hash chain value for ' +
			    'non-matching entries at line %d', lineno);
			return;
		}
	}

	psecret = secret;
	secret = nextSecret(secret);
	++step;

	while (step < 5 && !valid) {
		var h = mod_crypto.createHmac('sha256', secret);
		h.update(blob);
		ourHmac = h.digest().toString('base64');
		valid = (ourHmac == hmac);
		psecret = secret;
		secret = nextSecret(secret);
		++step;
	}

	if (!valid) {
		console.error('Line %d failed verification:', lineno);
		console.error(obj);
		console.error('Included HMAC   = %s', hmac);
		console.error('Calculated HMAC = %s (at step %d)', ourHmac,
		    step);
		process.exit(1);
	}

	if (step > 1) {
		console.error('WARNING: entry appears to have been elided ' +
		    'between lines %d and %d', lineno - 1, lineno);
	}
	phmac = hmac;
}
