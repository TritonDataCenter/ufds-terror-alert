#!/usr/bin/env node
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent, Inc.
 */

var mod_fs = require('fs');
var mod_dashdash = require('dashdash');
var mod_path = require('path');
var mod_cproc = require('child_process');
var mod_crypto = require('crypto');
var mod_secrets = require('secrets.js');

var options = [
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
	console.error('writeyubikey: error: %s', e.message);
	process.exit(1);
}

if (opts.help || (!opts.secret)) {
	var help = parser.help({}).trimRight();
	console.error('writeyubikey: write an HMAC secret to a yubikey');
	console.error('usage: ./writeyubikey -s piece1,piece2[,...]\n');
	console.error(help);
	process.exit(1);
}


var parts = opts.secret.split(',');
if (parts.length > 1) {
	opts.secret = mod_secrets.combine(parts);
}
opts.secret = new Buffer(opts.secret, 'hex');

var args = ['-2', '-a' + opts.secret.toString('hex'), '-ochal-resp',
    '-ochal-hmac', '-ochal-btn-trig', '-ohmac-lt64', '-y'];
kid = mod_cproc.spawnSync('ykpersonalize', args);
if (kid.status !== 0) {
	console.error('writeyubikey: failed to write to yubikey:');
	console.error(kid.stderr.toString('ascii'));
	process.exit(1);
} else {
	console.error('writeyubikey: wrote to yubikey slot 2');
	process.exit(0);
}
