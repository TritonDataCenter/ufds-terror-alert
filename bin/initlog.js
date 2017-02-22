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
var mod_sqlite = require('sqlite3').verbose();
var mod_readline = require('readline');

var options = [
	{
		names: ['config', 'f'],
		type: 'string',
		help: 'Path to config file. Default etc/config.json'
	},
	{
		names: ['pieces', 'p'],
		type: 'number',
		help: 'Number of pieces to break the key into. Default 3.'
	},
	{
		names: ['required', 'r'],
		type: 'number',
		help: 'Number of pieces required to recover the key. Default 2.'
	},
	{
		names: ['gpg-keys', 'k'],
		type: 'string',
		help: 'List of GPG recipients to encrypt pieces to, ' +
		    'comma-separated. Requires "gpg2" on PATH.'
	},
	{
		names: ['yubikey', 'y'],
		type: 'bool',
		help: 'Write the secret key to a Yubikey in slot #2'
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
	console.error('initlog: error: %s', e.message);
	process.exit(1);
}

if (opts.help) {
	var help = parser.help({}).trimRight();
	console.error('initlog: set up initial hash chain secret');
	console.error('usage: ./initlog [options]\n');
	console.error(help);
	process.exit(1);
}

if (opts.pieces === undefined)
	opts.pieces = 3;
if (opts.required === undefined)
	opts.required = 2;

var keys;
if (opts.gpg_keys !== undefined) {
	keys = opts.gpg_keys.split(',');
	if (keys.length !== opts.pieces) {
		console.error('initlog: requested %d pieces but only gave %d ' +
		    'GPG keys', opts.pieces, keys.length);
		process.exit(1);
	}
}

var configFile = opts.config;
if (configFile === undefined)
	configFile = mod_path.join(__dirname, '..', 'etc', 'config.json');
var config = JSON.parse(mod_fs.readFileSync(configFile).toString('utf-8'));

var dbPath = config.sqlite_db;
if (dbPath.charAt(0) !== '/')
	dbPath = mod_path.join(__dirname, '..', dbPath);
var db = new mod_sqlite.Database(dbPath);

var stmt = db.prepare(
    'select name, sql from sqlite_master where type = ? and name = ?');

stmt.all('table', 'metadata', function (err, rows) {
	if (err) {
		console.error(err.stack);
		process.exit(1);
	}
	if (rows.length < 1) {
		console.error('initlog: everything looks ok');
		console.error('initlog: using %d/%d secret sharing',
		    opts.required, opts.pieces);
		var rl = mod_readline.createInterface({
			input: process.stdin,
			output: process.stderr
		});
		console.error('Please confirm:');
		console.error('You wish to initialize a new UFDS signed ' +
		    'changelog and output the split secret key to this ' +
		    'console.')
		rl.question('Is that correct? [y/n] ',
		    function (response) {
			if (response !== 'y') {
				process.exit(1);
			}
			rl.close();
			db.run('create table metadata (' +
			    'key text primary key, value text)',
			    doInitialSecret);
		});
	} else {
		console.error('initlog: database already initialized');
		console.error('cowardly refusing to do anything');
		process.exit(1);
	}
});

function doInitialSecret() {
	var secret = mod_crypto.randomBytes(20);

	var shares = mod_secrets.share(secret.toString('hex'), opts.pieces,
	    opts.required);
	if (keys !== undefined) {
		for (var i = 0; i < shares.length; ++i) {
			var share = shares[i];
			var key = keys[i];
			var kid = mod_cproc.spawnSync('gpg2',
			    ['-k', key]);
			if (kid.status !== 0) {
				console.error('initlog: failed to find ' +
				    'pubkey for recipient "%s":', key);
				console.error(kid.stderr.toString('ascii'));
				process.exit(1);
			}
			var text = kid.stdout.toString('ascii');
			shares[i] = text + '\n';

			kid = mod_cproc.spawnSync('gpg2',
			    ['-e', '-a', '-r', key],
			    { input: share + '\n' });
			if (kid.status !== 0) {
				console.error('initlog: failed to encrypt ' +
				    'for recipient "%s":', key);
				console.error(kid.stderr.toString('ascii'));
				process.exit(1);
			}
			text = kid.stdout.toString('ascii');
			shares[i] += text;
		}
	}

	var challenge = mod_crypto.randomBytes(32);
	var ins = db.prepare('insert into metadata (key, value) values ' +
	    '(?, ?)');
	var h = mod_crypto.createHmac('sha1', secret);
	h.update(challenge);

	var qs = 0;
	ins.run('challenge', challenge.toString('base64'), doneQ);
	ins.run('secret', h.digest().toString('base64'), doneQ);
	ins.run('serial', '-1', doneQ);
	function doneQ() {
		if (++qs >= 3) {
			printIt(secret, shares);
		}
	}

	var initl =
	    JSON.stringify({ challenge: challenge.toString('hex') }) + '\n';
	mod_fs.writeFileSync(config.ufds_log, initl);
}

function printIt(secret, shares) {
	for (var j = 0; j < shares.length; ++j) {
		console.error('=============================================');
		console.error('=====           key piece #%d            =====',
		    j);
		console.error(shares[j]);
		console.error('=============================================');
		console.error('');
	}

	if (opts.yubikey) {
		var args = ['-2', '-a' + secret.toString('hex'), '-ochal-resp',
		    '-ochal-hmac', '-ochal-btn-trig', '-ohmac-lt64', '-y'];
		kid = mod_cproc.spawnSync('ykpersonalize', args);
		if (kid.status !== 0) {
			console.error('WARNING: failed to write to yubikey:');
			console.error(kid.stderr.toString('ascii'));
		} else {
			console.error('initlog: wrote to yubikey slot 2');
		}
		console.error('');
	}

	config.initialSync = true;
	mod_fs.writeFileSync(configFile, JSON.stringify(config, undefined, 4));
	console.error('initlog: wrote config.json file');
	console.error('After initial sync-up is finished, make sure to ' +
	    'remove the "initialSync" property from config.json!');

	process.exit(0);
}
