/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Joyent, Inc.
 */

var mod_fs = require('fs');
var mod_path = require('path');
var mod_sqlite = require('sqlite3').verbose();
var mod_vasync = require('vasync');
var mod_crypto = require('crypto');
var mod_bunyan = require('bunyan');
var mod_mailer = require('nodemailer');

var Notifier = require('./lib/notifier');
var createUfdsPool = require('./lib/ufds-pool');
var UfdsWatcher = require('./lib/ufds-watcher');

var configFile = mod_path.join(__dirname, 'etc', 'config.json');
var config = JSON.parse(mod_fs.readFileSync(configFile).toString('utf-8'));

var db = new mod_sqlite.Database(config.sqlite_db);

var log = mod_bunyan.createLogger({
	name: 'ufds-terror-alert',
	level: 'debug'
});

var initsec = mod_path.join(__dirname, 'etc', 'initialsecret');

try {
	mod_fs.statSync(initsec);
	throw (new Error('Initial secret file must be removed'));
} catch (ex) {
	if (ex.code !== 'ENOENT') {
		throw (new Error('Initial secret file must be removed'));
	}
}

var stmt = db.prepare(
    'select name, sql from sqlite_master where type = ? and name = ?');

mod_vasync.pipeline({
	funcs: [
		checkCreateMetadata, checkCreateUsers, checkCreateKeys
	]
}, function (err) {
	if (err)
		throw (err);
	stmt.finalize();

	var opts = {
		config: config,
		db: db,
		log: log
	};
	opts.mailer = mod_mailer.createTransport(config.smtp);
	opts.notifier = new Notifier(opts);
	opts.ufdsPool = createUfdsPool(opts);
	opts.watcher = new UfdsWatcher(opts);

	setInterval(function () {
		opts.watcher.check();
	}, 1000);
});

function checkCreateMetadata(_, cb) {
	stmt.all('table', 'metadata', function (err, rows) {
		if (err) {
			cb(err);
			return;
		}
		if (rows.length < 1) {
			log.info('initializing database: add table metadata');
			db.run('create table metadata (' +
			    'key text primary key, value text)', function () {
				doInitialSecret(cb);
			});
		} else {
			cb();
		}
	});
}

function doInitialSecret(cb) {
	log.info('initializing database: generating root secret');
	var secret = mod_crypto.randomBytes(20);
	var challenge = mod_crypto.randomBytes(32);
	var ins = db.prepare('insert into metadata (key, value) values ' +
	    '(?, ?)');
	var h = mod_crypto.createHmac('sha1', secret);
	h.update(challenge);
	ins.run('challenge', challenge.toString('base64'));
	ins.run('secret', h.digest().toString('base64'));
	ins.run('serial', '-1');
	mod_fs.writeFileSync(initsec, secret.toString('hex') + '\n');
	var initl =
	    JSON.stringify({ challenge: challenge.toString('hex') }) + '\n';
	mod_fs.writeFileSync(config.ufds_log, initl);
	log.warn('ufds log root secret written out to %s: please copy this ' +
	    'value to offline storage and delete this file now', initsec);
	var int = setInterval(function () {
		try {
			mod_fs.statSync(initsec);
		} catch (ex) {
			if (ex.code === 'ENOENT') {
				clearInterval(int);
				config.initialSync = true;
				cb();
			}
		}
	}, 1000);
}

function checkCreateUsers(_, cb) {
	stmt.all('table', 'users', function (err, rows) {
		if (err) {
			cb(err);
			return;
		}
		if (rows.length < 1) {
			log.info('initializing database: add table users');
			db.run('create table users (' +
			    'uuid text primary key, login text, ' +
			    'userpassword text, email text, ' +
			    'operator integer, reader integer)', cb);
		} else if (!rows[0].sql.match(/\breader\s*integer\b/)) {
			log.info('database: upgrading schema for table users');
			log.warn('you will need to manually set the "reader"' +
			    ' flag on any read-only operators that already ' +
			    'exist');
			db.run('alter table users add column ' +
			    'reader integer default 0', cb);
		} else {
			cb();
		}
	});
}

function checkCreateKeys(_, cb) {
	stmt.all('table', 'keys', function (err, rows) {
		if (err) {
			cb(err);
			return;
		}
		if (rows.length < 1) {
			log.info('initializing database: add table keys');
			db.run('create table keys (' +
			    'uuid text, fingerprint text,' +
			    'name text, comment text, ' +
			    'primary key (uuid, fingerprint))', cb);
		} else {
			cb();
		}
	});
}
