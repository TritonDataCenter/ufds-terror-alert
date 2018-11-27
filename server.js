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

var log = mod_bunyan.createLogger({
	name: 'ufds-terror-alert',
	level: 'debug'
});

try {
	mod_fs.statSync(config.sqlite_db);
} catch (ex) {
	log.error('database not found. db must be initialized using ' +
	    'bin/initlog.js');
	process.exit(1);
}

var db = new mod_sqlite.Database(config.sqlite_db);

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
			log.error('database not initialized. please use the ' +
			    'bin/initlog.js tool first');
			process.exit(1);
		} else {
			cb();
		}
	});
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
			    'operator integer, reader integer, ' +
			    'status text)', cb);
		} else if (!rows[0].sql.match(/\breader\s*integer\b/)) {
			log.info('database: upgrading schema for table users');
			log.warn('you will need to manually set the "reader"' +
			    ' flag on any read-only operators that already ' +
			    'exist');
			db.run('alter table users add column ' +
			    'reader integer default 0', cb);
		} else if (!rows[0].sql.match(/\bstatus\s*text\b/)) {
			log.info('database: upgrading schema for table users');
			log.warn('you will need to manually set the "status"' +
			    ' field on any disabled accounts that already ' +
			    'exist');
			db.run('alter table users add column ' +
			    'status text default "active"', cb);
		} else if (!rows[0].sql.match(/\broleoper\s*integer\b/)) {
			log.info('database: upgrading schema for table users');
			log.warn('you will need to manually set the "roleoper"' +
			    ' flag on any role-operators that already ' +
			    'exist');
			db.run('alter table users add column ' +
			    'roleoper integer default 0', cb);
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
