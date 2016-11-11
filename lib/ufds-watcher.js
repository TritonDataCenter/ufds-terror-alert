/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Joyent, Inc.
 */

module.exports = UfdsWatcher;

var mod_stream = require('stream');
var mod_util = require('util');
var mod_assert = require('assert-plus');
var mod_bunyan = require('bunyan');
var mod_crypto = require('crypto');
var mod_sshpk = require('sshpk');
var mod_qs = require('querystring');
var mod_fs = require('fs');
var mod_path = require('path');
var mod_vasync = require('vasync');
var EventEmitter = require('events').EventEmitter;

var mod_ldapjs = require('ldapjs');

function UfdsWatcher(opts) {
	mod_assert.object(opts, 'options');

	mod_assert.object(opts.config, 'options.config');
	mod_assert.object(opts.ufdsPool, 'options.ufdsPool');

	mod_assert.optionalObject(opts.log, 'options.log');
	var log = opts.log || mod_bunyan.createLogger({
	    name: 'ufds-terror-alert' });
	this.log = log.child({component: 'UfdsWatcher'});

	this.logfile = opts.config.ufds_log;
	mod_assert.string(this.logfile, 'config.ufds_log');

	this.pool = opts.ufdsPool;
	this.config = opts.config;

	mod_assert.object(opts.notifier, 'options.notifier');
	this.notifier = opts.notifier;

	mod_assert.object(opts.db, 'options.db');
	this.db = opts.db;
	this.inCheck = false;

	this.updatePending = false;
}

UfdsWatcher.prototype.check = function () {
	if (this.inCheck)
		return;
	this.inCheck = true;

	var self = this;
	var meta = this.db.prepare('select value from metadata where key = ?');
	var state = {};

	mod_vasync.pipeline({
		funcs: [getSerial, ufdsWatcherClaim, search, scheduleUpdate],
		arg: state
	}, function (err) {
		if (err)
			self.log.warn(err, 'failed to check for UFDS update');
		if (state.handle)
			state.handle.release();
		meta.finalize();
		self.inCheck = false;
	});

	function getSerial(_, cb) {
		meta.get('serial', function (err, row) {
			if (err) {
				cb(err);
				return;
			}
			if (row !== undefined) {
				_.serial = parseInt(row.value, 10);
			} else {
				_.serial = -1;
			}
			cb();
		});
	}

	function ufdsWatcherClaim(_, cb) {
		self.pool.claim(function (err, handle, ufds) {
			if (err) {
				cb(err);
				return;
			}
			_.handle = handle;
			_.ufds = ufds;
			cb();
		});
	}

	function search(_, cb) {
		var gotBase = false;
		var base = 'cn=changelog';
		var opts = {
			scope: 'one',
			filter: new mod_ldapjs.filters.GreaterThanEqualsFilter({
				attribute: 'changenumber',
				value: _.serial.toString()
			}),
			sizeLimit: 2,
			attributes: ['changenumber']
		};
		self.log.trace('beginning search');
		_.ufds.search(base, opts, function (err, res) {
			if (err) {
				cb(err);
				return;
			}
			res.on('searchEntry', function (ent) {
				var es = ent.attributes.filter(function (attr) {
					return (attr.type === 'changenumber');
				});
				mod_assert.strictEqual(es.length, 1);
				var serial = parseInt(es[0].vals[0], 10);
				if (serial > _.serial) {
					_.newSerial = true;
				} else if (serial === _.serial) {
					gotBase = true;
				}
			});
			res.once('end', function () {
				var e;
				if (!gotBase &&
				    !(_.serial === -1 && _.newSerial)) {
					e = new Error('Failed to receive ' +
					    'current serial');
				}
				cb(e);
			});
			res.once('error', function (err2) {
				cb(err2);
			});
		});
	}

	function scheduleUpdate(_, cb) {
		if (_.newSerial) {
			if (!self.updatePending) {
				self.updatePending = true;
				self.log.info('updating serial from %d',
				    _.serial);
				setImmediate(function () {
					self.update(_.serial);
				});
			}
		} else {
			if (self.config.initialSync) {
				self.log.info('initial sync-up complete, ' +
				    'will begin to send email now');
				delete (self.config.initialSync);
			}
		}
		cb();
	}
};

UfdsWatcher.prototype.update = function (serial) {
	var self = this;

	var meta = this.db.prepare(
	    'select value from metadata where key = ?');
	var metaset = this.db.prepare(
	    'update metadata set value = ? where key = ?');

	var q = mod_vasync.queue(processEntry, 1);

	var base = 'cn=changelog';
	var flts = [];
	flts.push(new mod_ldapjs.filters.GreaterThanEqualsFilter({
		attribute: 'changenumber',
		value: serial.toString()
	}));
	var opts = {
		scope: 'one',
		filter: new mod_ldapjs.filters.AndFilter({
			filters: flts
		}),
		sizeLimit: 2000
	};
	this.pool.claim(function (err, handle, ufds) {
		if (err) {
			self.log.error(err, 'failed to claim UFDS client');
			q.close();
			return;
		}

		ufds.search(base, opts, function (err2, res) {
			if (err2) {
				handle.release();
				self.log.error(err2, 'UFDS query failed');
				q.close();
				return;
			}

			res.on('searchEntry', function (ent) {
				q.push(ent);
			});
			res.once('end', function () {
				handle.release();
				q.close();
			});
			res.once('error', function (err3) {
				self.log.error(err3, 'UFDS query failed');
				handle.release();
				q.close();
			});
		});
	});
	q.on('end', function () {
		meta.finalize();
		metaset.finalize();
		self.updatePending = false;
	});
	function processEntry(ent, cb) {
		var logentry = {};
		ent.attributes.forEach(function (attr) {
			mod_assert.strictEqual(logentry[attr.type], undefined);
			mod_assert.equal(attr.vals.length, 1);
			logentry[attr.type] = attr.vals[0];
		});
		mod_assert.string(logentry.targetdn, 'logentry.targetdn');
		mod_assert.string(logentry.changetype, 'logentry.changetype');
		mod_assert.strictEqual(logentry.objectclass, 'changeLogEntry');
		mod_assert.string(logentry.changetime, 'changetime');
		mod_assert.optionalString(logentry.entry, 'entry');
		mod_assert.string(logentry.changenumber, 'changenumber');
		mod_assert.string(logentry.changes, 'changes');

		logentry.changenumber = parseInt(logentry.changenumber, 10);
		if (logentry.changenumber <= serial) {
			cb();
			return;
		}

		logentry.changes = JSON.parse(logentry.changes);
		if (logentry.entry !== undefined)
			logentry.entry = JSON.parse(logentry.entry);

		var changes = logentry.changes;
		if (logentry.changetype === 'add') {
			mod_assert.strictEqual(logentry.entry, undefined);
			mod_assert.object(changes, 'changes');
		} else if (logentry.changetype === 'modify') {
			mod_assert.object(logentry.entry, 'entry');
			mod_assert.arrayOfObject(changes, 'changes');
		} else if (logentry.changetype === 'delete') {
			mod_assert.strictEqual(logentry.entry, undefined);
			mod_assert.object(changes, 'changes');
		} else {
			throw (new Error('Unrecognized change type: ' +
			    logentry.changetype));
		}

		mod_vasync.pipeline({
			funcs: [
				openTx,
				signLogEntry, writeLogEntry, updateSerial,
				commitTx,
				updateUsers, updateKeys, updateOperators
			],
			arg: logentry
		}, function (err) {
			if (err) {
				self.log.error({err: err, entry: logentry},
				    'failed to process changelog entry');
				self.db.run('rollback', cb);
				return;
			}
			if (!self.config.initialSync ||
			    logentry.changenumber % 500 === 0) {
				self.log.debug({serial: logentry.changenumber},
				    'processed changelog entry');
			}
			cb();
		});
	}
	function openTx(ent, cb) {
		self.db.run('begin transaction', cb);
	}
	function signLogEntry(ent, cb) {
		meta.get('secret', function (err, row) {
			if (err) {
				cb(err);
				return;
			}

			var secret = new Buffer(row.value, 'base64');
			var h = mod_crypto.createHash('sha1');
			h.update(secret);
			var newSecret = h.digest();

			metaset.run(newSecret.toString('base64'), 'secret',
			    function (err2) {
				if (err2) {
					cb(err2);
					return;
				}
				if (this.changes !== 1) {
					cb(new Error('Did not update secret'));
					return;
				}

				h = mod_crypto.createHmac('sha256', secret);
				var b = new Buffer(
				    JSON.stringify(ent), 'utf-8');
				h.update(b);
				ent.hmac = h.digest().toString('base64');
				cb();
			});
		});
	}
	function writeLogEntry(ent, cb) {
		mod_fs.open(self.logfile, 'a', 0x180, function (err, fd) {
			if (err) {
				cb(err);
				return;
			}
			var b = new Buffer(JSON.stringify(ent) + '\n', 'utf-8');
			mod_fs.write(fd, b, 0, b.length, null,
			    function (err2, written) {
				if (!err2 && written < b.length)
					err2 = new Error('Short write');
				if (err2) {
					cb(err2);
					return;
				}
				mod_fs.fsync(fd, function (err3) {
					if (err3) {
						cb(err3);
						return;
					}
					mod_fs.close(fd, cb);
				});
			});
		});
	}
	function updateSerial(ent, cb) {
		metaset.run(ent.changenumber.toString(), 'serial', cb);
	}
	function commitTx(ent, cb) {
		self.db.run('commit', cb);
	}
	function updateUsers(ent, cb) {
		var dn = mod_ldapjs.parseDN(ent.targetdn);
		var r = dn.pop();
		mod_assert.strictEqual(r.attrs.o.value, 'smartdc');
		r = dn.pop();
		if (!r || !r.attrs.ou || r.attrs.ou.value !== 'users') {
			cb();
			return;
		}
		r = dn.pop();
		if (!r || !r.attrs.uuid) {
			cb();
			return;
		}
		var uuid = r.attrs.uuid.value;
		if (dn.pop()) {
			cb();
			return;
		}

		self.db.get('select uuid, login, userpassword, email, ' +
		    'operator from users where uuid = ?', uuid,
		    function (err, row) {
			if (err) {
				cb(err);
				return;
			}
			if (row === undefined && ent.changetype !== 'add') {
				throw (new Error('Got ' + ent.changetype +
				    'change for user ' + uuid + ' which ' +
				    'does not exist'));
			}
			processUserUpdate(uuid, ent, row, cb);
		});
	}
	function processUserUpdate(uuid, ent, row, cb) {
		switch (ent.changetype) {
		case 'add':
			mod_assert.ok(
			    ent.changes.objectclass.indexOf('sdcperson') !== -1,
			    'entry is for a user but missing objectclass');
			self.db.run('insert into users values (?, ?, ?, ?, ?)',
			    uuid, ent.changes.login[0],
			    ent.changes.userpassword[0],
			    ent.changes.email[0], 0, cb);
			break;
		case 'modify':
			var sets = [];
			var vals = [];
			ent.changes.forEach(function (ch) {
				var mod = ch.modification;
				mod_assert.object(mod, 'modification');
				if (ch.operation !== 'add' &&
				    ch.operation !== 'replace') {
					return;
				}
				switch (mod.type) {
				case 'login':
					mod_assert.equal(mod.vals.length, 1);
					if (row.login === mod.vals[0])
						break;
					self.notifier.changedLogin(
					    ent.changetime, uuid, row.login,
					    mod.vals[0], row.email);
					sets.push('login = ?');
					vals.push(mod.vals[0]);
					break;
				case 'userpassword':
					mod_assert.equal(mod.vals.length, 1);
					if (row.userpassword === mod.vals[0])
						break;
					self.notifier.changedPassword(
					    ent.changetime, uuid, row.email);
					sets.push('userpassword = ?');
					vals.push(mod.vals[0]);
					break;
				case 'email':
					mod_assert.equal(mod.vals.length, 1);
					if (row.email === mod.vals[0])
						break;
					self.notifier.changedEmail(
					    ent.changetime, uuid, row.email,
					    mod.vals[0]);
					sets.push('email = ?');
					vals.push(mod.vals[0]);
					break;
				default:
					/* ignored */
					break;
				}
			});
			if (sets.length < 1) {
				cb();
				return;
			}
			vals.push(uuid);
			vals.push(cb);
			vals.unshift('update users set ' + sets.join(', ') +
			    'where uuid = ?');
			self.db.run.apply(self.db, vals);
			break;
		case 'delete':
			self.notifier.deletedUser(ent.changetime, uuid,
			    row);
			self.db.run('delete from users where uuid = ?',
			    uuid, cb);
			break;
		default:
			throw (new Error('Unknown changetype ' +
			    ent.changetype));
		}
	}
	function updateKeys(ent, cb) {
		var dn = mod_ldapjs.parseDN(ent.targetdn);
		var r = dn.pop();
		mod_assert.strictEqual(r.attrs.o.value, 'smartdc');
		r = dn.pop();
		if (!r || !r.attrs.ou || r.attrs.ou.value !== 'users') {
			cb();
			return;
		}
		r = dn.pop();
		if (!r || !r.attrs.uuid) {
			cb();
			return;
		}
		var uuid = r.attrs.uuid.value;
		r = dn.pop();
		if (!r || !r.attrs.fingerprint) {
			cb();
			return;
		}
		var fp = r.attrs.fingerprint.value;
		if (dn.pop()) {
			cb();
			return;
		}

		if (ent.changes.name) {
			var name = ent.changes.name[0];
			var key = mod_sshpk.parseKey(ent.changes.openssh[0]);
			var comment = key.comment;
		}

		self.db.all('select fingerprint, name, comment from keys ' +
		    'where uuid = ?', uuid, function (err, rows) {
			if (err) {
				cb(err);
				return;
			}
			var keys = {};
			rows.forEach(function (rr) {
				keys[r.fingerprint] = rr;
			});
			if (ent.changetype === 'add') {
				self.notifier.addedKey(ent.changetime, uuid,
				    key, name, keys);
				self.db.run('insert into keys (uuid, ' +
				     'fingerprint, name, comment) values ' +
				     '(?, ?, ?, ?)',
				     uuid, fp, name, comment, cb);
			} else if (ent.changetype === 'delete') {
				self.notifier.deletedKey(ent.changetime, uuid,
				    key, name, keys);
				self.db.run('delete from keys where uuid = ? ' +
				    'and fingerprint = ?', uuid, fp, cb);
			} else {
				throw (new Error('Keys cannot be modified'));
			}
		});
	}
	function updateOperators(ent, cb) {
		var dn = mod_ldapjs.parseDN(ent.targetdn);
		var r = dn.pop();
		mod_assert.strictEqual(r.attrs.o.value, 'smartdc');
		r = dn.pop();
		if (!r || !r.attrs.ou || r.attrs.ou.value !== 'groups') {
			cb();
			return;
		}
		r = dn.pop();
		if (!r || !r.attrs.cn || r.attrs.cn.value !== 'operators') {
			cb();
			return;
		}
		if (dn.pop()) {
			cb();
			return;
		}

		if (ent.changetype === 'add') {
			ent.changes = ent.changes.uniquemember.map(
			    function (udn) {
				return ({ operation: 'add', modification: {
				    type: 'uniquemember', vals: [udn] } });
			});
		} else if (ent.changetype !== 'modify') {
			cb();
			return;
		}

		mod_vasync.forEachPipeline({
			func: doChange,
			inputs: ent.changes
		}, cb);
		function doChange(ch, ccb) {
			var mod = ch.modification;
			var udn, ur, uuid;
			if (ch.operation === 'add' &&
			    mod.type === 'uniquemember') {
				mod_assert.equal(mod.vals.length, 1);
				udn = mod_ldapjs.parseDN(mod.vals[0]);
				ur = udn.pop();
				mod_assert.strictEqual(
				    ur.attrs.o.value, 'smartdc');
				ur = udn.pop();
				mod_assert.strictEqual(
				    ur.attrs.ou.value, 'users');
				ur = udn.pop();
				mod_assert.string(ur.attrs.uuid.value, 'uuid');
				uuid = ur.attrs.uuid.value;
				mod_assert.ok(!udn.pop());
				self.db.get('select operator from users ' +
				    'where uuid = ?', uuid,
				    function (err, row) {
					if (!err && row === undefined) {
						err = new Error('Tried to ' +
						    'add unknown user ' +
						    uuid + ' to operators');
					}
					if (err) {
						ccb(err);
						return;
					}
					if (row.operator !== 1 &&
					    row.operator !== '1') {
						self.notifier.operatorAdded(
						    ent.changetime, uuid);
						self.db.run('update users ' +
						    'set operator = 1 ' +
						    'where uuid = ?', uuid,
						    ccb);
					}
				});
			} else if (ch.operation === 'delete' &&
			    mod.type === 'uniquemember') {
				mod_assert.equal(mod.vals.length, 1);
				udn = mod_ldapjs.parseDN(mod.vals[0]);
				ur = udn.pop();
				mod_assert.strictEqual(
				    ur.attrs.o.value, 'smartdc');
				ur = udn.pop();
				mod_assert.strictEqual(
				    ur.attrs.ou.value, 'users');
				ur = udn.pop();
				mod_assert.string(ur.attrs.uuid.value, 'uuid');
				uuid = ur.attrs.uuid.value;
				mod_assert.ok(!udn.pop());
				self.notifier.operatorRemoved(ent.changetime,
				    uuid);
				self.db.run('update users set operator = 0 ' +
				    'where uuid = ?', uuid, ccb);
			}
		}
	}
};
