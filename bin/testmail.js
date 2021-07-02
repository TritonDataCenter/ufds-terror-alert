#!/usr/bin/env node
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2021 Joyent, Inc.
 */

var mod_fs = require('fs');
var mod_path = require('path');

var mod_mailer = require('nodemailer');

var configFile = mod_path.join(__dirname, '../etc', 'config.json');
var config = JSON.parse(mod_fs.readFileSync(configFile).toString('utf-8'));

var message = {
    from: config.my_email,
    to: config.operators[0],
    subject: config.oper_prefix + ' Test Notification',
    text: 'Test message for ' + config.cloud_name
};

console.log('Mail config:');
console.log(JSON.stringify(config.smtp, null, 2));

var mailer = mod_mailer.createTransport(config.smtp);
mailer.sendMail(message, function (err, info) {
    if (err) {
        console.log('Error sending mail: ');
        console.log(JSON.stringify(err, null, 2));
    } else {
        console.log('Message successfully sent: ');
        console.log(JSON.stringify(info, null, 2));
    }
    return 0;
});
