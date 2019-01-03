'use strict';

const crypto = require('crypto');
const fs = require('fs');

const userStorage = {
    dbFile: 'users.json',
    load() {
        let db;
        try {
            db = fs.readFileSync(this.dbFile, 'utf-8');
        } catch (err) {
            let newErr = new Error('Failed to load database file (diagnostics code: ' + err.code + ')');
            newErr.code = err.code;
            throw newErr;
        }

        try {
            db = JSON.parse(db);
        } catch (err) {
            let newErr = new Error('Invalid database file, please fix manually');
            newErr.code = err.code;
            throw newErr;
        }

        return db;
    },

    get(username) {
        const db = this.load();
        let userData = db[username];
        if (!userData) {
            return false;
        }
        userData.username = username;
        userData.tags = [].concat(userData.tags || []);
        return userData;
    },

    authenticate(username, password) {
        const db = this.load();

        if (!db.hasOwnProperty(username)) {
            return false;
        }

        let userData = db[username];
        if (!userData.enabled || !userData.password) {
            return false;
        }

        let parts = userData.password.split('$');
        let salt = Buffer.from(parts[2], 'base64');
        let hash = parts[3];

        if (crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('base64') !== hash) {
            return false;
        }

        userData.username = username;
        return userData;
    }
};

module.exports = userStorage;
