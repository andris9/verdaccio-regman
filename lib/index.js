'use strict';

const userStorage = require('./user-storage');
const httpError = require('http-errors');

/**
 * Custom Verdaccio Authenticate Plugin.
 */
class AuthRegMan {
    constructor(config, stuff) {
        this.logger = stuff.logger;

        userStorage.dbFile = config.db_file;

        return this;
    }

    logError(err, username) {
        this.logger.warn(`${err.code}, user: ${username}, Error: ${err.message}`);
    }

    /**
     * Authenticate an user.
     * @param user user to log
     * @param password provided password
     * @param cb callback function
     */
    authenticate(user, password, cb) {
        let userData;
        try {
            userData = userStorage.authenticate(user, password);
        } catch (err) {
            this.logError(err, user);
            return cb(httpError(500, 'Internal Server Error'));
        }
        if (!userData) {
            return cb(httpError(401, 'Invalid username or password'));
        }
        return cb(null, [user]);
    }

    adduser(user, password, cb) {
        let userData;
        try {
            userData = userStorage.get(user);
        } catch (err) {
            this.logError(err, user);
            return cb(httpError(500, 'Internal Server Error'));
        }
        if (userData) {
            return cb(null, true);
        }

        return cb(httpError(409, 'User registration via web interface only'));
    }

    /**
     * check grants for such user.
     */
    allow_access(user, pkg, cb) {
        if (pkg.access.includes('$all') || pkg.access.includes('$anonymous')) {
            return cb(null, true);
        }

        if (!user.name) {
            return cb(httpError(403, 'Not allowed to access package'));
        }

        let userData;
        try {
            userData = userStorage.get(user.name);
        } catch (err) {
            this.logError(err, user);
            return cb(httpError(500, 'Internal Server Error'));
        }

        if (userData && (pkg.access.includes(user.name) || pkg.access.includes('$authenticated'))) {
            // allow access for authenticated users only
            return cb(null, true);
        }

        return cb(httpError(403, 'Not allowed to access package'));
    }

    /**
     * check grants to publish
     */
    allow_publish(user, pkg, cb) {
        if (pkg.publish.includes('$all') || pkg.publish.includes('$anonymous')) {
            return cb(null, true);
        }

        if (!user.name) {
            return cb(httpError(403, 'not allowed to publish package'));
        }

        let userData;
        try {
            userData = userStorage.get(user.name);
        } catch (err) {
            this.logError(err, user);
            return cb(httpError(500, 'Internal Server Error'));
        }

        if (!userData) {
            return cb(httpError(403, 'Not allowed to publish package'));
        }

        if (userData.tags.includes('admin') || userData.tags.includes('publish')) {
            return cb(null, true);
        }

        return cb(httpError(403, 'Not allowed to publish package'));
    }
}

module.exports = (config, stuff) => new AuthRegMan(config, stuff);
