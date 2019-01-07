'use strict';

const userStorage = require('./user-storage');
const httpError = require('http-errors');
const Gelf = require('gelf');
const os = require('os');

/**
 * Custom Verdaccio Authenticate Plugin.
 */
class AuthRegMan {
    constructor(config, stuff) {
        this.logger = stuff.logger;

        userStorage.dbFile = config.db_file;

        const facility = (config.gelf && config.gelf.facility) || 'verdaccio';
        const hostname = (config.gelf && config.gelf.hostname) || os.hostname();
        const gelf =
            config.gelf && config.gelf.enabled
                ? new Gelf(config.gelf.options)
                : {
                      // placeholder
                      emit: () => false
                  };

        this.loggelf = message => {
            if (typeof message === 'string') {
                message = {
                    short_message: message
                };
            }
            message = message || {};
            message.facility = facility;
            message.host = hostname;
            message.timestamp = Date.now() / 1000;

            Object.keys(message).forEach(key => {
                if (!message[key]) {
                    delete message[key];
                }
            });
            gelf.emit('gelf.log', message);
        };

        return this;
    }

    logError(err, username) {
        this.loggelf({
            short_message: 'Verdaccio Auth Error',
            full_message: err.stack,
            _code: err.code,
            _username: username
        });
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
            this.loggelf({
                short_message: 'Verdaccio Auth Failed',
                _action: 'authfail',
                _method: 'authenticate',
                _username: user
            });
            let err = httpError(401, 'Invalid username or password');
            return cb(err);
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
            this.loggelf({
                short_message: 'Verdaccio Auth Success',
                _action: 'authok',
                _username: user
            });

            return cb(null, true);
        }

        this.loggelf({
            short_message: 'Verdaccio Auth Failed',
            _action: 'authfail',
            _method: 'adduser',
            _username: user
        });

        return cb(httpError(409, 'User registration via web interface only'));
    }

    /**
     * check grants for such user.
     */
    allow_access(user, pkg, cb) {
        if (pkg.access.includes('$all') || pkg.access.includes('$anonymous')) {
            this.loggelf({
                short_message: 'Verdaccio Access Success',
                _action: 'access',
                _scope: 'all',
                _username: user && user.name
            });
            return cb(null, true);
        }

        if (!user.name) {
            this.loggelf({
                short_message: 'Verdaccio Access Failed',
                _action: 'accessfail',
                _scope: 'all',
                _username: user && user.name
            });
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
            this.loggelf({
                short_message: 'Verdaccio Access Success',
                _action: 'access',
                _scope: 'authenticated',
                _username: user && user.name
            });
            return cb(null, true);
        }

        this.loggelf({
            short_message: 'Verdaccio Access Failed',
            _action: 'accessfail',
            _scope: 'authenticated',
            _username: user && user.name
        });

        return cb(httpError(403, 'Not allowed to access package'));
    }

    /**
     * check grants to publish
     */
    allow_publish(user, pkg, cb) {
        if (pkg.publish.includes('$all') || pkg.publish.includes('$anonymous')) {
            this.loggelf({
                short_message: 'Verdaccio Publish Success',
                _action: 'publish',
                _scope: 'all',
                _username: user && user.name
            });
            return cb(null, true);
        }

        if (!user.name) {
            this.loggelf({
                short_message: 'Verdaccio Publish Failed',
                _action: 'publishfail',
                _scope: 'all',
                _username: user && user.name
            });
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
            this.loggelf({
                short_message: 'Verdaccio Publish Failed',
                _action: 'publish',
                _scope: 'authenticated',
                _username: user && user.name
            });
            return cb(httpError(403, 'Not allowed to publish package'));
        }

        if (userData.tags.includes('admin') || userData.tags.includes('publish')) {
            this.loggelf({
                short_message: 'Verdaccio Publish Success',
                _action: 'publish',
                _scope: 'authenticated',
                _username: user && user.name
            });
            return cb(null, true);
        }

        this.loggelf({
            short_message: 'Verdaccio Publish Failed',
            _action: 'publish',
            _scope: 'authenticated',
            _tags: userData.tags.join(','),
            _username: user && user.name
        });

        return cb(httpError(403, 'Not allowed to publish package'));
    }
}

module.exports = (config, stuff) => new AuthRegMan(config, stuff);
