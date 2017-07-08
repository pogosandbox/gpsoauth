const querystring = require('querystring');
const url = require('url');
const crypto = require('crypto');
const request = require('request');
const nodeRSA = require("node-rsa");
const ursa = require("ursa");

var AUTH_URL = 'https://android.clients.google.com/auth';

var USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 5.1.1; Andromax I56D2G Build/LMY47V';

/**
 * Parse the values
 * @param {*} body 
 */
function parseKeyValues(body) {
    var obj = {};
    body.split("\n").forEach(function (line) {
        var pos = line.indexOf("=");
        if (pos > 0) obj[line.substr(0, pos)] = line.substr(pos + 1);
    });
    return obj;
};

/**
 * Generates a signature to be passed into GPS
 */
function generateSignature(email, password) {
    let googleDefaultPublicKey  = 'AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==';
    let keyBuffer = Buffer.from(googleDefaultPublicKey, 'base64');
    
    let sha = crypto.createHash('sha1');
    sha.update(keyBuffer);

    let hash = sha.digest().slice(0, 4);

    let modLength = keyBuffer.readUInt32BE(0);
    let mod = keyBuffer.slice(4, 4 + modLength);
    
    let expLength = keyBuffer.readUInt32BE(4 + modLength);
    let exp = keyBuffer.slice(8 + modLength, 8 + modLength + expLength);

    let pem = ursa
        .createPublicKeyFromComponents(mod, exp)
        .toPublicPem()
        .toString();

    let rsa = new nodeRSA(pem);
    let encrypted = rsa.encrypt(email + '\x00' + password);
    
    let base64Output = Buffer.concat([
        Buffer.from([0]),
        hash,
        encrypted
    ]).toString('base64');

    base64Output = base64Output.replace(/\+/g, '-');
    base64Output = base64Output.replace(/\//g, '_');

    return base64Output;
}

/**
 * New instance
 */
var GoogleOauth = function() {
    this.request = request.defaults({
        headers: {
            'User-Agent': USER_AGENT,
        },
        encoding: 'utf8',
    });
};

/**
 * Holds the proxy for this session
 */
GoogleOauth.prototype.setProxy = function(proxy) {
    this.request = this.request.defaults({
        proxy: proxy,
    });
};

/**
 * OAuth against your application
 */
GoogleOauth.prototype.oauth = function (email, master_token, android_id, service, app, client_sig, callback) {
    var data = {
        accountType: "HOSTED_OR_GOOGLE",
        Email: email,
        EncryptedPasswd: master_token,
        has_permission: 1,
        service: service,
        source: "android",
        androidId: android_id,
        app: app,
        client_sig: client_sig,
        device_country: "us",
        operatorCountry: "us",
        lang: "en",
        sdk_version: "17"
    };

    this.request.post({
        url: AUTH_URL,
        form: data,
    }, function(err, response, body) {
        callback(err, err ? null : parseKeyValues(body));
    });
};

/**
 * Logs the user in. If it fails, falls back to a secure login
 */
GoogleOauth.prototype.login = function (email, password, android_id, callback) {
    var _this = this;
    
    var data = {
        accountType: "HOSTED_OR_GOOGLE",
        Email: email.trim(),
        has_permission: "1",
        add_account: "1",
        Passwd: password,
        service: "ac2dm",
        source: "android",
        androidId: android_id,
        device_country: "us",
        operatorCountry: "us",
        lang: "en",
        sdk_version: "17"
    };

    this.request.post({
        url: AUTH_URL,
        form: data,
    }, function(err, response, body) {
        
        if(err || body.indexOf("Error") > -1) {
            _this.loginForProtected(email, password, android_id, function(err, response) {
                callback(err, response);
            })
        } else {
            const content = parseKeyValues(body);
            callback(err, {androidId: android_id, masterToken: content.Token});
        }
    });
};

/**
 * Secure login
 */
GoogleOauth.prototype.loginForProtected = function(username, password, android_id, callback) {
    var data = {
        "Email": username,
        "EncryptedPasswd":  generateSignature(username, password),
        "accountType": "HOSTED_OR_GOOGLE",
        "add_account": "1",
        "androidId": android_id,
        "device_country": "us",
        "has_permission": "1",
        "lang": "en",
        "operatorCountry": "us",
        "sdk_version": "17",
        "service": "ac2dm",
        "source": "android"
    };

    this.request.post({
        url: AUTH_URL,
        form: data,
    }, function(err, response, body) {
        
        if(err) {
            callback(err);
        } else {
            const content = parseKeyValues(body);
            callback(err, {androidId: android_id, masterToken: content.Token});
        }
    });
}

module.exports = exports = GoogleOauth;
