const querystring = require('querystring');
const url = require('url');
const crypto = require('crypto');
const request = require('request');
const nodeRSA = require("node-rsa");

let AUTH_URL = 'https://android.clients.google.com/auth';

let USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 5.1.1; Andromax I56D2G Build/LMY47V';

/**
 * Parse the values
 * @param {*} body 
 */
function parseKeyValues(body) {
    let obj = {};
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

    let pem = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKJv9Wv79JW5TtlG67etCdoHLl
0pYxhUF4HMmVr3lixMKOqa8IIt4iSGXaHcoSmUKzVqeZyid7K0V3FFvhdQQ922hF
RnJhIKmi2VDQY5tOe6SkSNepAdGKaXhseaiEOUIys7EfBE0GyizVoEWNEETVc9+J
DCUdz/y4B2sf+q5n+QIDAQAB
-----END PUBLIC KEY-----`;

    let sha = crypto.createHash('sha1');
    sha.update(keyBuffer);

    let hash = sha.digest().slice(0, 4);

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
let GoogleOauth = function() {
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
    let data = {
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
GoogleOauth.prototype.loginWithPassword = function (email, password, android_id, callback) {
    let self = this;
    
    let data = {
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
        if(err) {
            callback(err);
        } else {
            const content = parseKeyValues(body);
            callback(err, {androidId: android_id, masterToken: content.Token});
        }
    });
};

/**
 * Secure login
 */
GoogleOauth.prototype.login = function(username, password, android_id, callback) {
    let data = {
        "Email": username,
        "EncryptedPasswd": generateSignature(username, password),
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
