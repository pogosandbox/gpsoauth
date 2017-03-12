const querystring = require('querystring');
const url = require('url');
const CryptoJS = require("crypto-js");
const crypto = require('crypto');
const request = require('request');

var AUTH_URL = 'https://android.clients.google.com/auth';

var USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 5.1.1; Andromax I56D2G Build/LMY47V';

var oauthUtil = {};
oauthUtil.parseKeyValues = function (body) {
    var obj = {};
    body.split("\n").forEach(function (line) {
        var pos = line.indexOf("=");
        if (pos > 0) obj[line.substr(0, pos)] = line.substr(pos + 1);
    });
    return obj;
};
oauthUtil.Base64 = {
    _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    stringify: CryptoJS.enc.Base64.stringify,
    parse: CryptoJS.enc.Base64.parse
};
oauthUtil.salt = function (len) {
    return Array.apply(0, Array(len)).map(function () {
        return (function (charset) {
            return charset.charAt(Math.floor(Math.random() * charset.length));
        }('abcdefghijklmnopqrstuvwxyz0123456789'));
    }).join('');
};

var GoogleOauth = function () {
    this.request = request.defaults({
        headers: {
            'User-Agent': USER_AGENT,
        },
        encoding: 'utf8',
    });
};

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
        callback(err, err ? null : oauthUtil.parseKeyValues(data));
    });
};

GoogleOauth.prototype.login = function (email, password, android_id, callback) {
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
        let content = oauthUtil.parseKeyValues(data);
        callback(err, err ? null : {androidId: android_id, masterToken: content.Token});
    });
};

module.exports = exports = GoogleOauth;
