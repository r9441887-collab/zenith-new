var b64 = require('base64');
var fs = require('fs');
var path = require('path');

exports.encode = b64.encode;
exports.decode = b64.decode;
exports.joinPath = function(a, b) { return path.join(a, b); };
exports.exists = function(p) { return fs.existsSync(p); };
exports.readLen = function(p) { return fs.existsSync(p) ? fs.readFileSync(p).length : -1; };
exports.roundtrip = function(body) {
    var enc = b64.encode(body);
    var dec = b64.decode(enc);
    return dec == body;
};
