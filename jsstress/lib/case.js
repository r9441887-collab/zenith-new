var path = require('path');
var b64 = require('base64');

exports.upper = function(s) { return s.toUpperCase(); };
exports.lower = function(s) { return s.toLowerCase(); };
exports.title = function(s) {
    var out = '';
    var up = true;
    var i;
    for (i = 0; i < s.length; i = i + 1) {
        var ch = s[i];
        if (ch == ' ') { out = out + ' '; up = true; }
        else if (up) { out = out + ch.toUpperCase(); up = false; }
        else { out = out + ch; }
    }
    return out;
};
exports.basename = function(p) { return path.basename(p); };
exports.tag = function(s) { return b64.encode(s); };
