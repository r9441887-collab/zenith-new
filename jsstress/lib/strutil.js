var cs = require('./case');

exports.count = function(s, c) {
    var n = 0;
    var i;
    for (i = 0; i < s.length; i = i + 1) {
        if (s[i] == c) n = n + 1;
    }
    return n;
};
exports.upper = cs.upper;
exports.title = cs.title;
exports.basename = cs.basename;
