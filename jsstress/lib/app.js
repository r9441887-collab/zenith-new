var hash = require('./hash');
var su = require('./strutil');
var m = require('./math');
var data = require('./data');

exports.compute = hash.compute;
exports.upper = su.upper;
exports.title = su.title;
exports.basename = su.basename;
exports.count = su.count;
exports.fib = m.fib;
exports.isPrime = m.isPrime;
exports.encode = data.encode;
exports.decode = data.decode;
exports.readLen = data.readLen;
exports.exists = data.exists;
exports.roundtrip = data.roundtrip;
