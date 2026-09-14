var isPrime = require('./prime');

exports.isPrime = isPrime;
exports.fib = function(n) { if (n < 2) return n; return exports.fib(n - 1) + exports.fib(n - 2); };
exports.sumTo = function(n) {
    var s = 0;
    var i;
    for (i = 1; i <= n; i = i + 1) s = s + i;
    return s;
};
exports.mix = function(a, b) { return a * 31 + b; };
