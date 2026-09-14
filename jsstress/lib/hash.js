var su = require('./strutil');
var m = require('./math');
var data = require('./data');
var zu = require('zenutils');

console.log('[hash] module loaded via nested require');

exports.compute = function(s) {
    var e = su.count(s, 'e');
    var sp = su.count(s, ' ');
    var base = su.basename('/jsstress/lib/hash.js');
    var words = s.split(' ');
    var h = m.sumTo(words.length);
    var i;
    for (i = 0; i < words.length; i = i + 1) {
        h = m.mix(h, words[i].length);
    }
    if (m.isPrime(e)) h = h + 1000;
    if (m.isPrime(sp)) h = h + 2000;
    h = h + base.length + sp;
    if (!data.roundtrip(s)) h = h + 999999;
    if (zu.say(s) != s.toUpperCase()) h = h + 888888;
    return h;
};
