/* npm demo: real libraries on the embedded engine.
   Deterministic output for diffing against node. */
var ms = require('ms');
var Papa = require('papaparse');
var semver = require('semver');
var marked = require('marked');

console.log('ms(2 days)=' + ms('2 days'));
console.log('ms(10h)=' + ms('10h'));
console.log('ms(5m)=' + ms('5m'));
console.log('ms(60000)=' + ms(60000));
console.log('ms(172800000)=' + ms(172800000));

var csv = 'name,age\nAlice,30\nBob,25\n';
var r = Papa.parse(csv);
console.log('csv rows=' + r.data.length);
console.log('csv last=' + r.data[2][0]);
console.log('csv noHeader=' + r.errors.length + ' cols=' + r.data[0].length);

var rh = Papa.parse(csv, { header: true });
console.log('csv header name=' + rh.data[0].name + ' age=' + rh.data[0].age);

var u = Papa.unparse([['a', 'b'], [1, 2]]);
console.log('unparse=[' + u + ']');

var rs = Papa.parse('1;2;3\n4;5;6', { delimiter: ';' });
console.log('semi a0=' + rs.data[0][0] + ' rows=' + rs.data.length);

var sf = Papa.parse('x,y\n1,2\n', { dynamicTyping: true });
console.log('dyn type=' + (typeof sf.data[1][0]) + ' val=' + sf.data[1][0]);

console.log('ver valid=' + semver.valid('1.2.3'));
console.log('ver bad=' + semver.valid('not a version'));
console.log('ver gt=' + semver.gt('2.0.0', '1.2.3'));
console.log('ver lt=' + semver.lt('1.2.3', '2.0.0'));
console.log('ver satisf=' + semver.satisfies('1.2.3', '^1.0.0'));
console.log('ver inc patch=' + semver.inc('1.2.3', 'patch'));
console.log('ver inc minor=' + semver.inc('1.2.3', 'minor'));
console.log('ver cmp=' + semver.compare('2.0.0', '1.2.3'));

console.log('md h1=' + marked('# Hello'));
console.log('md bold=' + marked('**bold**'));
console.log('md list=' + marked('- a\n- b'));
console.log('md code=' + marked('```\ncode\n```'));
console.log('md combo=' + marked('# T\n\npara **b** here.'));