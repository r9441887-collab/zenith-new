module.exports = function isPrime(n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    var i = 3;
    while (i * i <= n) {
        if (n % i == 0) return 0;
        i = i + 2;
    }
    return 1;
};
