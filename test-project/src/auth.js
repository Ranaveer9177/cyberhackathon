const jwt = require('jsonwebtoken');
const http = require('http');
const { exec } = require('child_process');

// Hardcoded JWT secret
const JWT_SECRET = 'super-secret-key-do-not-share';
const API_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

// Dangerous eval usage
function processUserInput(input) {
    const result = eval(input);
    return result;
}

// Another dangerous eval
function computeFormula(formula) {
    return new Function('return ' + formula)();
}

// Command injection
function checkServer(hostname) {
    exec('ping -c 4 ' + hostname, (error, stdout) => {
        console.log(stdout);
    });
}

// Insecure HTTP request
function fetchData() {
    return fetch('http://api.payment-gateway.com/process');
}

// Weak crypto
const crypto = require('crypto');
function hashData(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// Disabled TLS verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

module.exports = { processUserInput, checkServer, fetchData, hashData };
