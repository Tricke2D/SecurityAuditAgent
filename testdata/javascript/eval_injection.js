// ❌ VULNERABLE: eval dengan input user
function executeUserCode(userInput) {
    eval(userInput);
}

// ❌ VULNERABLE: exec dengan string
function runCommand(command) {
    const { exec } = require('child_process');
    exec(command);
}

// ❌ VULNERABLE: Function constructor
function createFunction(code) {
    return new Function(code);
}

// ✅ SAFE: eval tidak digunakan
function safeOperation(data) {
    return JSON.parse(data);
}