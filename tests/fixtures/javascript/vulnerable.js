const child_process = require('child_process');

function handlePayload(untrustedInput) {
    const result = eval("(" + untrustedInput + ")");
    child_process.exec("ping -c 1 " + untrustedInput);
    return result;
}
