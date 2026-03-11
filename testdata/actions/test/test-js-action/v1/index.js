const greeting = process.env.INPUT_GREETING || 'Hello from JS action';
console.log(`::notice::${greeting}`);

// Write output using GITHUB_OUTPUT file
const fs = require('fs');
const outputFile = process.env.GITHUB_OUTPUT;
if (outputFile) {
  fs.appendFileSync(outputFile, `result=${greeting}\n`);
}

// Create a file to prove execution happened
fs.writeFileSync('/tmp/js-action-executed', 'true');
console.log('JS action executed successfully');
