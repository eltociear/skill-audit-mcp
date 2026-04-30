#!/usr/bin/env node
const { execSync } = require('child_process');
const path = require('path');

const cliPath = path.join(__dirname, '..', 'cli.py');
const args = process.argv.slice(2).join(' ');

try {
  execSync(`python3 "${cliPath}" ${args}`, { stdio: 'inherit' });
} catch (e) {
  process.exit(e.status || 1);
}
