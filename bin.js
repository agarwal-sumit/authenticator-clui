#!/usr/bin/env node

'use strict';

const { program } = require('commander');

const authenticator = require('./src/lib');
const PasswordPrompt = require('./src/PasswordPrompt');
const passwordPrompt = new PasswordPrompt({ promptMsg: "Enter password: " });

program
	.name("authenticator")
	.usage("A simple command-line authenticator (import accounts from Google Authenticator, Microsoft Authenticator and Facebook Authenticator)")
	.option('-i, --import <import otpauth-migration url>', 'Import account(s), Authenticator exported accounts URI like "otpauth-migration://offline?data=xyz" make sure URI in "double quotes" (Use QR reader to get this from export QR code)')
	.option('-en, --encrypt', 'Encrypt your imported account with AES256 encryption using a strong password')
	.option('-d, --delete', 'Delete imported accounts !!!Can\'t restore')
	.option('-f, --force', 'Forcefully execute operations')
	.option('-r, --run', 'Run authenticator with imported accounts')
	.option('-m, --min', 'Minimal Output')
	.option('-s, --service <name>', 'Name of the service you want the token for')
	.parse(process.argv);

const processOpts = async (options) => {
	let password = "";
	if (options && Object.keys(options).length) {

		if (options.import) {
			if (authenticator.accounts.isValidBackupFile()) {
				console.error("🚫 Accounts already exist, delete existing accounts before import");
				return program.help({ error: true });
			}
			if (options.encrypt) {
				password = await passwordPrompt.start();
			};
			return authenticator.accounts.seed(options.import, password);
		}

		if (!options.force) {
			if (!authenticator.accounts.isValidBackupFile()) {
				console.error("❌ Accounts does not exist");
				return program.help({ error: true });
			}
			if (authenticator.accounts.isEncrypted()) {
				password = await passwordPrompt.start();
			};
			if (!authenticator.accounts.isValid(password)) {
				if (password) {
					return console.error("🚫 Invalid password. Please try again.");
				}
				console.error("❌ Account(s) are not valid.");
				return program.help({ error: true });
			}
		}

		if (options.delete) {
			return authenticator.accounts.flushAll();
		}

		if (options.run) {
			if (options.force) {
				console.error("🚫 Can't run with --force");
				return program.help({ error: true });
			}
			if (options.service) {
				return authenticator.getByService(options.service, password, options.min)
			}
			return authenticator.run(password);
		}
	} else {
		program.help({ error: true });
	};
}

processOpts(program.opts())
