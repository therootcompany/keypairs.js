'use strict';

var Keypairs = require('../');

/* global Promise*/
Keypairs.parseOrGenerate({ key: null })
	.then(function(pair) {
		// should NOT have any warning output
		if (!pair.private || !pair.public) {
			throw new Error('missing key pairs');
		}

		return Promise.all([
			// Testing Public Part of key
			Keypairs.export({ jwk: pair.public }).then(function(pem) {
				if (!/--BEGIN PUBLIC/.test(pem)) {
					throw new Error('did not export public pem');
				}
				return Promise.all([
					Keypairs.parse({ key: pem }).then(function(pair) {
						if (pair.private) {
							throw new Error("shouldn't have private part");
						}
						return true;
					}),
					Keypairs.parse({ key: pem, private: true })
						.then(function() {
							var err = new Error(
								'should have thrown an error when private key was required and public pem was given'
							);
							err.code = 'NOERR';
							throw err;
						})
						.catch(function(e) {
							if ('NOERR' === e.code) {
								throw e;
							}
							return true;
						})
				]).then(function() {
					return true;
				});
			}),
			// Testing Private Part of Key
			Keypairs.export({ jwk: pair.private }).then(function(pem) {
				if (!/--BEGIN .*PRIVATE KEY--/.test(pem)) {
					throw new Error('did not export private pem: ' + pem);
				}
				return Promise.all([
					Keypairs.parse({ key: pem }).then(function(pair) {
						if (!pair.private) {
							throw new Error('should have private part');
						}
						if (!pair.public) {
							throw new Error('should have public part also');
						}
						return true;
					}),
					Keypairs.parse({ key: pem, public: true }).then(function(
						pair
					) {
						if (pair.private) {
							throw new Error('should NOT have private part');
						}
						if (!pair.public) {
							throw new Error(
								'should have the public part though'
							);
						}
						return true;
					})
				]).then(function() {
					return true;
				});
			}),
			Keypairs.parseOrGenerate({ key: 'not a key', public: true }).then(
				function(pair) {
					// SHOULD have warning output
					if (!pair.private || !pair.public) {
						throw new Error(
							"missing key pairs (should ignore 'public')"
						);
					}
					if (!pair.parseError) {
						throw new Error(
							'should pass parseError for malformed string'
						);
					}
					return true;
				}
			),
			Keypairs.parse({ key: JSON.stringify(pair.private) }).then(function(
				pair
			) {
				if (!pair.private || !pair.public) {
					throw new Error('missing key pairs (stringified jwt)');
				}
				return true;
			}),
			Keypairs.parse({
				key: JSON.stringify(pair.private),
				public: true
			}).then(function(pair) {
				if (pair.private) {
					throw new Error("has private key when it shouldn't");
				}
				if (!pair.public) {
					throw new Error("doesn't have public key when it should");
				}
				return true;
			}),
			Keypairs.parse({ key: JSON.stringify(pair.public), private: true })
				.then(function() {
					var err = new Error(
						'should have thrown an error when private key was required and public jwk was given'
					);
					err.code = 'NOERR';
					throw err;
				})
				.catch(function(e) {
					if ('NOERR' === e.code) {
						throw e;
					}
					return true;
				}),
			Keypairs.signJwt({
				jwk: pair.private,
				// Note: using ES512 won't actually increase the length
				// (it would be truncated to fit into the key size)
				alg: 'ES256',
				iss: 'https://example.com/',
				exp: '1h'
			}).then(function(jwt) {
				var parts = jwt.split('.');
				var now = Math.round(Date.now() / 1000);
				var token = {
					header: JSON.parse(Buffer.from(parts[0], 'base64')),
					payload: JSON.parse(Buffer.from(parts[1], 'base64')),
					signature: parts[2] //Buffer.from(parts[2], 'base64')
				};
				// allow some leeway just in case we happen to hit a 1ms boundary
				if (token.payload.exp - now > 60 * 59.99) {
					return true;
				}
				throw new Error('token was not properly generated');
			})
		]).then(function(results) {
			if (
				results.length &&
				results.every(function(v) {
					return true === v;
				})
			) {
				console.log('PASS');
				process.exit(0);
			} else {
				throw new Error("didn't get all passes (but no errors either)");
			}
		});
	})
	.catch(function(e) {
		console.error('Caught an unexpected (failing) error:');
		console.error(e);
		process.exit(1);
	});
