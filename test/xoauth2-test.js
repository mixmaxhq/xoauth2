'use strict';

var chai = require('chai');
var expect = chai.expect;
chai.Assertion.includeStack = true;

var xoauth2 = require('../src/xoauth2');
var mockServer = require('./server');

describe('XOAuth2 tests', function() {
    this.timeout(10000);

    var server;
    var users = {};
    var XOAUTH_PORT = 8993;

    beforeEach(function(done) {
        server = mockServer({
            port: XOAUTH_PORT,
            onUpdate: function(username, accessToken, idToken) {
                users[username] = { accessToken, idToken };
            }
        });
        server.addUser('test@example.com', 'saladus');
        server.addUser('userwithoutidtoken@example.com', 'noidtoken');
        server.start(done);
    });

    afterEach(function(done) {
        server.stop(done);
    });

    it('should get an existing access token', function(done) {
        var xoauth2gen = xoauth2.createXOAuth2Generator({
            user: 'test@example.com',
            clientId: '{Client ID}',
            clientSecret: '{Client Secret}',
            refreshToken: 'saladus',
            accessUrl: 'http://localhost:' + XOAUTH_PORT + '/',
            accessToken: 'abc',
            timeout: 3600
        });

        xoauth2gen.getToken(function(err, token, accessToken) {
            expect(err).to.not.exist;
            expect(accessToken).to.equal('abc');
            done();
        });
    });

    it('should get an existing access token, no timeout', function(done) {
        var xoauth2gen = xoauth2.createXOAuth2Generator({
            user: 'test@example.com',
            clientId: '{Client ID}',
            clientSecret: '{Client Secret}',
            refreshToken: 'saladus',
            accessUrl: 'http://localhost:' + XOAUTH_PORT + '/',
            accessToken: 'abc'
        });

        xoauth2gen.getToken(function(err, token, accessToken) {
            expect(err).to.not.exist;
            expect(accessToken).to.equal('abc');
            done();
        });
    });

    it('should generate a fresh access token', function(done) {
        var xoauth2gen = xoauth2.createXOAuth2Generator({
            user: 'test@example.com',
            clientId: '{Client ID}',
            clientSecret: '{Client Secret}',
            refreshToken: 'saladus',
            accessUrl: 'http://localhost:' + XOAUTH_PORT + '/',
            timeout: 3600
        });

        xoauth2gen.getToken(function(err, token, accessToken) {
            expect(err).to.not.exist;
            expect(accessToken).to.equal(users['test@example.com'].accessToken);
            done();
        });
    });

    it('should generate a fresh access token after timeout', function(done) {
        var xoauth2gen = xoauth2.createXOAuth2Generator({
            user: 'test@example.com',
            clientId: '{Client ID}',
            clientSecret: '{Client Secret}',
            refreshToken: 'saladus',
            accessUrl: 'http://localhost:' + XOAUTH_PORT + '/',
            accessToken: 'abc',
            timeout: 1
        });

        setTimeout(function() {
            xoauth2gen.getToken(function(err, token, accessToken) {
                expect(err).to.not.exist;
                expect(accessToken).to.equal(users['test@example.com'].accessToken);
                done();
            });
        }, 3000);
    });

    it('should emit both access and id token updates', function(done) {
        var xoauth2gen = xoauth2.createXOAuth2Generator({
            user: 'test@example.com',
            clientId: '{Client ID}',
            clientSecret: '{Client Secret}',
            refreshToken: 'saladus',
            accessUrl: 'http://localhost:' + XOAUTH_PORT + '/',
            timeout: 3600
        });

        xoauth2gen.once('token', function(tokenData) {
            expect(tokenData).to.deep.equal({
                user: 'test@example.com',
                accessToken: users['test@example.com'].accessToken,
                timeout: 3600,
                idToken: users['test@example.com'].idToken
            });
            done();
        });

        xoauth2gen.getToken(function() {});
    });

    it('should emit a fallback if the id token isn\'t returned', function(done) {
        var xoauth2gen = xoauth2.createXOAuth2Generator({
            user: 'userwithoutidtoken@example.com',
            clientId: '{Client ID}',
            clientSecret: '{Client Secret}',
            refreshToken: 'noidtoken',
            accessUrl: 'http://localhost:' + XOAUTH_PORT + '/',
            timeout: 3600
        });

        xoauth2gen.once('token', function(tokenData) {
            expect(tokenData).to.deep.equal({
                user: 'userwithoutidtoken@example.com',
                accessToken: users['userwithoutidtoken@example.com'].accessToken,
                timeout: 3600,
                idToken: ''
            });
            done();
        });

        xoauth2gen.getToken(function() {});
    });
});
