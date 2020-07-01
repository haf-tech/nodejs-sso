/* ******************************
 * ShowCase: Nodejs and SSO (OpenID)
 *
 * ******************************
*/

const promClient = require('prom-client');
const promBundle = require("express-prom-bundle");
const express = require('express');
const logger = require('morgan');
const axios = require('axios');


// OpenID, WebApp support
const passport = require('passport');
const WebAppStrategy = require('ibmcloud-appid').WebAppStrategy;
 

// *** Prometheus 
// include HTTP method and URL path into the labels
const metricsMiddleware = promBundle({includeMethod: true, includePath: true});

// Initialize
var app = express();


app.use(logger('dev'));
app.use(metricsMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));


const counterUserAgent = new promClient.Counter({name: 'http_request_blueprint_nodejs_user_agent_total', help: 'Blueprint Nodejs: User Agents', labelNames: ['ua']});


// ############# Application configuration
app.set('port', (process.env.PORT || 5000))
app.set('ip', (process.env.IP || '0.0.0.0'))

// ############# OAuth configuration

// Below URLs will be used for App ID OAuth flows
const LANDING_PAGE_URL = "/";
const LOGIN_URL = "/ibm/bluemix/appid/login";
const CALLBACK_URL = "/ibm/bluemix/appid/callback";
const LOGOUT_URL = "/ibm/bluemix/appid/logout";

app.use(passport.initialize());
app.use(passport.session());


const ssoProviderUrl = process.env.OAUTH_URL;
const ssoSecret = process.env.CLIENT_SECRET;
const ssoClientId = process.env.CLIENT_ID;
const ssoTenantId = process.env.TENANT_ID;
const sspAppBaseUrl = process.env.REDIRECT_URL;

passport.use(new WebAppStrategy({
  tenantId: ssoTenantId,
  clientId: ssoClientId,
  secret: ssoSecret,
  oauthServerUrl: ssoProviderUrl,
  redirectUri: sspAppBaseUrl + CALLBACK_URL
}));

// Configure passportjs with user serialization/deserialization. This is required
// for authenticated session persistence across HTTP requests. See passportjs docs
// for additional information http://passportjs.org/docs
passport.serializeUser(function(user, cb) {
  cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
  cb(null, obj);
});

// Explicit login endpoint. Will always redirect browser to login widget due to {forceLogin: true}. If forceLogin is set to false the redirect to login widget will not occur if user is already authenticated
app.get(LOGIN_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
  successRedirect: LANDING_PAGE_URL,
  forceLogin: true
}));

// Callback to finish the authorization process. Will retrieve access and identity tokens/
// from App ID service and redirect to either (in below order)
// 1. the original URL of the request that triggered authentication, as persisted in HTTP session under WebAppStrategy.ORIGINAL_URL key.
// 2. successRedirect as specified in passport.authenticate(name, {successRedirect: "...."}) invocation
// 3. application root ("/")
app.get(CALLBACK_URL, passport.authenticate(WebAppStrategy.STRATEGY_NAME));

// Logout endpoint. Clears authentication information from session
app.get(LOGOUT_URL, function(req, res){
  WebAppStrategy.logout(req);
  res.redirect(LANDING_PAGE_URL);
});

// Protected area. If current user is not authenticated - redirect to the login widget will be returned.
// In case user is authenticated - a page with current user information will be returned.
app.get("/protected", passport.authenticate(WebAppStrategy.STRATEGY_NAME), function(req, res){
  res.json(req.user);
});


// ############# Utilities
const sleep = (waitTimeInMs) => new Promise(resolve => setTimeout(resolve, waitTimeInMs));

// ############# Entry points
app.get('/', (req, res) => {
  
    var userAgent = req.get('User-Agent');
    var ret = "Hello you! " + userAgent;    
    console.log('user-agent: ' + userAgent);
  
    // Prometheus Metric: inc and set the user agent
    counterUserAgent.labels(userAgent).inc();
  
    res.send(ret);    
});


app.listen(app.get('port'), app.get('ip'), function() {


    console.log("Node app is running at localhost:" + app.get('port'))
  })

module.exports = app;