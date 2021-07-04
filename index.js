/* ******************************
 * ShowCase: Nodejs and SSO (OpenID)
 *
 * Details and Examples for IBM App ID
 * https://github.com/ibm-cloud-security/appid-serversdk-nodejs
 * ******************************
*/

const express = require('express');
const session = require("express-session");
// IBM App ID needs log4js
const log4js = require("log4js");
const promClient = require('prom-client');
const promBundle = require("express-prom-bundle");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const flash = require("connect-flash");
const axios = require('axios');




// OpenID, WebApp support
const passport = require('passport');
const WebAppStrategy = require('ibmcloud-appid').WebAppStrategy;
const APIStrategy = require("ibmcloud-appid").APIStrategy;
const TokenManager = require('ibmcloud-appid').TokenManager;
const ApiStrategy = require('ibmcloud-appid/lib/strategies/api-strategy');
 

// *** Prometheus 
// include HTTP method and URL path into the labels
const metricsMiddleware = promBundle({includeMethod: true, includePath: true});

// Initialize
var app = express();
const logger = log4js.getLogger("nodejsAppId");

app.use(metricsMiddleware);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));


const counterUserAgent = new promClient.Counter({name: 'http_request_blueprint_nodejs_user_agent_total', help: 'Blueprint Nodejs: User Agents', labelNames: ['ua']});


// ############# Application configuration
app.set('port', (process.env.PORT || 5000))
app.set('ip', (process.env.IP || '0.0.0.0'))
// ensure messages in sessions are available after redirects
app.use(flash());
app.use(cookieParser());
// set up ejs for templating
app.set('view engine', 'ejs'); 

// ############# OAuth configuration

// Below URLs will be used for App ID OAuth flows
const LANDING_PAGE_URL = "/webpage.html";
const LOGIN_URL = "/ibm/appid/login";
const CALLBACK_URL = "/ibm/appid/callback";
const LOGOUT_URL = "/ibm/appid/logout";
const SIGN_UP_URL = "/ibm/appid/sign_up";
const CHANGE_PASSWORD_URL = "/ibm/appid/change_password";
const CHANGE_DETAILS_URL = "/ibm/appid/change_details";
const FORGOT_PASSWORD_URL = "/ibm/appid/forgot_password";
const LOGIN_ANON_URL = "/ibm/appid/loginanon";
const ROP_LOGIN_PAGE_URL = "/ibm/appid/rop/login";


// Retrieve the OpenID/OAuth information from the env
const ssoProviderUrl = process.env.OAUTH_URL;
const ssoSecret = process.env.CLIENT_SECRET;
const ssoClientId = process.env.CLIENT_ID;
const ssoTenantId = process.env.TENANT_ID;
const sspAppBaseUrl = process.env.REDIRECT_URL;

const config = {
	tenantId: ssoTenantId,
	clientId: ssoClientId,
	secret: ssoSecret,
	oauthServerUrl: ssoProviderUrl,
  redirectUri: sspAppBaseUrl + CALLBACK_URL
};


// Setup express application to use express-session middleware
// Must be configured with proper session storage for production
// environments. See https://github.com/expressjs/session for
// additional documentation
app.use(session({
	secret: "123456789",
	resave: true,
	saveUninitialized: true
}));

// Use static resources from current directory
app.use(express.static(__dirname ));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new WebAppStrategy(config));
passport.use(new ApiStrategy(config));
const tokenManager = new TokenManager(config);

// Configure passportjs with user serialization/deserialization. This is required
// for authenticated session persistence across HTTP requests. See passportjs docs
// for additional information http://passportjs.org/docs

passport.serializeUser(function(user, cb) {
  console.log('serializeUser()', user);
  if(user == null) {
    cb(null, '0');
  } else {
    cb(null, user);
  }
});

passport.deserializeUser(function(obj, cb) {
  cb(null, obj);
});



// Explicit login endpoint. Will always redirect browser to login widget due to {forceLogin: true}. 
// If forceLogin is set to false the redirect to login widget will not occur if user is already authenticated
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
  
  var idpAuthContext = req.session[WebAppStrategy.AUTH_CONTEXT];
  // ATTENTION: Print out the Access/Identity Token Payload
  console.log('AccessTokenPayload:', idpAuthContext.accessTokenPayload);
  console.log('IdentityTokenPayload:', idpAuthContext.identityTokenPayload);

  res.json(req.user);
});

// Protected area. If current user is not authenticated - redirect to the login widget will be returned.
// In case user is authenticated - a page with current user information will be returned.
app.get("/api/protected", passport.authenticate(APIStrategy.STRATEGY_NAME), function(req, res){
  
  var idpAuthContext = req.appIdAuthorizationContext;
  // ATTENTION: Print out the Access/Identity Token Payload
  console.log('AccessTokenPayload:', idpAuthContext.accessTokenPayload);
  console.log('IdentityTokenPayload:', idpAuthContext.identityTokenPayload);

  res.json(idpAuthContext.accessTokenPayload);
});

app.post("/rop/login/submit", bodyParser.urlencoded({extended: false}), passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
	successRedirect: LANDING_PAGE_URL,
	failureRedirect: ROP_LOGIN_PAGE_URL,
	failureFlash : true // allow flash messages
}));

app.get(ROP_LOGIN_PAGE_URL, function(req, res) {
	// render the page and pass in any flash data if it exists
	res.render("login.ejs", { message: req.flash('error') });
});


// ############# Utilities
const sleep = (waitTimeInMs) => new Promise(resolve => setTimeout(resolve, waitTimeInMs));

async function getAppIdentityToken() {
	try {
			const tokenResponse = await tokenManager.getApplicationIdentityToken();
      return tokenResponse;
	} catch (err) {
			console.log('err obtained : ' + err);
	}
}

httpBackendResponses = '';
function httpRequest(url, accessToken, customHeaderValue, serviceName) {

  const req = axios.get(url, {
    headers: {      
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,     
        'X-Custom': customHeaderValue 
    }
  })
  .then(function (response) {
    console.log(`Secure Backend "${serviceName}" done`, response.status);
    httpBackendResponses += '<br />' + 'Secure Backend "secured/date": ' +  JSON.stringify(response.data);
  })
  .catch(function (error) {
    // handle error
    console.log(`Secure Backend "${serviceName}" done`, error.message);
    httpBackendResponses += '<br />' + `Secure Backend "${serviceName}": Communication Failed: ${error.message}`;
  })
  .finally(function () {

    console.log(`Secure Backend "${serviceName}" done.`);
  }); 

  return req;
}

// ############# Entry points
app.get('/', (req, res) => {
  
    var userAgent = req.get('User-Agent');
    var ret = "Hello you! " + userAgent;    
    console.log('user-agent: ' + userAgent);
  
    // Prometheus Metric: inc and set the user agent
    counterUserAgent.labels(userAgent).inc();
  
    res.send(ret);    
});

// ############# Call (secured) backend service
app.get('/backend', passport.authenticate(WebAppStrategy.STRATEGY_NAME, {
  successRedirect: '/secure/backend',
  forceLogin: false
}));

app.get('/secure/backend', passport.authenticate(WebAppStrategy.STRATEGY_NAME), function(req, res) {
  
  getAppIdentityToken().then( j => callBackend(j, res) );
});


app.listen(app.get('port'), app.get('ip'), function() {

    console.log("Node app is running at localhost:" + app.get('port'))
})


function callBackend(accessToken, res) {

  console.log('accessToken', accessToken.accessToken);
 
  httpBackendResponses = ''; 
  const req1 = httpRequest("http://127.0.0.1:8080/secured/date", accessToken.accessToken, 'Req1', 'secured/date');
  const req2 = httpRequest("http://127.0.0.1:8080/secured/user", accessToken.accessToken, 'Req2', 'secured/user');
  const req3 = httpRequest("http://127.0.0.1:8080/secured/dateForManager", accessToken.accessToken, 'Req3', 'secured/dateForManager');

  Promise.all([req1, req2, req3])
      .then(() => {

        console.log('callBackend done.');
        res.send(httpBackendResponses);
      })
  }

module.exports = app;
