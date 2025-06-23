'use strict';


/**
 * Dashboard page
 * Returns the dashboard if authenticated.
 *
 * no response value expected for this operation
 **/
exports.dashboardGET = function() {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Run image detection
 * Runs inference on an image for object detection.
 *
 * returns byte[]
 **/
exports.detectPOST = function() {
  return new Promise(function(resolve, reject) {
    var examples = {};
    examples['application/json'] = "";
    if (Object.keys(examples).length > 0) {
      resolve(examples[Object.keys(examples)[0]]);
    } else {
      resolve();
    }
  });
}


/**
 * Favicon
 * Returns the favicon.
 *
 * no response value expected for this operation
 **/
exports.favicon_icoGET = function() {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Forgot password page
 * Displays the forgot password page.
 *
 * no response value expected for this operation
 **/
exports.forgotGET = function() {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Forgot password
 * Allows a user to request a password reset using their email.
 *
 * body Forgotpassword_body 
 * no response value expected for this operation
 **/
exports.forgot_passwordPOST = function(body) {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Display the login page
 * Returns the login page HTML.
 *
 * no response value expected for this operation
 **/
exports.loginGET = function() {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Authenticate user
 * Authenticates the user with email and password.
 *
 * body Login_body 
 * no response value expected for this operation
 **/
exports.loginPOST = function(body) {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Message page
 * Displays a page with a query-provided message.
 *
 * message String  (optional)
 * no response value expected for this operation
 **/
exports.messageGET = function(message) {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Password reset page
 * Displays the password reset page.
 *
 * token String 
 * no response value expected for this operation
 **/
exports.password_resetGET = function(token) {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Access protected page
 * Returns the protected page if authenticated.
 *
 * no response value expected for this operation
 **/
exports.protectedGET = function() {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Display the registration page
 * Returns the registration page HTML.
 *
 * no response value expected for this operation
 **/
exports.registerGET = function() {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Register a new user
 * Allows a user to register with email and password.
 *
 * body Register_body 
 * no response value expected for this operation
 **/
exports.registerPOST = function(body) {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Reset password
 * Resets the password using a JWT and new password.
 *
 * body Resetpassword_body 
 * no response value expected for this operation
 **/
exports.reset_passwordPOST = function(body) {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}


/**
 * Homepage
 * Displays the homepage.
 *
 * no response value expected for this operation
 **/
exports.rootGET = function() {
  return new Promise(function(resolve, reject) {
    resolve();
  });
}

