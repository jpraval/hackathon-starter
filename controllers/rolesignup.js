const { promisify } = require('util');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const User = require('../models/User');
var validator = require('validator');

const randomBytesAsync = promisify(crypto.randomBytes);

/**
 * GET /
 * Roles select page.
 */
exports.index = (req, res) => {
  res.render('account/askroles', {
    title: 'Roles'
  });
};

/**
 * GET /account/family/search
 * search page.
 */
exports.getFamilySearch = (req, res) => {
  res.render('account/family/search', {
    title: 'Family Search'
  });
};

/**
 * GET /account/provider/search
 * search page.
 */
exports.getProviderSearch = (req, res) => {
  res.render('account/provider/search', {
    title: 'Provider Search'
  });
};

/**
 * GET /account/carer/search
 * search page.
 */
exports.getCarerSearch = (req, res) => {
  res.render('account/carer/search', {
    title: 'Carer Search'
  });
};

/**
 * GET /account/family/signup
 * Roles select page.
 */
exports.getFamilySignup = (req, res) => {
  res.render('account/family/signup', {
    title: 'Family Signup'
  });
};

/**
 * POST /account/family/signup
 * Request from family signup page.
 */
exports.postFamilySignup = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });
  req.assert('numhoursneeded','Should be a number').isNumeric();
  req.assert('careagesrequired','Should select atleast one age group').isArray( {min: 1});
  req.assert('contactname','Contact name should not be empty').notEmpty();
  req.assert('mobile','Should be valid mobile number').isNumeric();
  req.assert('address','Should not be empty').notEmpty();
  req.assert('pincode','Should not be empty').notEmpty();


  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/signup/family');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password,
    role:"familyaccount",
    numhoursneeded: req.body.password,
    careagesrequired: req.body.careagesrequired,
    contactname:req.body.contactname,
    mobile:req.body.mobile,
    address:req.body.address,
    pincode:req.body.pincode
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) { return next(err); }
    if (existingUser) {
      req.flash('errors', { msg: 'Account with that email address already exists.' });
      return res.redirect('/signup/family');
    }
    user.save((err) => {
      if (err) { return next(err); }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
};



/**
 * GET /account/carer/signup
 * Roles select page.
 */
exports.getCarerSignup = (req, res) => {
  res.render('account/carer/signup', {
    title: 'Carer Signup'
  });
};


/**
 * POST /account/carer/signup
 * Request from carer signup page.
 */
exports.postCarerSignup = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });
  req.assert('numhoursavailable','Should be a number').isNumeric();
  req.assert('careagesavailablefor','Should select atleast one age group').isArray({min: 1});
  req.assert('contactname','Contact name should not be empty').notEmpty();
  req.assert('mobile','Should be valid mobile number').isNumeric();
  req.assert('address','Should not be empty').notEmpty();
  req.assert('pincode','Should not be empty').notEmpty();


  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/signup/carer');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password,
    role:"carer",
    numhoursavailable: req.body.numhoursavailable,
    careagesavailablefor: req.body.careagesavailablefor,
    contactname:req.body.contactname,
    mobile:req.body.mobile,
    address:req.body.address,
    pincode:req.body.pincode
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) { return next(err); }
    if (existingUser) {
      req.flash('errors', { msg: 'Account with that email address already exists.' });
      return res.redirect('/signup/carer');
    }
    user.save((err) => {
      if (err) { return next(err); }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
};


/**
 * GET /account/provider/signup
 * Roles select page.
 */
exports.getProviderSignup = (req, res) => {
  res.render('account/provider/signup', {
    title: 'Provider Signup'
  });
};

/**
 * POST /account/provider/signup
 * Request from provider signup page.
 */
exports.postProviderSignup = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });
  req.assert('typeofprovider','Provider type should not be empty').isArray({min: 1});
  req.assert('numhoursavailable','Number of hours should be a number').isNumeric();
  req.assert('careagesavailablefor','Should select atleast one age group').isArray({min: 1});
  req.assert('contactname','Contact name should not be empty').notEmpty();
  req.assert('mobile','Should be valid mobile number').isNumeric();
  req.assert('address','Address should not be empty').notEmpty();
  req.assert('pincode','Pincode should not be empty').notEmpty();


  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/signup/provider');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password,
    role:"provider",
    typeofprovider: req.body.typeofprovider,
    numhoursavailable: req.body.numhoursavailable,
    careagesavailablefor: req.body.careagesavailablefor,
    contactname:req.body.contactname,
    mobile:req.body.mobile,
    address:req.body.address,
    pincode:req.body.pincode
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) { return next(err); }
    if (existingUser) {
      req.flash('errors', { msg: 'Account with that email address already exists.' });
      return res.redirect('/signup/provider');
    }
    user.save((err) => {
      if (err) { return next(err); }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
};