var lti = require('ims-lti');
var passport = require('passport-strategy');
var util = require('util');

function Strategy(options, verify) {
  options = options || {};

  options.providerName = options.providerName || 'lti';

  passport.Strategy.call(this);
  this.name = options.providerName;
  this._passReqToCallback = options.passReqToCallback;
  this._verify = verify;
  this.getProfile = options.getProfile || this._getProfile;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype._getProfile = function(data, schoolName){
  var fullname = data.lis_person_name_full || '';
  var firstname = fullname.split(' ')[0] || '';
  var lastname = fullname.split(' ')[1] || '';

  var profile = {
    id: data.user_id,
    email: data.lis_person_contact_email_primary.toLowerCase(),
    firstname: data.lis_person_name_given || firstname,
    lastname: data.lis_person_name_family || lastname,
    _json: data,
    provider: schoolName
  };

  return profile;
};

Strategy.prototype.authenticate = function(req, options) {

  var self = this;

  if (req.query) {
    for (var key in req.query) {
      delete req.body[key];
    }
  }

  // auth/lti
  if (req.path.indexOf('callback') === -1) {

    if (req.body.lti_message_type !== 'basic-lti-launch-request') {
      return self.fail("Request isn't LTI launch");
    }

    var key = req.body.oauth_consumer_key;
    var secret = undefined;

    for(var schoolName in options.schools){
      var school = options.schools[schoolName];

      if (school.consumerKey === key) {
        secret = school.consumerSecret;
        break;
      }
    }

    var provider = new lti.Provider(key, secret);

    provider.valid_request(req, function (err, valid) {
      if (err) return self.error(err);
      if (!valid) return self.fail();

      var profile = self.getProfile(provider.body, schoolName);

      req.session = req.session || {};
      req.session.ltiProfile = profile;
      req.session.ltiSchool = school;

      self.redirect(options.callbackURL);
    });

  // auth/lti/callback
  } else {

    function verified(err, user, info) {
      if (err) return self.error(err);
      if (!user) return self.fail(info);
      return self.success(user, info);
    }

    var profile = req.session.ltiProfile || {};
    var school = req.session.ltiSchool || {};

    delete req.session.ltiProfile;
    delete req.session.ltiSchool;

    if (!profile.provider) return self.error('No Profile!');

    req.query = req.query || {};

    if (!req.query.redirect && school.redirect){
      req.query.redirect = school.redirect;
    }

    try {
      if (self._passReqToCallback) {
        return self._verify(req, undefined, undefined, profile, verified);
      } else {
        return self._verify(undefined, undefined, profile, verified);
      }
    } catch (ex) {
      return self.error(ex);
    }
  }
};

module.exports = Strategy;
