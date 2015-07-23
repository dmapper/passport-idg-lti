var lti = require('ims-lti');
var passport = require('passport-strategy');
var util = require('util');

function Strategy(options, verify) {
  options = options || {};

  options.providerName = options.providerName || 'lti'

  passport.Strategy.call(this);
  this.name = options.providerName;
  this._passReqToCallback = options.passReqToCallback;
  this._provider = new lti.Provider(options.consumerKey,
      options.consumerSecret);
  this._verify = verify;
  this.getProfile = options.getProfile || this._getProfile;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype._getProfile = function(data){
  var fullname = data.lis_person_name_full || '';
  var firstname = fullname.split(' ')[0] || '';
  var lastname = fullname.split(' ')[1] || '';

  var profile = {
    id: data.user_id,
    email: data.lis_person_contact_email_primary.toLowerCase(),
    firstname: data.lis_person_name_given || firstname,
    lastname: data.lis_person_name_family || lastname,
    //_json: data,
    provider: this.name
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

  if (!req.query || !req.query.profile) {


    if (req.body.lti_message_type !== 'basic-lti-launch-request') {
      return self.fail("Request isn't LTI launch");
    }

    self._provider.valid_request(req, function (err, valid) {
      var en1criptedProfile = '';

      if (err) return self.error(err);
      if (!valid) return self.fail();

      var profile = self.getProfile(self._provider.body);

      try{
        en1criptedProfile = encodeURIComponent(JSON.stringify(profile));
      } catch(e){
        console.log('Error: - can not serialize the profile:');
        console.log(profile);
        en1criptedProfile = '{}';
      }

      self.redirect(options.callbackURL+"?profile="+en1criptedProfile)
    });
  } else {

    function verified(err, user, info) {
      if (err) return self.error(err);
      if (!user) return self.fail(info);
      return self.success(user, info);
    }

    var profile = JSON.parse(req.query.profile);
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
