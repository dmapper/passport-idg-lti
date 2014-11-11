var lti = require('ims-lti');
var passport = require('passport-strategy');
var util = require('util');

function Strategy(options) {

  options = options || {};

  options.providerName = options.providerName || 'lti';
  options.collection = options.collection || 'auths';

  passport.Strategy.call(this);

  this.name = options.providerName;
  this._collection = options.collection;

  this._provider = new lti.Provider(options.consumerKey, options.consumerSecret);
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.lti = true;

Strategy.prototype.authenticate = function(req, options) {
  var self = this;
  if (req.query){
    for(var key in req.query){
      delete req.body[key];
    }
  }
  if (req.body.lti_message_type !== 'basic-lti-launch-request') {
    return self.fail("Request isn't LTI launch");
  }

  function verified(err, user, info) {
    if (err) return self.error(err);
    if (!user) return self.fail(info);
    return self.success(user, info);
  }

  self._provider.valid_request(req, function(err, valid) {
    if (err) {
      console.log('Valid_request ERROR!: ', err);
      return self.error(err);
    }

    if (!valid) return self.fail();

    try {
      return self._verify(req, self._provider.body, verified);
    } catch (ex) {
      return self.error(ex);
    }
  });
};


Strategy.prototype._verify = function(req, data, done){
  console.log('verify');

  var self = this;
  var model = req.getModel();
  var email = data.lis_person_contact_email_primary.toLowerCase();

  var query = {
    email: email,
    $limit: 1
  };

  var $userQuery = model.query(self._collection, query);

  model.fetch($userQuery, function(err) {
    if (err) return done(err);

    var user = $userQuery.get()[0];

    var providerData = {
      email: email,
      firstname: data.lis_person_name_given,
      lastname: data.lis_person_name_family,
      _json: data,
      provider: self.name
    };

    if (user) {
      req.session.userId = user.id;

      if (user[self.name]){
        done(null, user);
      } else {
        var upgrade = {};
        upgrade[self.name] = providerData;
        if (req.query.profId) {
          upgrade.profId = req.query.profId;
          upgrade.profIdAccepted = true;
        }

        model.setEach(self._collection + '.' + user.id, upgrade, function(){
          user[self.name] = providerData;
          user.profkey = req.query.profkey;
          done(null, user);
        })
      }

      return;
    }

    var name = data.lis_person_name_given + ' ' + data.lis_person_name_family.charAt(0) + '.';

    var userData = {
      id: model.id(),
      timestamps: {registered: Date.now()},
      name: name,
      email: email
    };

    if (req.query.profId){
      userData.profId = req.query.profId;
      userData.profIdAccepted = true;
    }

    userData[self.name] = providerData;


    model.add(self._collection, userData, function(err){
      if (err) return done(err);
      req.session.userId = userData.id;
      done(null, userData);
    });

  });
};

module.exports = Strategy;
