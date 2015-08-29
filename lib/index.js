var _ = require('lodash');

module.exports = function (sails) {
  return {
    initialize: function (cb) {
      var acl = _getACL(sails.config.acl);
      console.log(' ');
      console.log(require('util').inspect(acl, {depth: null}));
      var authPolicyName = sails.config.acl.authPolicy || 'isAuthenticated';
      var aclPolicyFn = _.partial(_aclPolicy, acl);

      sails.on('hook:orm:loaded', function () {
        var policyMap = sails.hooks.policies.mapping;
        var injectPolicy = _.partial(_injectPolicy, authPolicyName, _, aclPolicyFn);
        _.forEach(policyMap, function (controllerPolicy) {
          if (_.isArray(controllerPolicy)) return injectPolicy(policyMap['*']); // inject policy for *;
          _.map(controllerPolicy, injectPolicy);
        });
      });

      cb();
    }
  }
};

function _injectPolicy(authPolicyName, actionPolicies, fn) {
  var eqFunc = _.ary(_.flow(_.partial(_.result, _, 'globalId'), _.partial(_.isEqual, authPolicyName)), 1);
  var authPolicyIndex = _.findIndex(actionPolicies, eqFunc);
  actionPolicies.splice(authPolicyIndex + 1, 0, fn);
}

function checkPermissions(acl, req, role) {
  var controller = req.options.controller;
  var action = req.options.action;
  var check = _.partial(_.get, acl, _, false);
  var permission = check([role, controller, action].join('.')) || check([role, controller, '*'].join('.'));
  if (permission) {
    if (_.isBoolean(permission)) {
      return permission;
    }
    if (_.isObject(permission)) {
      var res = true;
      if ('fieldsBlackList' in permission)
        _.set(req.options, 'criteria.blacklist', permission.fieldsBlackList);
      if ('check' in permission)
        res = permission.check(req);
      if ('method' in permission)
        res = res && req.method.toLowerCase() == permission.method.toLowerCase();

      return res;
    }
  }
  return false;
}

function _aclPolicy(acl, req, res, next) {
  var currentRole = _.get(req, 'user.role') || 'guest';
  if (checkPermissions(acl, req, currentRole))
    return next()
  else
    return res.unauthorized('ACL');
  res.unauthorized();
}

function _createRoleHelpObj(obj) {
  return _.transform(obj, function (res, permissions, key) {
    if (key === 'inherits')
      return res[key] = permissions;
    //console.log(permissions);
    res[key] = {};
    if (_.isArray(permissions)) {
      _.forEach(permissions, function (permission) {
        //console.log(permission);
        if (_.isObject(permission)) {
          res[key][permission.action] = _.pick(permission, _.negate(_.rearg(_.partial(_.isEqual, 'action'), 1, 0)));
        } else {
          res[key][permission] = true;
        }
      });
    } else if (_.isString(permissions)) {
      res[key][permissions] = true;
    }
    //res[key] = _.object(permissions, _.fill(new Array(permissions.length), true));
  });
}

/*
 * Returns full permissions object (with inherited permissions) for role
 */
function _getRolePermissions(defaultAcl, inheritedAcl, roleName) {
  if (roleName in inheritedAcl) return inheritedAcl[roleName];
  if (!_.get(defaultAcl, roleName, false)) return {};

  var rolePermissions = defaultAcl[roleName];
  var role = rolePermissions;
  if (rolePermissions.inherits) {
    role = _.merge(rolePermissions, _getRolePermissions(defaultAcl, inheritedAcl, rolePermissions.inherits), function (a, b) {
      if (!_.isArray(a) && !_.isUndefined(a)) a = [a];
      if (!_.isArray(b) && !_.isUndefined(b)) b = [b];
      if (_.isArray(a) && _.isArray(b)) return a;
    });
    delete role.inherits;
  }
  return inheritedAcl[roleName] = role;
}

function _getACL(aclConfig) {
  var fullACL = {};
  var getRolePermissionsFn = _.partial(_getRolePermissions, aclConfig.roles, fullACL);
  // create help obj and apply inheritance
  return _.transform(aclConfig.roles, function (result, val, key) {
    result[key] = _createRoleHelpObj(getRolePermissionsFn(key));
  });
}
