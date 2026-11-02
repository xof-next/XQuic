'use strict';

module.exports = {
  ...require('./codec'),
  ...require('./registry')
};
module.exports.default = module.exports;
