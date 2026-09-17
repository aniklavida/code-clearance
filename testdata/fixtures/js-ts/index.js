const _ = require('lodash');

function greet(name) {
  return _.capitalize('hello, ' + name + '!');
}

module.exports = { greet };

if (require.main === module) {
  console.log(greet('world'));
}
