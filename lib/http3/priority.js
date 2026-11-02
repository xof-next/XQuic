'use strict';

const structured = require('./structured-fields');
const DEFAULT_PRIORITY = Object.freeze({ urgency: 3, incremental: false });

function defaultPriority() {
  return { urgency: DEFAULT_PRIORITY.urgency, incremental: DEFAULT_PRIORITY.incremental };
}
function memberValue(member) {
  return member && typeof member === 'object' && Object.prototype.hasOwnProperty.call(member, 'value') ? member.value : member;
}
function parsePriority(value) {
  if (typeof value !== 'string') return defaultPriority();
  let dictionary;
  try { dictionary = structured.parseDictionary(value, { maxInputLength: 8192, maxMembers: 256 }); }
  catch { return defaultPriority(); }
  const result = defaultPriority();
  if (Object.prototype.hasOwnProperty.call(dictionary, 'u')) {
    const urgency = memberValue(dictionary.u);
    if (typeof urgency !== 'number' || !Number.isInteger(urgency) || urgency < 0 || urgency > 7) return defaultPriority();
    result.urgency = urgency;
  }
  if (Object.prototype.hasOwnProperty.call(dictionary, 'i')) {
    const incremental = memberValue(dictionary.i);
    if (typeof incremental !== 'boolean') return defaultPriority();
    result.incremental = incremental;
  }
  return result;
}
function encodePriority(priority = {}) {
  const urgency = priority.urgency === undefined ? DEFAULT_PRIORITY.urgency : Number(priority.urgency);
  const incremental = priority.incremental === undefined ? DEFAULT_PRIORITY.incremental : priority.incremental;
  if (!Number.isInteger(urgency) || urgency < 0 || urgency > 7) throw new RangeError('Priority urgency must be an integer from 0 to 7');
  if (typeof incremental !== 'boolean') throw new TypeError('Priority incremental must be a boolean');
  return incremental ? structured.serializeDictionary({ u: { value: urgency, params: {} }, i: { value: true, params: {} } }) : structured.serializeDictionary({ u: { value: urgency, params: {} } });
}

module.exports = { DEFAULT_PRIORITY, parsePriority, encodePriority };
module.exports.default = module.exports;
