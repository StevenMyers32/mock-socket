var commonjsGlobal = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

/**
 * Check if we're required to add a port number.
 *
 * @see https://url.spec.whatwg.org/#default-port
 * @param {Number|String} port Port number we need to check
 * @param {String} protocol Protocol we need to check against.
 * @returns {Boolean} Is it a default port for the given protocol
 * @api private
 */
var requiresPort = function required(port, protocol) {
  protocol = protocol.split(':')[0];
  port = +port;

  if (!port) { return false; }

  switch (protocol) {
    case 'http':
    case 'ws':
    return port !== 80;

    case 'https':
    case 'wss':
    return port !== 443;

    case 'ftp':
    return port !== 21;

    case 'gopher':
    return port !== 70;

    case 'file':
    return false;
  }

  return port !== 0;
};

var has = Object.prototype.hasOwnProperty;
var undef;

/**
 * Decode a URI encoded string.
 *
 * @param {String} input The URI encoded string.
 * @returns {String} The decoded string.
 * @api private
 */
function decode(input) {
  return decodeURIComponent(input.replace(/\+/g, ' '));
}

/**
 * Simple query string parser.
 *
 * @param {String} query The query string that needs to be parsed.
 * @returns {Object}
 * @api public
 */
function querystring(query) {
  var parser = /([^=?&]+)=?([^&]*)/g
    , result = {}
    , part;

  while (part = parser.exec(query)) {
    var key = decode(part[1])
      , value = decode(part[2]);

    //
    // Prevent overriding of existing properties. This ensures that build-in
    // methods like `toString` or __proto__ are not overriden by malicious
    // querystrings.
    //
    if (key in result) { continue; }
    result[key] = value;
  }

  return result;
}

/**
 * Transform a query string to an object.
 *
 * @param {Object} obj Object that should be transformed.
 * @param {String} prefix Optional prefix.
 * @returns {String}
 * @api public
 */
function querystringify(obj, prefix) {
  prefix = prefix || '';

  var pairs = []
    , value
    , key;

  //
  // Optionally prefix with a '?' if needed
  //
  if ('string' !== typeof prefix) { prefix = '?'; }

  for (key in obj) {
    if (has.call(obj, key)) {
      value = obj[key];

      //
      // Edge cases where we actually want to encode the value to an empty
      // string instead of the stringified value.
      //
      if (!value && (value === null || value === undef || isNaN(value))) {
        value = '';
      }

      pairs.push(encodeURIComponent(key) +'='+ encodeURIComponent(value));
    }
  }

  return pairs.length ? prefix + pairs.join('&') : '';
}

//
// Expose the module.
//
var stringify = querystringify;
var parse = querystring;

var querystringify_1 = {
	stringify: stringify,
	parse: parse
};

var protocolre = /^([a-z][a-z0-9.+-]*:)?(\/\/)?([\S\s]*)/i;
var slashes = /^[A-Za-z][A-Za-z0-9+-.]*:\/\//;

/**
 * These are the parse rules for the URL parser, it informs the parser
 * about:
 *
 * 0. The char it Needs to parse, if it's a string it should be done using
 *    indexOf, RegExp using exec and NaN means set as current value.
 * 1. The property we should set when parsing this value.
 * 2. Indication if it's backwards or forward parsing, when set as number it's
 *    the value of extra chars that should be split off.
 * 3. Inherit from location if non existing in the parser.
 * 4. `toLowerCase` the resulting value.
 */
var rules = [
  ['#', 'hash'],                        // Extract from the back.
  ['?', 'query'],                       // Extract from the back.
  function sanitize(address) {          // Sanitize what is left of the address
    return address.replace('\\', '/');
  },
  ['/', 'pathname'],                    // Extract from the back.
  ['@', 'auth', 1],                     // Extract from the front.
  [NaN, 'host', undefined, 1, 1],       // Set left over value.
  [/:(\d+)$/, 'port', undefined, 1],    // RegExp the back.
  [NaN, 'hostname', undefined, 1, 1]    // Set left over.
];

/**
 * These properties should not be copied or inherited from. This is only needed
 * for all non blob URL's as a blob URL does not include a hash, only the
 * origin.
 *
 * @type {Object}
 * @private
 */
var ignore = { hash: 1, query: 1 };

/**
 * The location object differs when your code is loaded through a normal page,
 * Worker or through a worker using a blob. And with the blobble begins the
 * trouble as the location object will contain the URL of the blob, not the
 * location of the page where our code is loaded in. The actual origin is
 * encoded in the `pathname` so we can thankfully generate a good "default"
 * location from it so we can generate proper relative URL's again.
 *
 * @param {Object|String} loc Optional default location object.
 * @returns {Object} lolcation object.
 * @public
 */
function lolcation(loc) {
  var globalVar;

  if (typeof window !== 'undefined') { globalVar = window; }
  else if (typeof commonjsGlobal !== 'undefined') { globalVar = commonjsGlobal; }
  else if (typeof self !== 'undefined') { globalVar = self; }
  else { globalVar = {}; }

  var location = globalVar.location || {};
  loc = loc || location;

  var finaldestination = {}
    , type = typeof loc
    , key;

  if ('blob:' === loc.protocol) {
    finaldestination = new Url(unescape(loc.pathname), {});
  } else if ('string' === type) {
    finaldestination = new Url(loc, {});
    for (key in ignore) { delete finaldestination[key]; }
  } else if ('object' === type) {
    for (key in loc) {
      if (key in ignore) { continue; }
      finaldestination[key] = loc[key];
    }

    if (finaldestination.slashes === undefined) {
      finaldestination.slashes = slashes.test(loc.href);
    }
  }

  return finaldestination;
}

/**
 * @typedef ProtocolExtract
 * @type Object
 * @property {String} protocol Protocol matched in the URL, in lowercase.
 * @property {Boolean} slashes `true` if protocol is followed by "//", else `false`.
 * @property {String} rest Rest of the URL that is not part of the protocol.
 */

/**
 * Extract protocol information from a URL with/without double slash ("//").
 *
 * @param {String} address URL we want to extract from.
 * @return {ProtocolExtract} Extracted information.
 * @private
 */
function extractProtocol(address) {
  var match = protocolre.exec(address);

  return {
    protocol: match[1] ? match[1].toLowerCase() : '',
    slashes: !!match[2],
    rest: match[3]
  };
}

/**
 * Resolve a relative URL pathname against a base URL pathname.
 *
 * @param {String} relative Pathname of the relative URL.
 * @param {String} base Pathname of the base URL.
 * @return {String} Resolved pathname.
 * @private
 */
function resolve(relative, base) {
  var path = (base || '/').split('/').slice(0, -1).concat(relative.split('/'))
    , i = path.length
    , last = path[i - 1]
    , unshift = false
    , up = 0;

  while (i--) {
    if (path[i] === '.') {
      path.splice(i, 1);
    } else if (path[i] === '..') {
      path.splice(i, 1);
      up++;
    } else if (up) {
      if (i === 0) { unshift = true; }
      path.splice(i, 1);
      up--;
    }
  }

  if (unshift) { path.unshift(''); }
  if (last === '.' || last === '..') { path.push(''); }

  return path.join('/');
}

/**
 * The actual URL instance. Instead of returning an object we've opted-in to
 * create an actual constructor as it's much more memory efficient and
 * faster and it pleases my OCD.
 *
 * It is worth noting that we should not use `URL` as class name to prevent
 * clashes with the global URL instance that got introduced in browsers.
 *
 * @constructor
 * @param {String} address URL we want to parse.
 * @param {Object|String} [location] Location defaults for relative paths.
 * @param {Boolean|Function} [parser] Parser for the query string.
 * @private
 */
function Url(address, location, parser) {
  if (!(this instanceof Url)) {
    return new Url(address, location, parser);
  }

  var relative, extracted, parse, instruction, index, key
    , instructions = rules.slice()
    , type = typeof location
    , url = this
    , i = 0;

  //
  // The following if statements allows this module two have compatibility with
  // 2 different API:
  //
  // 1. Node.js's `url.parse` api which accepts a URL, boolean as arguments
  //    where the boolean indicates that the query string should also be parsed.
  //
  // 2. The `URL` interface of the browser which accepts a URL, object as
  //    arguments. The supplied object will be used as default values / fall-back
  //    for relative paths.
  //
  if ('object' !== type && 'string' !== type) {
    parser = location;
    location = null;
  }

  if (parser && 'function' !== typeof parser) { parser = querystringify_1.parse; }

  location = lolcation(location);

  //
  // Extract protocol information before running the instructions.
  //
  extracted = extractProtocol(address || '');
  relative = !extracted.protocol && !extracted.slashes;
  url.slashes = extracted.slashes || relative && location.slashes;
  url.protocol = extracted.protocol || location.protocol || '';
  address = extracted.rest;

  //
  // When the authority component is absent the URL starts with a path
  // component.
  //
  if (!extracted.slashes) { instructions[3] = [/(.*)/, 'pathname']; }

  for (; i < instructions.length; i++) {
    instruction = instructions[i];

    if (typeof instruction === 'function') {
      address = instruction(address);
      continue;
    }

    parse = instruction[0];
    key = instruction[1];

    if (parse !== parse) {
      url[key] = address;
    } else if ('string' === typeof parse) {
      if (~(index = address.indexOf(parse))) {
        if ('number' === typeof instruction[2]) {
          url[key] = address.slice(0, index);
          address = address.slice(index + instruction[2]);
        } else {
          url[key] = address.slice(index);
          address = address.slice(0, index);
        }
      }
    } else if ((index = parse.exec(address))) {
      url[key] = index[1];
      address = address.slice(0, index.index);
    }

    url[key] = url[key] || (
      relative && instruction[3] ? location[key] || '' : ''
    );

    //
    // Hostname, host and protocol should be lowercased so they can be used to
    // create a proper `origin`.
    //
    if (instruction[4]) { url[key] = url[key].toLowerCase(); }
  }

  //
  // Also parse the supplied query string in to an object. If we're supplied
  // with a custom parser as function use that instead of the default build-in
  // parser.
  //
  if (parser) { url.query = parser(url.query); }

  //
  // If the URL is relative, resolve the pathname against the base URL.
  //
  if (
      relative
    && location.slashes
    && url.pathname.charAt(0) !== '/'
    && (url.pathname !== '' || location.pathname !== '')
  ) {
    url.pathname = resolve(url.pathname, location.pathname);
  }

  //
  // We should not add port numbers if they are already the default port number
  // for a given protocol. As the host also contains the port number we're going
  // override it with the hostname which contains no port number.
  //
  if (!requiresPort(url.port, url.protocol)) {
    url.host = url.hostname;
    url.port = '';
  }

  //
  // Parse down the `auth` for the username and password.
  //
  url.username = url.password = '';
  if (url.auth) {
    instruction = url.auth.split(':');
    url.username = instruction[0] || '';
    url.password = instruction[1] || '';
  }

  url.origin = url.protocol && url.host && url.protocol !== 'file:'
    ? url.protocol +'//'+ url.host
    : 'null';

  //
  // The href is just the compiled result.
  //
  url.href = url.toString();
}

/**
 * This is convenience method for changing properties in the URL instance to
 * insure that they all propagate correctly.
 *
 * @param {String} part          Property we need to adjust.
 * @param {Mixed} value          The newly assigned value.
 * @param {Boolean|Function} fn  When setting the query, it will be the function
 *                               used to parse the query.
 *                               When setting the protocol, double slash will be
 *                               removed from the final url if it is true.
 * @returns {URL} URL instance for chaining.
 * @public
 */
function set(part, value, fn) {
  var url = this;

  switch (part) {
    case 'query':
      if ('string' === typeof value && value.length) {
        value = (fn || querystringify_1.parse)(value);
      }

      url[part] = value;
      break;

    case 'port':
      url[part] = value;

      if (!requiresPort(value, url.protocol)) {
        url.host = url.hostname;
        url[part] = '';
      } else if (value) {
        url.host = url.hostname +':'+ value;
      }

      break;

    case 'hostname':
      url[part] = value;

      if (url.port) { value += ':'+ url.port; }
      url.host = value;
      break;

    case 'host':
      url[part] = value;

      if (/:\d+$/.test(value)) {
        value = value.split(':');
        url.port = value.pop();
        url.hostname = value.join(':');
      } else {
        url.hostname = value;
        url.port = '';
      }

      break;

    case 'protocol':
      url.protocol = value.toLowerCase();
      url.slashes = !fn;
      break;

    case 'pathname':
    case 'hash':
      if (value) {
        var char = part === 'pathname' ? '/' : '#';
        url[part] = value.charAt(0) !== char ? char + value : value;
      } else {
        url[part] = value;
      }
      break;

    default:
      url[part] = value;
  }

  for (var i = 0; i < rules.length; i++) {
    var ins = rules[i];

    if (ins[4]) { url[ins[1]] = url[ins[1]].toLowerCase(); }
  }

  url.origin = url.protocol && url.host && url.protocol !== 'file:'
    ? url.protocol +'//'+ url.host
    : 'null';

  url.href = url.toString();

  return url;
}

/**
 * Transform the properties back in to a valid and full URL string.
 *
 * @param {Function} stringify Optional query stringify function.
 * @returns {String} Compiled version of the URL.
 * @public
 */
function toString(stringify) {
  if (!stringify || 'function' !== typeof stringify) { stringify = querystringify_1.stringify; }

  var query
    , url = this
    , protocol = url.protocol;

  if (protocol && protocol.charAt(protocol.length - 1) !== ':') { protocol += ':'; }

  var result = protocol + (url.slashes ? '//' : '');

  if (url.username) {
    result += url.username;
    if (url.password) { result += ':'+ url.password; }
    result += '@';
  }

  result += url.host + url.pathname;

  query = 'object' === typeof url.query ? stringify(url.query) : url.query;
  if (query) { result += '?' !== query.charAt(0) ? '?'+ query : query; }

  if (url.hash) { result += url.hash; }

  return result;
}

Url.prototype = { set: set, toString: toString };

//
// Expose the URL parser and some additional properties that might be useful for
// others or testing.
//
Url.extractProtocol = extractProtocol;
Url.location = lolcation;
Url.qs = querystringify_1;

var urlParse = Url;

/*
 * This delay allows the thread to finish assigning its on* methods
 * before invoking the delay callback. This is purely a timing hack.
 * http://geekabyte.blogspot.com/2014/01/javascript-effect-of-setting-settimeout.html
 *
 * @param {callback: function} the callback which will be invoked after the timeout
 * @parma {context: object} the context in which to invoke the function
 */
function delay(callback, context) {
  setTimeout(function (timeoutContext) { return callback.call(timeoutContext); }, 4, context);
}

function log(method, message) {
  /* eslint-disable no-console */
  if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'test') {
    console[method].call(null, message);
  }
  /* eslint-enable no-console */
}

function reject(array, callback) {
  var results = [];
  array.forEach(function (itemInArray) {
    if (!callback(itemInArray)) {
      results.push(itemInArray);
    }
  });

  return results;
}

function filter(array, callback) {
  var results = [];
  array.forEach(function (itemInArray) {
    if (callback(itemInArray)) {
      results.push(itemInArray);
    }
  });

  return results;
}

/*
 * EventTarget is an interface implemented by objects that can
 * receive events and may have listeners for them.
 *
 * https://developer.mozilla.org/en-US/docs/Web/API/EventTarget
 */
var EventTarget = function EventTarget() {
  this.listeners = {};
};

/*
 * Ties a listener function to an event type which can later be invoked via the
 * dispatchEvent method.
 *
 * @param {string} type - the type of event (ie: 'open', 'message', etc.)
 * @param {function} listener - callback function to invoke when an event is dispatched matching the type
 * @param {boolean} useCapture - N/A TODO: implement useCapture functionality
 */
EventTarget.prototype.addEventListener = function addEventListener (type, listener /* , useCapture */) {
  if (typeof listener === 'function') {
    if (!Array.isArray(this.listeners[type])) {
      this.listeners[type] = [];
    }

    // Only add the same function once
    if (filter(this.listeners[type], function (item) { return item === listener; }).length === 0) {
      this.listeners[type].push(listener);
    }
  }
};

/*
 * Removes the listener so it will no longer be invoked via the dispatchEvent method.
 *
 * @param {string} type - the type of event (ie: 'open', 'message', etc.)
 * @param {function} listener - callback function to invoke when an event is dispatched matching the type
 * @param {boolean} useCapture - N/A TODO: implement useCapture functionality
 */
EventTarget.prototype.removeEventListener = function removeEventListener (type, removingListener /* , useCapture */) {
  var arrayOfListeners = this.listeners[type];
  this.listeners[type] = reject(arrayOfListeners, function (listener) { return listener === removingListener; });
};

/*
 * Invokes all listener functions that are listening to the given event.type property. Each
 * listener will be passed the event as the first argument.
 *
 * @param {object} event - event object which will be passed to all listeners of the event.type property
 */
EventTarget.prototype.dispatchEvent = function dispatchEvent (event) {
    var this$1 = this;
    var customArguments = [], len = arguments.length - 1;
    while ( len-- > 0 ) customArguments[ len ] = arguments[ len + 1 ];

  var eventName = event.type;
  var listeners = this.listeners[eventName];

  if (!Array.isArray(listeners)) {
    return false;
  }

  listeners.forEach(function (listener) {
    if (customArguments.length > 0) {
      listener.apply(this$1, customArguments);
    } else {
      listener.call(this$1, event);
    }
  });

  return true;
};

/*
 * The network bridge is a way for the mock websocket object to 'communicate' with
 * all available servers. This is a singleton object so it is important that you
 * clean up urlMap whenever you are finished.
 */
var NetworkBridge = function NetworkBridge() {
  this.urlMap = {};
};

/*
 * Attaches a websocket object to the urlMap hash so that it can find the server
 * it is connected to and the server in turn can find it.
 *
 * @param {object} websocket - websocket object to add to the urlMap hash
 * @param {string} url
 */
NetworkBridge.prototype.attachWebSocket = function attachWebSocket (websocket, url) {
  var connectionLookup = this.urlMap[url];

  if (connectionLookup && connectionLookup.server && connectionLookup.websockets.indexOf(websocket) === -1) {
    connectionLookup.websockets.push(websocket);
    return connectionLookup.server;
  }
};

/*
 * Attaches a websocket to a room
 */
NetworkBridge.prototype.addMembershipToRoom = function addMembershipToRoom (websocket, room) {
  var connectionLookup = this.urlMap[websocket.url];

  if (connectionLookup && connectionLookup.server && connectionLookup.websockets.indexOf(websocket) !== -1) {
    if (!connectionLookup.roomMemberships[room]) {
      connectionLookup.roomMemberships[room] = [];
    }

    connectionLookup.roomMemberships[room].push(websocket);
  }
};

/*
 * Attaches a server object to the urlMap hash so that it can find a websockets
 * which are connected to it and so that websockets can in turn can find it.
 *
 * @param {object} server - server object to add to the urlMap hash
 * @param {string} url
 */
NetworkBridge.prototype.attachServer = function attachServer (server, url) {
  var connectionLookup = this.urlMap[url];

  if (!connectionLookup) {
    this.urlMap[url] = {
      server: server,
      websockets: [],
      roomMemberships: {}
    };

    return server;
  }
};

/*
 * Finds the server which is 'running' on the given url.
 *
 * @param {string} url - the url to use to find which server is running on it
 */
NetworkBridge.prototype.serverLookup = function serverLookup (url) {
  var connectionLookup = this.urlMap[url];

  if (connectionLookup) {
    return connectionLookup.server;
  }
};

/*
 * Finds all websockets which is 'listening' on the given url.
 *
 * @param {string} url - the url to use to find all websockets which are associated with it
 * @param {string} room - if a room is provided, will only return sockets in this room
 * @param {class} broadcaster - socket that is broadcasting and is to be excluded from the lookup
 */
NetworkBridge.prototype.websocketsLookup = function websocketsLookup (url, room, broadcaster) {
  var websockets;
  var connectionLookup = this.urlMap[url];

  websockets = connectionLookup ? connectionLookup.websockets : [];

  if (room) {
    var members = connectionLookup.roomMemberships[room];
    websockets = members || [];
  }

  return broadcaster ? websockets.filter(function (websocket) { return websocket !== broadcaster; }) : websockets;
};

/*
 * Removes the entry associated with the url.
 *
 * @param {string} url
 */
NetworkBridge.prototype.removeServer = function removeServer (url) {
  delete this.urlMap[url];
};

/*
 * Removes the individual websocket from the map of associated websockets.
 *
 * @param {object} websocket - websocket object to remove from the url map
 * @param {string} url
 */
NetworkBridge.prototype.removeWebSocket = function removeWebSocket (websocket, url) {
  var connectionLookup = this.urlMap[url];

  if (connectionLookup) {
    connectionLookup.websockets = reject(connectionLookup.websockets, function (socket) { return socket === websocket; });
  }
};

/*
 * Removes a websocket from a room
 */
NetworkBridge.prototype.removeMembershipFromRoom = function removeMembershipFromRoom (websocket, room) {
  var connectionLookup = this.urlMap[websocket.url];
  var memberships = connectionLookup.roomMemberships[room];

  if (connectionLookup && memberships !== null) {
    connectionLookup.roomMemberships[room] = reject(memberships, function (socket) { return socket === websocket; });
  }
};

var networkBridge = new NetworkBridge(); // Note: this is a singleton

/*
 * https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent
 */
var CLOSE_CODES = {
  CLOSE_NORMAL: 1000,
  CLOSE_GOING_AWAY: 1001,
  CLOSE_PROTOCOL_ERROR: 1002,
  CLOSE_UNSUPPORTED: 1003,
  CLOSE_NO_STATUS: 1005,
  CLOSE_ABNORMAL: 1006,
  UNSUPPORTED_DATA: 1007,
  POLICY_VIOLATION: 1008,
  CLOSE_TOO_LARGE: 1009,
  MISSING_EXTENSION: 1010,
  INTERNAL_ERROR: 1011,
  SERVICE_RESTART: 1012,
  TRY_AGAIN_LATER: 1013,
  TLS_HANDSHAKE: 1015
};

var ERROR_PREFIX = {
  CONSTRUCTOR_ERROR: "Failed to construct 'WebSocket':",
  CLOSE_ERROR: "Failed to execute 'close' on 'WebSocket':",
  EVENT: {
    CONSTRUCT: "Failed to construct 'Event':",
    MESSAGE: "Failed to construct 'MessageEvent':",
    CLOSE: "Failed to construct 'CloseEvent':"
  }
};

var EventPrototype = function EventPrototype () {};

EventPrototype.prototype.stopPropagation = function stopPropagation () {};
EventPrototype.prototype.stopImmediatePropagation = function stopImmediatePropagation () {};

// if no arguments are passed then the type is set to "undefined" on
// chrome and safari.
EventPrototype.prototype.initEvent = function initEvent (type, bubbles, cancelable) {
    if ( type === void 0 ) type = 'undefined';
    if ( bubbles === void 0 ) bubbles = false;
    if ( cancelable === void 0 ) cancelable = false;

  this.type = "" + type;
  this.bubbles = Boolean(bubbles);
  this.cancelable = Boolean(cancelable);
};

var Event = (function (EventPrototype$$1) {
  function Event(type, eventInitConfig) {
    if ( eventInitConfig === void 0 ) eventInitConfig = {};

    EventPrototype$$1.call(this);

    if (!type) {
      throw new TypeError(((ERROR_PREFIX.EVENT_ERROR) + " 1 argument required, but only 0 present."));
    }

    if (typeof eventInitConfig !== 'object') {
      throw new TypeError(((ERROR_PREFIX.EVENT_ERROR) + " parameter 2 ('eventInitDict') is not an object."));
    }

    var bubbles = eventInitConfig.bubbles;
    var cancelable = eventInitConfig.cancelable;

    this.type = "" + type;
    this.timeStamp = Date.now();
    this.target = null;
    this.srcElement = null;
    this.returnValue = true;
    this.isTrusted = false;
    this.eventPhase = 0;
    this.defaultPrevented = false;
    this.currentTarget = null;
    this.cancelable = cancelable ? Boolean(cancelable) : false;
    this.canncelBubble = false;
    this.bubbles = bubbles ? Boolean(bubbles) : false;
  }

  if ( EventPrototype$$1 ) Event.__proto__ = EventPrototype$$1;
  Event.prototype = Object.create( EventPrototype$$1 && EventPrototype$$1.prototype );
  Event.prototype.constructor = Event;

  return Event;
}(EventPrototype));

var MessageEvent = (function (EventPrototype$$1) {
  function MessageEvent(type, eventInitConfig) {
    if ( eventInitConfig === void 0 ) eventInitConfig = {};

    EventPrototype$$1.call(this);

    if (!type) {
      throw new TypeError(((ERROR_PREFIX.EVENT.MESSAGE) + " 1 argument required, but only 0 present."));
    }

    if (typeof eventInitConfig !== 'object') {
      throw new TypeError(((ERROR_PREFIX.EVENT.MESSAGE) + " parameter 2 ('eventInitDict') is not an object"));
    }

    var bubbles = eventInitConfig.bubbles;
    var cancelable = eventInitConfig.cancelable;
    var data = eventInitConfig.data;
    var origin = eventInitConfig.origin;
    var lastEventId = eventInitConfig.lastEventId;
    var ports = eventInitConfig.ports;

    this.type = "" + type;
    this.timeStamp = Date.now();
    this.target = null;
    this.srcElement = null;
    this.returnValue = true;
    this.isTrusted = false;
    this.eventPhase = 0;
    this.defaultPrevented = false;
    this.currentTarget = null;
    this.cancelable = cancelable ? Boolean(cancelable) : false;
    this.canncelBubble = false;
    this.bubbles = bubbles ? Boolean(bubbles) : false;
    this.origin = "" + origin;
    this.ports = typeof ports === 'undefined' ? null : ports;
    this.data = typeof data === 'undefined' ? null : data;
    this.lastEventId = "" + (lastEventId || '');
  }

  if ( EventPrototype$$1 ) MessageEvent.__proto__ = EventPrototype$$1;
  MessageEvent.prototype = Object.create( EventPrototype$$1 && EventPrototype$$1.prototype );
  MessageEvent.prototype.constructor = MessageEvent;

  return MessageEvent;
}(EventPrototype));

var CloseEvent = (function (EventPrototype$$1) {
  function CloseEvent(type, eventInitConfig) {
    if ( eventInitConfig === void 0 ) eventInitConfig = {};

    EventPrototype$$1.call(this);

    if (!type) {
      throw new TypeError(((ERROR_PREFIX.EVENT.CLOSE) + " 1 argument required, but only 0 present."));
    }

    if (typeof eventInitConfig !== 'object') {
      throw new TypeError(((ERROR_PREFIX.EVENT.CLOSE) + " parameter 2 ('eventInitDict') is not an object"));
    }

    var bubbles = eventInitConfig.bubbles;
    var cancelable = eventInitConfig.cancelable;
    var code = eventInitConfig.code;
    var reason = eventInitConfig.reason;
    var wasClean = eventInitConfig.wasClean;

    this.type = "" + type;
    this.timeStamp = Date.now();
    this.target = null;
    this.srcElement = null;
    this.returnValue = true;
    this.isTrusted = false;
    this.eventPhase = 0;
    this.defaultPrevented = false;
    this.currentTarget = null;
    this.cancelable = cancelable ? Boolean(cancelable) : false;
    this.cancelBubble = false;
    this.bubbles = bubbles ? Boolean(bubbles) : false;
    this.code = typeof code === 'number' ? parseInt(code, 10) : 0;
    this.reason = "" + (reason || '');
    this.wasClean = wasClean ? Boolean(wasClean) : false;
  }

  if ( EventPrototype$$1 ) CloseEvent.__proto__ = EventPrototype$$1;
  CloseEvent.prototype = Object.create( EventPrototype$$1 && EventPrototype$$1.prototype );
  CloseEvent.prototype.constructor = CloseEvent;

  return CloseEvent;
}(EventPrototype));

/*
 * Creates an Event object and extends it to allow full modification of
 * its properties.
 *
 * @param {object} config - within config you will need to pass type and optionally target
 */
function createEvent(config) {
  var type = config.type;
  var target = config.target;
  var eventObject = new Event(type);

  if (target) {
    eventObject.target = target;
    eventObject.srcElement = target;
    eventObject.currentTarget = target;
  }

  return eventObject;
}

/*
 * Creates a MessageEvent object and extends it to allow full modification of
 * its properties.
 *
 * @param {object} config - within config: type, origin, data and optionally target
 */
function createMessageEvent(config) {
  var type = config.type;
  var origin = config.origin;
  var data = config.data;
  var target = config.target;
  var messageEvent = new MessageEvent(type, {
    data: data,
    origin: origin
  });

  if (target) {
    messageEvent.target = target;
    messageEvent.srcElement = target;
    messageEvent.currentTarget = target;
  }

  return messageEvent;
}

/*
 * Creates a CloseEvent object and extends it to allow full modification of
 * its properties.
 *
 * @param {object} config - within config: type and optionally target, code, and reason
 */
function createCloseEvent(config) {
  var code = config.code;
  var reason = config.reason;
  var type = config.type;
  var target = config.target;
  var wasClean = config.wasClean;

  if (!wasClean) {
    wasClean = code === 1000;
  }

  var closeEvent = new CloseEvent(type, {
    code: code,
    reason: reason,
    wasClean: wasClean
  });

  if (target) {
    closeEvent.target = target;
    closeEvent.srcElement = target;
    closeEvent.currentTarget = target;
  }

  return closeEvent;
}

function closeWebSocketConnection(context, code, reason) {
  context.readyState = WebSocket$1.CLOSING;

  var server = networkBridge.serverLookup(context.url);
  var closeEvent = createCloseEvent({
    type: 'close',
    target: context,
    code: code,
    reason: reason
  });

  delay(function () {
    networkBridge.removeWebSocket(context, context.url);

    context.readyState = WebSocket$1.CLOSED;
    context.dispatchEvent(closeEvent);

    if (server) {
      server.dispatchEvent(closeEvent, server);
    }
  }, context);
}

function failWebSocketConnection(context, code, reason) {
  context.readyState = WebSocket$1.CLOSING;

  var server = networkBridge.serverLookup(context.url);
  var closeEvent = createCloseEvent({
    type: 'close',
    target: context,
    code: code,
    reason: reason,
    wasClean: false
  });

  var errorEvent = createEvent({
    type: 'error',
    target: context
  });

  delay(function () {
    networkBridge.removeWebSocket(context, context.url);

    context.readyState = WebSocket$1.CLOSED;
    context.dispatchEvent(errorEvent);
    context.dispatchEvent(closeEvent);

    if (server) {
      server.dispatchEvent(closeEvent, server);
    }
  }, context);
}

function normalizeSendData(data) {
  if (Object.prototype.toString.call(data) !== '[object Blob]' && !(data instanceof ArrayBuffer)) {
    data = String(data);
  }

  return data;
}

function proxyFactory(target) {
  var handler = {
    get: function get(obj, prop) {
      if (prop === 'close') {
        return function close(options) {
          if ( options === void 0 ) options = {};

          var code = options.code || CLOSE_CODES.CLOSE_NORMAL;
          var reason = options.reason || '';

          closeWebSocketConnection(target, code, reason);
        };
      }

      if (prop === 'send') {
        return function send(data) {
          data = normalizeSendData(data);

          target.dispatchEvent(
            createMessageEvent({
              type: 'message',
              data: data,
              origin: this.url,
              target: target
            })
          );
        };
      }

      if (prop === 'on') {
        return function onWrapper(type, cb) {
          target.addEventListener(("server::" + type), cb);
        };
      }

      return obj[prop];
    }
  };

  var proxy = new Proxy(target, handler);
  return proxy;
}

function lengthInUtf8Bytes(str) {
  // Matches only the 10.. bytes that are non-initial characters in a multi-byte sequence.
  var m = encodeURIComponent(str).match(/%[89ABab]/g);
  return str.length + (m ? m.length : 0);
}

function urlVerification(url) {
  var urlRecord = new urlParse(url);
  var pathname = urlRecord.pathname;
  var protocol = urlRecord.protocol;
  var hash = urlRecord.hash;

  if (!url) {
    throw new TypeError(((ERROR_PREFIX.CONSTRUCTOR_ERROR) + " 1 argument required, but only 0 present."));
  }

  if (!pathname) {
    urlRecord.pathname = '/';
  }

  if (protocol === '') {
    throw new SyntaxError(((ERROR_PREFIX.CONSTRUCTOR_ERROR) + " The URL '" + (urlRecord.toString()) + "' is invalid."));
  }

  if (protocol !== 'ws:' && protocol !== 'wss:') {
    throw new SyntaxError(
      ((ERROR_PREFIX.CONSTRUCTOR_ERROR) + " The URL's scheme must be either 'ws' or 'wss'. '" + protocol + "' is not allowed.")
    );
  }

  if (hash !== '') {
    /* eslint-disable max-len */
    throw new SyntaxError(
      ((ERROR_PREFIX.CONSTRUCTOR_ERROR) + " The URL contains a fragment identifier ('" + hash + "'). Fragment identifiers are not allowed in WebSocket URLs.")
    );
    /* eslint-enable max-len */
  }

  return urlRecord.toString();
}

function protocolVerification(protocols) {
  if ( protocols === void 0 ) protocols = [];

  if (!Array.isArray(protocols) && typeof protocols !== 'string') {
    throw new SyntaxError(((ERROR_PREFIX.CONSTRUCTOR_ERROR) + " The subprotocol '" + (protocols.toString()) + "' is invalid."));
  }

  if (typeof protocols === 'string') {
    protocols = [protocols];
  }

  var uniq = protocols
    .map(function (p) { return ({ count: 1, protocol: p }); })
    .reduce(function (a, b) {
      a[b.protocol] = (a[b.protocol] || 0) + b.count;
      return a;
    }, {});

  var duplicates = Object.keys(uniq).filter(function (a) { return uniq[a] > 1; });

  if (duplicates.length > 0) {
    throw new SyntaxError(((ERROR_PREFIX.CONSTRUCTOR_ERROR) + " The subprotocol '" + (duplicates[0]) + "' is duplicated."));
  }

  return protocols;
}

/*
 * The main websocket class which is designed to mimick the native WebSocket class as close
 * as possible.
 *
 * https://html.spec.whatwg.org/multipage/web-sockets.html
 */
var WebSocket$1 = (function (EventTarget$$1) {
  function WebSocket(url, protocols) {
    EventTarget$$1.call(this);

    this.url = urlVerification(url);
    protocols = protocolVerification(protocols);
    this.protocol = protocols[0] || '';

    this.binaryType = 'blob';
    this.readyState = WebSocket.CONNECTING;

    var server = networkBridge.attachWebSocket(this, this.url);

    /*
     * This delay is needed so that we dont trigger an event before the callbacks have been
     * setup. For example:
     *
     * var socket = new WebSocket('ws://localhost');
     *
     * If we dont have the delay then the event would be triggered right here and this is
     * before the onopen had a chance to register itself.
     *
     * socket.onopen = () => { // this would never be called };
     *
     * and with the delay the event gets triggered here after all of the callbacks have been
     * registered :-)
     */
    delay(function delayCallback() {
      if (server) {
        if (
          server.options.verifyClient &&
          typeof server.options.verifyClient === 'function' &&
          !server.options.verifyClient()
        ) {
          this.readyState = WebSocket.CLOSED;

          log(
            'error',
            ("WebSocket connection to '" + (this.url) + "' failed: HTTP Authentication failed; no valid credentials available")
          );

          networkBridge.removeWebSocket(this, this.url);
          this.dispatchEvent(createEvent({ type: 'error', target: this }));
          this.dispatchEvent(createCloseEvent({ type: 'close', target: this, code: CLOSE_CODES.CLOSE_NORMAL }));
        } else {
          if (server.options.selectProtocol && typeof server.options.selectProtocol === 'function') {
            var selectedProtocol = server.options.selectProtocol(protocols);
            var isFilled = selectedProtocol !== '';
            var isRequested = protocols.indexOf(selectedProtocol) !== -1;
            if (isFilled && !isRequested) {
              this.readyState = WebSocket.CLOSED;

              log('error', ("WebSocket connection to '" + (this.url) + "' failed: Invalid Sub-Protocol"));

              networkBridge.removeWebSocket(this, this.url);
              this.dispatchEvent(createEvent({ type: 'error', target: this }));
              this.dispatchEvent(createCloseEvent({ type: 'close', target: this, code: CLOSE_CODES.CLOSE_NORMAL }));
              return;
            }
            this.protocol = selectedProtocol;
          }
          this.readyState = WebSocket.OPEN;
          this.dispatchEvent(createEvent({ type: 'open', target: this }));
          server.dispatchEvent(createEvent({ type: 'connection' }), proxyFactory(this));
        }
      } else {
        this.readyState = WebSocket.CLOSED;
        this.dispatchEvent(createEvent({ type: 'error', target: this }));
        this.dispatchEvent(createCloseEvent({ type: 'close', target: this, code: CLOSE_CODES.CLOSE_NORMAL }));

        log('error', ("WebSocket connection to '" + (this.url) + "' failed"));
      }
    }, this);
  }

  if ( EventTarget$$1 ) WebSocket.__proto__ = EventTarget$$1;
  WebSocket.prototype = Object.create( EventTarget$$1 && EventTarget$$1.prototype );
  WebSocket.prototype.constructor = WebSocket;

  var prototypeAccessors = { onopen: {},onmessage: {},onclose: {},onerror: {} };

  prototypeAccessors.onopen.get = function () {
    return this.listeners.open;
  };

  prototypeAccessors.onmessage.get = function () {
    return this.listeners.message;
  };

  prototypeAccessors.onclose.get = function () {
    return this.listeners.close;
  };

  prototypeAccessors.onerror.get = function () {
    return this.listeners.error;
  };

  prototypeAccessors.onopen.set = function (listener) {
    delete this.listeners.open;
    this.addEventListener('open', listener);
  };

  prototypeAccessors.onmessage.set = function (listener) {
    delete this.listeners.message;
    this.addEventListener('message', listener);
  };

  prototypeAccessors.onclose.set = function (listener) {
    delete this.listeners.close;
    this.addEventListener('close', listener);
  };

  prototypeAccessors.onerror.set = function (listener) {
    delete this.listeners.error;
    this.addEventListener('error', listener);
  };

  WebSocket.prototype.send = function send (data) {
    var this$1 = this;

    if (this.readyState === WebSocket.CLOSING || this.readyState === WebSocket.CLOSED) {
      throw new Error('WebSocket is already in CLOSING or CLOSED state');
    }

    // TODO: handle bufferedAmount

    var messageEvent = createMessageEvent({
      type: 'server::message',
      origin: this.url,
      data: normalizeSendData(data)
    });

    var server = networkBridge.serverLookup(this.url);

    if (server) {
      delay(function () {
        this$1.dispatchEvent(messageEvent, data);
      }, server);
    }
  };

  WebSocket.prototype.close = function close (code, reason) {
    if (code !== undefined) {
      if (typeof code !== 'number' || (code !== 1000 && (code < 3000 || code > 4999))) {
        throw new TypeError(
          ((ERROR_PREFIX.CLOSE_ERROR) + " The code must be either 1000, or between 3000 and 4999. " + code + " is neither.")
        );
      }
    }

    if (reason !== undefined) {
      var length = lengthInUtf8Bytes(reason);

      if (length > 123) {
        throw new SyntaxError(((ERROR_PREFIX.CLOSE_ERROR) + " The message must not be greater than 123 bytes."));
      }
    }

    if (this.readyState === WebSocket.CLOSING || this.readyState === WebSocket.CLOSED) {
      return;
    }

    if (this.readyState === WebSocket.CONNECTING) {
      failWebSocketConnection(this, code, reason);
    } else {
      closeWebSocketConnection(this, code, reason);
    }
  };

  Object.defineProperties( WebSocket.prototype, prototypeAccessors );

  return WebSocket;
}(EventTarget));

WebSocket$1.CONNECTING = 0;
WebSocket$1.prototype.CONNECTING = WebSocket$1.CONNECTING;
WebSocket$1.OPEN = 1;
WebSocket$1.prototype.OPEN = WebSocket$1.OPEN;
WebSocket$1.CLOSING = 2;
WebSocket$1.prototype.CLOSING = WebSocket$1.CLOSING;
WebSocket$1.CLOSED = 3;
WebSocket$1.prototype.CLOSED = WebSocket$1.CLOSED;

var dedupe = function (arr) { return arr.reduce(function (deduped, b) {
    if (deduped.indexOf(b) > -1) { return deduped; }
    return deduped.concat(b);
  }, []); };

function retrieveGlobalObject() {
  if (typeof window !== 'undefined') {
    return window;
  }

  return typeof process === 'object' && typeof require === 'function' && typeof global === 'object' ? global : this;
}

var Server$1 = (function (EventTarget$$1) {
  function Server(url, options) {
    if ( options === void 0 ) options = {};

    EventTarget$$1.call(this);
    var urlRecord = new urlParse(url);

    if (!urlRecord.pathname) {
      urlRecord.pathname = '/';
    }

    this.url = urlRecord.toString();

    this.originalWebSocket = null;
    var server = networkBridge.attachServer(this, this.url);

    if (!server) {
      this.dispatchEvent(createEvent({ type: 'error' }));
      throw new Error('A mock server is already listening on this url');
    }

    if (typeof options.verifyClient === 'undefined') {
      options.verifyClient = null;
    }

    if (typeof options.selectProtocol === 'undefined') {
      options.selectProtocol = null;
    }

    this.options = options;
    this.start();
  }

  if ( EventTarget$$1 ) Server.__proto__ = EventTarget$$1;
  Server.prototype = Object.create( EventTarget$$1 && EventTarget$$1.prototype );
  Server.prototype.constructor = Server;

  /*
   * Attaches the mock websocket object to the global object
   */
  Server.prototype.start = function start () {
    var globalObj = retrieveGlobalObject();

    if (globalObj.WebSocket) {
      this.originalWebSocket = globalObj.WebSocket;
    }

    globalObj.WebSocket = WebSocket$1;
  };

  /*
   * Removes the mock websocket object from the global object
   */
  Server.prototype.stop = function stop (callback) {
    if ( callback === void 0 ) callback = function () {};

    var globalObj = retrieveGlobalObject();

    if (this.originalWebSocket) {
      globalObj.WebSocket = this.originalWebSocket;
    } else {
      delete globalObj.WebSocket;
    }

    this.originalWebSocket = null;

    networkBridge.removeServer(this.url);

    if (typeof callback === 'function') {
      callback();
    }
  };

  /*
   * This is the main function for the mock server to subscribe to the on events.
   *
   * ie: mockServer.on('connection', function() { console.log('a mock client connected'); });
   *
   * @param {string} type - The event key to subscribe to. Valid keys are: connection, message, and close.
   * @param {function} callback - The callback which should be called when a certain event is fired.
   */
  Server.prototype.on = function on (type, callback) {
    this.addEventListener(type, callback);
  };

  /*
   * Closes the connection and triggers the onclose method of all listening
   * websockets. After that it removes itself from the urlMap so another server
   * could add itself to the url.
   *
   * @param {object} options
   */
  Server.prototype.close = function close (options) {
    if ( options === void 0 ) options = {};

    var code = options.code;
    var reason = options.reason;
    var wasClean = options.wasClean;
    var listeners = networkBridge.websocketsLookup(this.url);

    // Remove server before notifications to prevent immediate reconnects from
    // socket onclose handlers
    networkBridge.removeServer(this.url);

    listeners.forEach(function (socket) {
      socket.readyState = WebSocket$1.CLOSE;
      socket.dispatchEvent(
        createCloseEvent({
          type: 'close',
          target: socket,
          code: code || CLOSE_CODES.CLOSE_NORMAL,
          reason: reason || '',
          wasClean: wasClean
        })
      );
    });

    this.dispatchEvent(createCloseEvent({ type: 'close' }), this);
  };

  /*
   * Sends a generic message event to all mock clients.
   */
  Server.prototype.emit = function emit (event, data, options) {
    var this$1 = this;
    if ( options === void 0 ) options = {};

    var websockets = options.websockets;

    if (!websockets) {
      websockets = networkBridge.websocketsLookup(this.url);
    }

    if (typeof options !== 'object' || arguments.length > 3) {
      data = Array.prototype.slice.call(arguments, 1, arguments.length);
      data = data.map(function (item) { return normalizeSendData(item); });
    } else {
      data = normalizeSendData(data);
    }

    websockets.forEach(function (socket) {
      if (Array.isArray(data)) {
        socket.dispatchEvent.apply(
          socket, [ createMessageEvent({
            type: event,
            data: data,
            origin: this$1.url,
            target: socket
          }) ].concat( data )
        );
      } else {
        socket.dispatchEvent(
          createMessageEvent({
            type: event,
            data: data,
            origin: this$1.url,
            target: socket
          })
        );
      }
    });
  };

  /*
   * Returns an array of websockets which are listening to this server
   * TOOD: this should return a set and not be a method
   */
  Server.prototype.clients = function clients () {
    return networkBridge.websocketsLookup(this.url);
  };

  /*
   * Prepares a method to submit an event to members of the room
   *
   * e.g. server.to('my-room').emit('hi!');
   */
  Server.prototype.to = function to (room, broadcaster, broadcastList) {
    var this$1 = this;
    if ( broadcastList === void 0 ) broadcastList = [];

    var self = this;
    var websockets = dedupe(broadcastList.concat(networkBridge.websocketsLookup(this.url, room, broadcaster)));

    return {
      to: function (chainedRoom, chainedBroadcaster) { return this$1.to.call(this$1, chainedRoom, chainedBroadcaster, websockets); },
      emit: function emit(event, data) {
        self.emit(event, data, { websockets: websockets });
      }
    };
  };

  /*
   * Alias for Server.to
   */
  Server.prototype.in = function in$1 () {
    var args = [], len = arguments.length;
    while ( len-- ) args[ len ] = arguments[ len ];

    return this.to.apply(null, args);
  };

  /*
   * Simulate an event from the server to the clients. Useful for
   * simulating errors.
   */
  Server.prototype.simulate = function simulate (event, eventProps) {
    if ( eventProps === void 0 ) eventProps = {};

    var listeners = networkBridge.websocketsLookup(this.url);

    if (event === 'error') {
      listeners.forEach(function (socket) {
        socket.readyState = WebSocket$1.CLOSE;
        var eventConfig = Object.assign({type: 'error'}, eventProps);
        socket.dispatchEvent(createEvent(eventConfig));
      });
    }
  };

  return Server;
}(EventTarget));

/*
 * Alternative constructor to support namespaces in socket.io
 *
 * http://socket.io/docs/rooms-and-namespaces/#custom-namespaces
 */
Server$1.of = function of(url) {
  return new Server$1(url);
};

/*
 * The socket-io class is designed to mimick the real API as closely as possible.
 *
 * http://socket.io/docs/
 */
var SocketIO$1 = (function (EventTarget$$1) {
  function SocketIO(url, protocol) {
    var this$1 = this;
    if ( url === void 0 ) url = 'socket.io';
    if ( protocol === void 0 ) protocol = '';

    EventTarget$$1.call(this);

    this.binaryType = 'blob';
    var urlRecord = new urlParse(url);

    if (!urlRecord.pathname) {
      urlRecord.pathname = '/';
    }

    this.url = urlRecord.toString();
    this.readyState = SocketIO.CONNECTING;
    this.protocol = '';

    if (typeof protocol === 'string' || (typeof protocol === 'object' && protocol !== null)) {
      this.protocol = protocol;
    } else if (Array.isArray(protocol) && protocol.length > 0) {
      this.protocol = protocol[0];
    }

    var server = networkBridge.attachWebSocket(this, this.url);

    /*
     * Delay triggering the connection events so they can be defined in time.
     */
    delay(function delayCallback() {
      if (server) {
        this.readyState = SocketIO.OPEN;
        server.dispatchEvent(createEvent({ type: 'connection' }), server, this);
        server.dispatchEvent(createEvent({ type: 'connect' }), server, this); // alias
        this.dispatchEvent(createEvent({ type: 'connect', target: this }));
      } else {
        this.readyState = SocketIO.CLOSED;
        this.dispatchEvent(createEvent({ type: 'error', target: this }));
        this.dispatchEvent(
          createCloseEvent({
            type: 'close',
            target: this,
            code: CLOSE_CODES.CLOSE_NORMAL
          })
        );

        log('error', ("Socket.io connection to '" + (this.url) + "' failed"));
      }
    }, this);

    /**
      Add an aliased event listener for close / disconnect
     */
    this.addEventListener('close', function (event) {
      this$1.dispatchEvent(
        createCloseEvent({
          type: 'disconnect',
          target: event.target,
          code: event.code
        })
      );
    });
  }

  if ( EventTarget$$1 ) SocketIO.__proto__ = EventTarget$$1;
  SocketIO.prototype = Object.create( EventTarget$$1 && EventTarget$$1.prototype );
  SocketIO.prototype.constructor = SocketIO;

  var prototypeAccessors = { broadcast: {} };

  /*
   * Closes the SocketIO connection or connection attempt, if any.
   * If the connection is already CLOSED, this method does nothing.
   */
  SocketIO.prototype.close = function close () {
    if (this.readyState !== SocketIO.OPEN) {
      return undefined;
    }

    var server = networkBridge.serverLookup(this.url);
    networkBridge.removeWebSocket(this, this.url);

    this.readyState = SocketIO.CLOSED;
    this.dispatchEvent(
      createCloseEvent({
        type: 'close',
        target: this,
        code: CLOSE_CODES.CLOSE_NORMAL
      })
    );

    if (server) {
      server.dispatchEvent(
        createCloseEvent({
          type: 'disconnect',
          target: this,
          code: CLOSE_CODES.CLOSE_NORMAL
        }),
        server
      );
    }

    return this;
  };

  /*
   * Alias for Socket#close
   *
   * https://github.com/socketio/socket.io-client/blob/master/lib/socket.js#L383
   */
  SocketIO.prototype.disconnect = function disconnect () {
    return this.close();
  };

  /*
   * Submits an event to the server with a payload
   */
  SocketIO.prototype.emit = function emit (event) {
    var data = [], len = arguments.length - 1;
    while ( len-- > 0 ) data[ len ] = arguments[ len + 1 ];

    if (this.readyState !== SocketIO.OPEN) {
      throw new Error('SocketIO is already in CLOSING or CLOSED state');
    }

    var messageEvent = createMessageEvent({
      type: event,
      origin: this.url,
      data: data
    });

    var server = networkBridge.serverLookup(this.url);

    if (server) {
      server.dispatchEvent.apply(server, [ messageEvent ].concat( data ));
    }

    return this;
  };

  /*
   * Submits a 'message' event to the server.
   *
   * Should behave exactly like WebSocket#send
   *
   * https://github.com/socketio/socket.io-client/blob/master/lib/socket.js#L113
   */
  SocketIO.prototype.send = function send (data) {
    this.emit('message', data);
    return this;
  };

  /*
   * For broadcasting events to other connected sockets.
   *
   * e.g. socket.broadcast.emit('hi!');
   * e.g. socket.broadcast.to('my-room').emit('hi!');
   */
  prototypeAccessors.broadcast.get = function () {
    if (this.readyState !== SocketIO.OPEN) {
      throw new Error('SocketIO is already in CLOSING or CLOSED state');
    }

    var self = this;
    var server = networkBridge.serverLookup(this.url);
    if (!server) {
      throw new Error(("SocketIO can not find a server at the specified URL (" + (this.url) + ")"));
    }

    return {
      emit: function emit(event, data) {
        server.emit(event, data, { websockets: networkBridge.websocketsLookup(self.url, null, self) });
        return self;
      },
      to: function to(room) {
        return server.to(room, self);
      },
      in: function in$1(room) {
        return server.in(room, self);
      }
    };
  };

  /*
   * For registering events to be received from the server
   */
  SocketIO.prototype.on = function on (type, callback) {
    this.addEventListener(type, callback);
    return this;
  };

  /*
   * Remove event listener
   *
   * https://socket.io/docs/client-api/#socket-on-eventname-callback
   */
  SocketIO.prototype.off = function off (type) {
    this.removeEventListener(type);
  };

  /*
   * Join a room on a server
   *
   * http://socket.io/docs/rooms-and-namespaces/#joining-and-leaving
   */
  SocketIO.prototype.join = function join (room) {
    networkBridge.addMembershipToRoom(this, room);
  };

  /*
   * Get the websocket to leave the room
   *
   * http://socket.io/docs/rooms-and-namespaces/#joining-and-leaving
   */
  SocketIO.prototype.leave = function leave (room) {
    networkBridge.removeMembershipFromRoom(this, room);
  };

  SocketIO.prototype.to = function to (room) {
    return this.broadcast.to(room);
  };

  SocketIO.prototype.in = function in$1 () {
    return this.to.apply(null, arguments);
  };

  /*
   * Invokes all listener functions that are listening to the given event.type property. Each
   * listener will be passed the event as the first argument.
   *
   * @param {object} event - event object which will be passed to all listeners of the event.type property
   */
  SocketIO.prototype.dispatchEvent = function dispatchEvent (event) {
    var this$1 = this;
    var customArguments = [], len = arguments.length - 1;
    while ( len-- > 0 ) customArguments[ len ] = arguments[ len + 1 ];

    var eventName = event.type;
    var listeners = this.listeners[eventName];

    if (!Array.isArray(listeners)) {
      return false;
    }

    listeners.forEach(function (listener) {
      if (customArguments.length > 0) {
        listener.apply(this$1, customArguments);
      } else {
        // Regular WebSockets expect a MessageEvent but Socketio.io just wants raw data
        //  payload instanceof MessageEvent works, but you can't isntance of NodeEvent
        //  for now we detect if the output has data defined on it
        listener.call(this$1, event.data ? event.data : event);
      }
    });
  };

  Object.defineProperties( SocketIO.prototype, prototypeAccessors );

  return SocketIO;
}(EventTarget));

SocketIO$1.CONNECTING = 0;
SocketIO$1.OPEN = 1;
SocketIO$1.CLOSING = 2;
SocketIO$1.CLOSED = 3;

/*
 * Static constructor methods for the IO Socket
 */
var IO = function ioConstructor(url, protocol) {
  return new SocketIO$1(url, protocol);
};

/*
 * Alias the raw IO() constructor
 */
IO.connect = function ioConnect(url, protocol) {
  /* eslint-disable new-cap */
  return IO(url, protocol);
  /* eslint-enable new-cap */
};

var Server = Server$1;
var WebSocket = WebSocket$1;
var SocketIO = IO;

export { Server, WebSocket, SocketIO };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibW9jay1zb2NrZXQuZXMuanMiLCJzb3VyY2VzIjpbIi4uL25vZGVfbW9kdWxlcy9yZXF1aXJlcy1wb3J0L2luZGV4LmpzIiwiLi4vbm9kZV9tb2R1bGVzL3F1ZXJ5c3RyaW5naWZ5L2luZGV4LmpzIiwiLi4vbm9kZV9tb2R1bGVzL3VybC1wYXJzZS9pbmRleC5qcyIsIi4uL3NyYy9oZWxwZXJzL2RlbGF5LmpzIiwiLi4vc3JjL2hlbHBlcnMvbG9nZ2VyLmpzIiwiLi4vc3JjL2hlbHBlcnMvYXJyYXktaGVscGVycy5qcyIsIi4uL3NyYy9ldmVudC90YXJnZXQuanMiLCIuLi9zcmMvbmV0d29yay1icmlkZ2UuanMiLCIuLi9zcmMvY29uc3RhbnRzLmpzIiwiLi4vc3JjL2V2ZW50L3Byb3RvdHlwZS5qcyIsIi4uL3NyYy9ldmVudC9ldmVudC5qcyIsIi4uL3NyYy9ldmVudC9tZXNzYWdlLmpzIiwiLi4vc3JjL2V2ZW50L2Nsb3NlLmpzIiwiLi4vc3JjL2V2ZW50L2ZhY3RvcnkuanMiLCIuLi9zcmMvYWxnb3JpdGhtcy9jbG9zZS5qcyIsIi4uL3NyYy9oZWxwZXJzL25vcm1hbGl6ZS1zZW5kLmpzIiwiLi4vc3JjL2hlbHBlcnMvcHJveHktZmFjdG9yeS5qcyIsIi4uL3NyYy9oZWxwZXJzL2J5dGUtbGVuZ3RoLmpzIiwiLi4vc3JjL2hlbHBlcnMvdXJsLXZlcmlmaWNhdGlvbi5qcyIsIi4uL3NyYy9oZWxwZXJzL3Byb3RvY29sLXZlcmlmaWNhdGlvbi5qcyIsIi4uL3NyYy93ZWJzb2NrZXQuanMiLCIuLi9zcmMvaGVscGVycy9kZWR1cGUuanMiLCIuLi9zcmMvaGVscGVycy9nbG9iYWwtb2JqZWN0LmpzIiwiLi4vc3JjL3NlcnZlci5qcyIsIi4uL3NyYy9zb2NrZXQtaW8uanMiLCIuLi9zcmMvaW5kZXguanMiXSwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xuXG4vKipcbiAqIENoZWNrIGlmIHdlJ3JlIHJlcXVpcmVkIHRvIGFkZCBhIHBvcnQgbnVtYmVyLlxuICpcbiAqIEBzZWUgaHR0cHM6Ly91cmwuc3BlYy53aGF0d2cub3JnLyNkZWZhdWx0LXBvcnRcbiAqIEBwYXJhbSB7TnVtYmVyfFN0cmluZ30gcG9ydCBQb3J0IG51bWJlciB3ZSBuZWVkIHRvIGNoZWNrXG4gKiBAcGFyYW0ge1N0cmluZ30gcHJvdG9jb2wgUHJvdG9jb2wgd2UgbmVlZCB0byBjaGVjayBhZ2FpbnN0LlxuICogQHJldHVybnMge0Jvb2xlYW59IElzIGl0IGEgZGVmYXVsdCBwb3J0IGZvciB0aGUgZ2l2ZW4gcHJvdG9jb2xcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIHJlcXVpcmVkKHBvcnQsIHByb3RvY29sKSB7XG4gIHByb3RvY29sID0gcHJvdG9jb2wuc3BsaXQoJzonKVswXTtcbiAgcG9ydCA9ICtwb3J0O1xuXG4gIGlmICghcG9ydCkgcmV0dXJuIGZhbHNlO1xuXG4gIHN3aXRjaCAocHJvdG9jb2wpIHtcbiAgICBjYXNlICdodHRwJzpcbiAgICBjYXNlICd3cyc6XG4gICAgcmV0dXJuIHBvcnQgIT09IDgwO1xuXG4gICAgY2FzZSAnaHR0cHMnOlxuICAgIGNhc2UgJ3dzcyc6XG4gICAgcmV0dXJuIHBvcnQgIT09IDQ0MztcblxuICAgIGNhc2UgJ2Z0cCc6XG4gICAgcmV0dXJuIHBvcnQgIT09IDIxO1xuXG4gICAgY2FzZSAnZ29waGVyJzpcbiAgICByZXR1cm4gcG9ydCAhPT0gNzA7XG5cbiAgICBjYXNlICdmaWxlJzpcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICByZXR1cm4gcG9ydCAhPT0gMDtcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciBoYXMgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5XG4gICwgdW5kZWY7XG5cbi8qKlxuICogRGVjb2RlIGEgVVJJIGVuY29kZWQgc3RyaW5nLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgVVJJIGVuY29kZWQgc3RyaW5nLlxuICogQHJldHVybnMge1N0cmluZ30gVGhlIGRlY29kZWQgc3RyaW5nLlxuICogQGFwaSBwcml2YXRlXG4gKi9cbmZ1bmN0aW9uIGRlY29kZShpbnB1dCkge1xuICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KGlucHV0LnJlcGxhY2UoL1xcKy9nLCAnICcpKTtcbn1cblxuLyoqXG4gKiBTaW1wbGUgcXVlcnkgc3RyaW5nIHBhcnNlci5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gcXVlcnkgVGhlIHF1ZXJ5IHN0cmluZyB0aGF0IG5lZWRzIHRvIGJlIHBhcnNlZC5cbiAqIEByZXR1cm5zIHtPYmplY3R9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5mdW5jdGlvbiBxdWVyeXN0cmluZyhxdWVyeSkge1xuICB2YXIgcGFyc2VyID0gLyhbXj0/Jl0rKT0/KFteJl0qKS9nXG4gICAgLCByZXN1bHQgPSB7fVxuICAgICwgcGFydDtcblxuICB3aGlsZSAocGFydCA9IHBhcnNlci5leGVjKHF1ZXJ5KSkge1xuICAgIHZhciBrZXkgPSBkZWNvZGUocGFydFsxXSlcbiAgICAgICwgdmFsdWUgPSBkZWNvZGUocGFydFsyXSk7XG5cbiAgICAvL1xuICAgIC8vIFByZXZlbnQgb3ZlcnJpZGluZyBvZiBleGlzdGluZyBwcm9wZXJ0aWVzLiBUaGlzIGVuc3VyZXMgdGhhdCBidWlsZC1pblxuICAgIC8vIG1ldGhvZHMgbGlrZSBgdG9TdHJpbmdgIG9yIF9fcHJvdG9fXyBhcmUgbm90IG92ZXJyaWRlbiBieSBtYWxpY2lvdXNcbiAgICAvLyBxdWVyeXN0cmluZ3MuXG4gICAgLy9cbiAgICBpZiAoa2V5IGluIHJlc3VsdCkgY29udGludWU7XG4gICAgcmVzdWx0W2tleV0gPSB2YWx1ZTtcbiAgfVxuXG4gIHJldHVybiByZXN1bHQ7XG59XG5cbi8qKlxuICogVHJhbnNmb3JtIGEgcXVlcnkgc3RyaW5nIHRvIGFuIG9iamVjdC5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqIE9iamVjdCB0aGF0IHNob3VsZCBiZSB0cmFuc2Zvcm1lZC5cbiAqIEBwYXJhbSB7U3RyaW5nfSBwcmVmaXggT3B0aW9uYWwgcHJlZml4LlxuICogQHJldHVybnMge1N0cmluZ31cbiAqIEBhcGkgcHVibGljXG4gKi9cbmZ1bmN0aW9uIHF1ZXJ5c3RyaW5naWZ5KG9iaiwgcHJlZml4KSB7XG4gIHByZWZpeCA9IHByZWZpeCB8fCAnJztcblxuICB2YXIgcGFpcnMgPSBbXVxuICAgICwgdmFsdWVcbiAgICAsIGtleTtcblxuICAvL1xuICAvLyBPcHRpb25hbGx5IHByZWZpeCB3aXRoIGEgJz8nIGlmIG5lZWRlZFxuICAvL1xuICBpZiAoJ3N0cmluZycgIT09IHR5cGVvZiBwcmVmaXgpIHByZWZpeCA9ICc/JztcblxuICBmb3IgKGtleSBpbiBvYmopIHtcbiAgICBpZiAoaGFzLmNhbGwob2JqLCBrZXkpKSB7XG4gICAgICB2YWx1ZSA9IG9ialtrZXldO1xuXG4gICAgICAvL1xuICAgICAgLy8gRWRnZSBjYXNlcyB3aGVyZSB3ZSBhY3R1YWxseSB3YW50IHRvIGVuY29kZSB0aGUgdmFsdWUgdG8gYW4gZW1wdHlcbiAgICAgIC8vIHN0cmluZyBpbnN0ZWFkIG9mIHRoZSBzdHJpbmdpZmllZCB2YWx1ZS5cbiAgICAgIC8vXG4gICAgICBpZiAoIXZhbHVlICYmICh2YWx1ZSA9PT0gbnVsbCB8fCB2YWx1ZSA9PT0gdW5kZWYgfHwgaXNOYU4odmFsdWUpKSkge1xuICAgICAgICB2YWx1ZSA9ICcnO1xuICAgICAgfVxuXG4gICAgICBwYWlycy5wdXNoKGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsnPScrIGVuY29kZVVSSUNvbXBvbmVudCh2YWx1ZSkpO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBwYWlycy5sZW5ndGggPyBwcmVmaXggKyBwYWlycy5qb2luKCcmJykgOiAnJztcbn1cblxuLy9cbi8vIEV4cG9zZSB0aGUgbW9kdWxlLlxuLy9cbmV4cG9ydHMuc3RyaW5naWZ5ID0gcXVlcnlzdHJpbmdpZnk7XG5leHBvcnRzLnBhcnNlID0gcXVlcnlzdHJpbmc7XG4iLCIndXNlIHN0cmljdCc7XG5cbnZhciByZXF1aXJlZCA9IHJlcXVpcmUoJ3JlcXVpcmVzLXBvcnQnKVxuICAsIHFzID0gcmVxdWlyZSgncXVlcnlzdHJpbmdpZnknKVxuICAsIHByb3RvY29scmUgPSAvXihbYS16XVthLXowLTkuKy1dKjopPyhcXC9cXC8pPyhbXFxTXFxzXSopL2lcbiAgLCBzbGFzaGVzID0gL15bQS1aYS16XVtBLVphLXowLTkrLS5dKjpcXC9cXC8vO1xuXG4vKipcbiAqIFRoZXNlIGFyZSB0aGUgcGFyc2UgcnVsZXMgZm9yIHRoZSBVUkwgcGFyc2VyLCBpdCBpbmZvcm1zIHRoZSBwYXJzZXJcbiAqIGFib3V0OlxuICpcbiAqIDAuIFRoZSBjaGFyIGl0IE5lZWRzIHRvIHBhcnNlLCBpZiBpdCdzIGEgc3RyaW5nIGl0IHNob3VsZCBiZSBkb25lIHVzaW5nXG4gKiAgICBpbmRleE9mLCBSZWdFeHAgdXNpbmcgZXhlYyBhbmQgTmFOIG1lYW5zIHNldCBhcyBjdXJyZW50IHZhbHVlLlxuICogMS4gVGhlIHByb3BlcnR5IHdlIHNob3VsZCBzZXQgd2hlbiBwYXJzaW5nIHRoaXMgdmFsdWUuXG4gKiAyLiBJbmRpY2F0aW9uIGlmIGl0J3MgYmFja3dhcmRzIG9yIGZvcndhcmQgcGFyc2luZywgd2hlbiBzZXQgYXMgbnVtYmVyIGl0J3NcbiAqICAgIHRoZSB2YWx1ZSBvZiBleHRyYSBjaGFycyB0aGF0IHNob3VsZCBiZSBzcGxpdCBvZmYuXG4gKiAzLiBJbmhlcml0IGZyb20gbG9jYXRpb24gaWYgbm9uIGV4aXN0aW5nIGluIHRoZSBwYXJzZXIuXG4gKiA0LiBgdG9Mb3dlckNhc2VgIHRoZSByZXN1bHRpbmcgdmFsdWUuXG4gKi9cbnZhciBydWxlcyA9IFtcbiAgWycjJywgJ2hhc2gnXSwgICAgICAgICAgICAgICAgICAgICAgICAvLyBFeHRyYWN0IGZyb20gdGhlIGJhY2suXG4gIFsnPycsICdxdWVyeSddLCAgICAgICAgICAgICAgICAgICAgICAgLy8gRXh0cmFjdCBmcm9tIHRoZSBiYWNrLlxuICBmdW5jdGlvbiBzYW5pdGl6ZShhZGRyZXNzKSB7ICAgICAgICAgIC8vIFNhbml0aXplIHdoYXQgaXMgbGVmdCBvZiB0aGUgYWRkcmVzc1xuICAgIHJldHVybiBhZGRyZXNzLnJlcGxhY2UoJ1xcXFwnLCAnLycpO1xuICB9LFxuICBbJy8nLCAncGF0aG5hbWUnXSwgICAgICAgICAgICAgICAgICAgIC8vIEV4dHJhY3QgZnJvbSB0aGUgYmFjay5cbiAgWydAJywgJ2F1dGgnLCAxXSwgICAgICAgICAgICAgICAgICAgICAvLyBFeHRyYWN0IGZyb20gdGhlIGZyb250LlxuICBbTmFOLCAnaG9zdCcsIHVuZGVmaW5lZCwgMSwgMV0sICAgICAgIC8vIFNldCBsZWZ0IG92ZXIgdmFsdWUuXG4gIFsvOihcXGQrKSQvLCAncG9ydCcsIHVuZGVmaW5lZCwgMV0sICAgIC8vIFJlZ0V4cCB0aGUgYmFjay5cbiAgW05hTiwgJ2hvc3RuYW1lJywgdW5kZWZpbmVkLCAxLCAxXSAgICAvLyBTZXQgbGVmdCBvdmVyLlxuXTtcblxuLyoqXG4gKiBUaGVzZSBwcm9wZXJ0aWVzIHNob3VsZCBub3QgYmUgY29waWVkIG9yIGluaGVyaXRlZCBmcm9tLiBUaGlzIGlzIG9ubHkgbmVlZGVkXG4gKiBmb3IgYWxsIG5vbiBibG9iIFVSTCdzIGFzIGEgYmxvYiBVUkwgZG9lcyBub3QgaW5jbHVkZSBhIGhhc2gsIG9ubHkgdGhlXG4gKiBvcmlnaW4uXG4gKlxuICogQHR5cGUge09iamVjdH1cbiAqIEBwcml2YXRlXG4gKi9cbnZhciBpZ25vcmUgPSB7IGhhc2g6IDEsIHF1ZXJ5OiAxIH07XG5cbi8qKlxuICogVGhlIGxvY2F0aW9uIG9iamVjdCBkaWZmZXJzIHdoZW4geW91ciBjb2RlIGlzIGxvYWRlZCB0aHJvdWdoIGEgbm9ybWFsIHBhZ2UsXG4gKiBXb3JrZXIgb3IgdGhyb3VnaCBhIHdvcmtlciB1c2luZyBhIGJsb2IuIEFuZCB3aXRoIHRoZSBibG9iYmxlIGJlZ2lucyB0aGVcbiAqIHRyb3VibGUgYXMgdGhlIGxvY2F0aW9uIG9iamVjdCB3aWxsIGNvbnRhaW4gdGhlIFVSTCBvZiB0aGUgYmxvYiwgbm90IHRoZVxuICogbG9jYXRpb24gb2YgdGhlIHBhZ2Ugd2hlcmUgb3VyIGNvZGUgaXMgbG9hZGVkIGluLiBUaGUgYWN0dWFsIG9yaWdpbiBpc1xuICogZW5jb2RlZCBpbiB0aGUgYHBhdGhuYW1lYCBzbyB3ZSBjYW4gdGhhbmtmdWxseSBnZW5lcmF0ZSBhIGdvb2QgXCJkZWZhdWx0XCJcbiAqIGxvY2F0aW9uIGZyb20gaXQgc28gd2UgY2FuIGdlbmVyYXRlIHByb3BlciByZWxhdGl2ZSBVUkwncyBhZ2Fpbi5cbiAqXG4gKiBAcGFyYW0ge09iamVjdHxTdHJpbmd9IGxvYyBPcHRpb25hbCBkZWZhdWx0IGxvY2F0aW9uIG9iamVjdC5cbiAqIEByZXR1cm5zIHtPYmplY3R9IGxvbGNhdGlvbiBvYmplY3QuXG4gKiBAcHVibGljXG4gKi9cbmZ1bmN0aW9uIGxvbGNhdGlvbihsb2MpIHtcbiAgdmFyIGdsb2JhbFZhcjtcblxuICBpZiAodHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCcpIGdsb2JhbFZhciA9IHdpbmRvdztcbiAgZWxzZSBpZiAodHlwZW9mIGdsb2JhbCAhPT0gJ3VuZGVmaW5lZCcpIGdsb2JhbFZhciA9IGdsb2JhbDtcbiAgZWxzZSBpZiAodHlwZW9mIHNlbGYgIT09ICd1bmRlZmluZWQnKSBnbG9iYWxWYXIgPSBzZWxmO1xuICBlbHNlIGdsb2JhbFZhciA9IHt9O1xuXG4gIHZhciBsb2NhdGlvbiA9IGdsb2JhbFZhci5sb2NhdGlvbiB8fCB7fTtcbiAgbG9jID0gbG9jIHx8IGxvY2F0aW9uO1xuXG4gIHZhciBmaW5hbGRlc3RpbmF0aW9uID0ge31cbiAgICAsIHR5cGUgPSB0eXBlb2YgbG9jXG4gICAgLCBrZXk7XG5cbiAgaWYgKCdibG9iOicgPT09IGxvYy5wcm90b2NvbCkge1xuICAgIGZpbmFsZGVzdGluYXRpb24gPSBuZXcgVXJsKHVuZXNjYXBlKGxvYy5wYXRobmFtZSksIHt9KTtcbiAgfSBlbHNlIGlmICgnc3RyaW5nJyA9PT0gdHlwZSkge1xuICAgIGZpbmFsZGVzdGluYXRpb24gPSBuZXcgVXJsKGxvYywge30pO1xuICAgIGZvciAoa2V5IGluIGlnbm9yZSkgZGVsZXRlIGZpbmFsZGVzdGluYXRpb25ba2V5XTtcbiAgfSBlbHNlIGlmICgnb2JqZWN0JyA9PT0gdHlwZSkge1xuICAgIGZvciAoa2V5IGluIGxvYykge1xuICAgICAgaWYgKGtleSBpbiBpZ25vcmUpIGNvbnRpbnVlO1xuICAgICAgZmluYWxkZXN0aW5hdGlvbltrZXldID0gbG9jW2tleV07XG4gICAgfVxuXG4gICAgaWYgKGZpbmFsZGVzdGluYXRpb24uc2xhc2hlcyA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICBmaW5hbGRlc3RpbmF0aW9uLnNsYXNoZXMgPSBzbGFzaGVzLnRlc3QobG9jLmhyZWYpO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBmaW5hbGRlc3RpbmF0aW9uO1xufVxuXG4vKipcbiAqIEB0eXBlZGVmIFByb3RvY29sRXh0cmFjdFxuICogQHR5cGUgT2JqZWN0XG4gKiBAcHJvcGVydHkge1N0cmluZ30gcHJvdG9jb2wgUHJvdG9jb2wgbWF0Y2hlZCBpbiB0aGUgVVJMLCBpbiBsb3dlcmNhc2UuXG4gKiBAcHJvcGVydHkge0Jvb2xlYW59IHNsYXNoZXMgYHRydWVgIGlmIHByb3RvY29sIGlzIGZvbGxvd2VkIGJ5IFwiLy9cIiwgZWxzZSBgZmFsc2VgLlxuICogQHByb3BlcnR5IHtTdHJpbmd9IHJlc3QgUmVzdCBvZiB0aGUgVVJMIHRoYXQgaXMgbm90IHBhcnQgb2YgdGhlIHByb3RvY29sLlxuICovXG5cbi8qKlxuICogRXh0cmFjdCBwcm90b2NvbCBpbmZvcm1hdGlvbiBmcm9tIGEgVVJMIHdpdGgvd2l0aG91dCBkb3VibGUgc2xhc2ggKFwiLy9cIikuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGFkZHJlc3MgVVJMIHdlIHdhbnQgdG8gZXh0cmFjdCBmcm9tLlxuICogQHJldHVybiB7UHJvdG9jb2xFeHRyYWN0fSBFeHRyYWN0ZWQgaW5mb3JtYXRpb24uXG4gKiBAcHJpdmF0ZVxuICovXG5mdW5jdGlvbiBleHRyYWN0UHJvdG9jb2woYWRkcmVzcykge1xuICB2YXIgbWF0Y2ggPSBwcm90b2NvbHJlLmV4ZWMoYWRkcmVzcyk7XG5cbiAgcmV0dXJuIHtcbiAgICBwcm90b2NvbDogbWF0Y2hbMV0gPyBtYXRjaFsxXS50b0xvd2VyQ2FzZSgpIDogJycsXG4gICAgc2xhc2hlczogISFtYXRjaFsyXSxcbiAgICByZXN0OiBtYXRjaFszXVxuICB9O1xufVxuXG4vKipcbiAqIFJlc29sdmUgYSByZWxhdGl2ZSBVUkwgcGF0aG5hbWUgYWdhaW5zdCBhIGJhc2UgVVJMIHBhdGhuYW1lLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSByZWxhdGl2ZSBQYXRobmFtZSBvZiB0aGUgcmVsYXRpdmUgVVJMLlxuICogQHBhcmFtIHtTdHJpbmd9IGJhc2UgUGF0aG5hbWUgb2YgdGhlIGJhc2UgVVJMLlxuICogQHJldHVybiB7U3RyaW5nfSBSZXNvbHZlZCBwYXRobmFtZS5cbiAqIEBwcml2YXRlXG4gKi9cbmZ1bmN0aW9uIHJlc29sdmUocmVsYXRpdmUsIGJhc2UpIHtcbiAgdmFyIHBhdGggPSAoYmFzZSB8fCAnLycpLnNwbGl0KCcvJykuc2xpY2UoMCwgLTEpLmNvbmNhdChyZWxhdGl2ZS5zcGxpdCgnLycpKVxuICAgICwgaSA9IHBhdGgubGVuZ3RoXG4gICAgLCBsYXN0ID0gcGF0aFtpIC0gMV1cbiAgICAsIHVuc2hpZnQgPSBmYWxzZVxuICAgICwgdXAgPSAwO1xuXG4gIHdoaWxlIChpLS0pIHtcbiAgICBpZiAocGF0aFtpXSA9PT0gJy4nKSB7XG4gICAgICBwYXRoLnNwbGljZShpLCAxKTtcbiAgICB9IGVsc2UgaWYgKHBhdGhbaV0gPT09ICcuLicpIHtcbiAgICAgIHBhdGguc3BsaWNlKGksIDEpO1xuICAgICAgdXArKztcbiAgICB9IGVsc2UgaWYgKHVwKSB7XG4gICAgICBpZiAoaSA9PT0gMCkgdW5zaGlmdCA9IHRydWU7XG4gICAgICBwYXRoLnNwbGljZShpLCAxKTtcbiAgICAgIHVwLS07XG4gICAgfVxuICB9XG5cbiAgaWYgKHVuc2hpZnQpIHBhdGgudW5zaGlmdCgnJyk7XG4gIGlmIChsYXN0ID09PSAnLicgfHwgbGFzdCA9PT0gJy4uJykgcGF0aC5wdXNoKCcnKTtcblxuICByZXR1cm4gcGF0aC5qb2luKCcvJyk7XG59XG5cbi8qKlxuICogVGhlIGFjdHVhbCBVUkwgaW5zdGFuY2UuIEluc3RlYWQgb2YgcmV0dXJuaW5nIGFuIG9iamVjdCB3ZSd2ZSBvcHRlZC1pbiB0b1xuICogY3JlYXRlIGFuIGFjdHVhbCBjb25zdHJ1Y3RvciBhcyBpdCdzIG11Y2ggbW9yZSBtZW1vcnkgZWZmaWNpZW50IGFuZFxuICogZmFzdGVyIGFuZCBpdCBwbGVhc2VzIG15IE9DRC5cbiAqXG4gKiBJdCBpcyB3b3J0aCBub3RpbmcgdGhhdCB3ZSBzaG91bGQgbm90IHVzZSBgVVJMYCBhcyBjbGFzcyBuYW1lIHRvIHByZXZlbnRcbiAqIGNsYXNoZXMgd2l0aCB0aGUgZ2xvYmFsIFVSTCBpbnN0YW5jZSB0aGF0IGdvdCBpbnRyb2R1Y2VkIGluIGJyb3dzZXJzLlxuICpcbiAqIEBjb25zdHJ1Y3RvclxuICogQHBhcmFtIHtTdHJpbmd9IGFkZHJlc3MgVVJMIHdlIHdhbnQgdG8gcGFyc2UuXG4gKiBAcGFyYW0ge09iamVjdHxTdHJpbmd9IFtsb2NhdGlvbl0gTG9jYXRpb24gZGVmYXVsdHMgZm9yIHJlbGF0aXZlIHBhdGhzLlxuICogQHBhcmFtIHtCb29sZWFufEZ1bmN0aW9ufSBbcGFyc2VyXSBQYXJzZXIgZm9yIHRoZSBxdWVyeSBzdHJpbmcuXG4gKiBAcHJpdmF0ZVxuICovXG5mdW5jdGlvbiBVcmwoYWRkcmVzcywgbG9jYXRpb24sIHBhcnNlcikge1xuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgVXJsKSkge1xuICAgIHJldHVybiBuZXcgVXJsKGFkZHJlc3MsIGxvY2F0aW9uLCBwYXJzZXIpO1xuICB9XG5cbiAgdmFyIHJlbGF0aXZlLCBleHRyYWN0ZWQsIHBhcnNlLCBpbnN0cnVjdGlvbiwgaW5kZXgsIGtleVxuICAgICwgaW5zdHJ1Y3Rpb25zID0gcnVsZXMuc2xpY2UoKVxuICAgICwgdHlwZSA9IHR5cGVvZiBsb2NhdGlvblxuICAgICwgdXJsID0gdGhpc1xuICAgICwgaSA9IDA7XG5cbiAgLy9cbiAgLy8gVGhlIGZvbGxvd2luZyBpZiBzdGF0ZW1lbnRzIGFsbG93cyB0aGlzIG1vZHVsZSB0d28gaGF2ZSBjb21wYXRpYmlsaXR5IHdpdGhcbiAgLy8gMiBkaWZmZXJlbnQgQVBJOlxuICAvL1xuICAvLyAxLiBOb2RlLmpzJ3MgYHVybC5wYXJzZWAgYXBpIHdoaWNoIGFjY2VwdHMgYSBVUkwsIGJvb2xlYW4gYXMgYXJndW1lbnRzXG4gIC8vICAgIHdoZXJlIHRoZSBib29sZWFuIGluZGljYXRlcyB0aGF0IHRoZSBxdWVyeSBzdHJpbmcgc2hvdWxkIGFsc28gYmUgcGFyc2VkLlxuICAvL1xuICAvLyAyLiBUaGUgYFVSTGAgaW50ZXJmYWNlIG9mIHRoZSBicm93c2VyIHdoaWNoIGFjY2VwdHMgYSBVUkwsIG9iamVjdCBhc1xuICAvLyAgICBhcmd1bWVudHMuIFRoZSBzdXBwbGllZCBvYmplY3Qgd2lsbCBiZSB1c2VkIGFzIGRlZmF1bHQgdmFsdWVzIC8gZmFsbC1iYWNrXG4gIC8vICAgIGZvciByZWxhdGl2ZSBwYXRocy5cbiAgLy9cbiAgaWYgKCdvYmplY3QnICE9PSB0eXBlICYmICdzdHJpbmcnICE9PSB0eXBlKSB7XG4gICAgcGFyc2VyID0gbG9jYXRpb247XG4gICAgbG9jYXRpb24gPSBudWxsO1xuICB9XG5cbiAgaWYgKHBhcnNlciAmJiAnZnVuY3Rpb24nICE9PSB0eXBlb2YgcGFyc2VyKSBwYXJzZXIgPSBxcy5wYXJzZTtcblxuICBsb2NhdGlvbiA9IGxvbGNhdGlvbihsb2NhdGlvbik7XG5cbiAgLy9cbiAgLy8gRXh0cmFjdCBwcm90b2NvbCBpbmZvcm1hdGlvbiBiZWZvcmUgcnVubmluZyB0aGUgaW5zdHJ1Y3Rpb25zLlxuICAvL1xuICBleHRyYWN0ZWQgPSBleHRyYWN0UHJvdG9jb2woYWRkcmVzcyB8fCAnJyk7XG4gIHJlbGF0aXZlID0gIWV4dHJhY3RlZC5wcm90b2NvbCAmJiAhZXh0cmFjdGVkLnNsYXNoZXM7XG4gIHVybC5zbGFzaGVzID0gZXh0cmFjdGVkLnNsYXNoZXMgfHwgcmVsYXRpdmUgJiYgbG9jYXRpb24uc2xhc2hlcztcbiAgdXJsLnByb3RvY29sID0gZXh0cmFjdGVkLnByb3RvY29sIHx8IGxvY2F0aW9uLnByb3RvY29sIHx8ICcnO1xuICBhZGRyZXNzID0gZXh0cmFjdGVkLnJlc3Q7XG5cbiAgLy9cbiAgLy8gV2hlbiB0aGUgYXV0aG9yaXR5IGNvbXBvbmVudCBpcyBhYnNlbnQgdGhlIFVSTCBzdGFydHMgd2l0aCBhIHBhdGhcbiAgLy8gY29tcG9uZW50LlxuICAvL1xuICBpZiAoIWV4dHJhY3RlZC5zbGFzaGVzKSBpbnN0cnVjdGlvbnNbM10gPSBbLyguKikvLCAncGF0aG5hbWUnXTtcblxuICBmb3IgKDsgaSA8IGluc3RydWN0aW9ucy5sZW5ndGg7IGkrKykge1xuICAgIGluc3RydWN0aW9uID0gaW5zdHJ1Y3Rpb25zW2ldO1xuXG4gICAgaWYgKHR5cGVvZiBpbnN0cnVjdGlvbiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgYWRkcmVzcyA9IGluc3RydWN0aW9uKGFkZHJlc3MpO1xuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgcGFyc2UgPSBpbnN0cnVjdGlvblswXTtcbiAgICBrZXkgPSBpbnN0cnVjdGlvblsxXTtcblxuICAgIGlmIChwYXJzZSAhPT0gcGFyc2UpIHtcbiAgICAgIHVybFtrZXldID0gYWRkcmVzcztcbiAgICB9IGVsc2UgaWYgKCdzdHJpbmcnID09PSB0eXBlb2YgcGFyc2UpIHtcbiAgICAgIGlmICh+KGluZGV4ID0gYWRkcmVzcy5pbmRleE9mKHBhcnNlKSkpIHtcbiAgICAgICAgaWYgKCdudW1iZXInID09PSB0eXBlb2YgaW5zdHJ1Y3Rpb25bMl0pIHtcbiAgICAgICAgICB1cmxba2V5XSA9IGFkZHJlc3Muc2xpY2UoMCwgaW5kZXgpO1xuICAgICAgICAgIGFkZHJlc3MgPSBhZGRyZXNzLnNsaWNlKGluZGV4ICsgaW5zdHJ1Y3Rpb25bMl0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHVybFtrZXldID0gYWRkcmVzcy5zbGljZShpbmRleCk7XG4gICAgICAgICAgYWRkcmVzcyA9IGFkZHJlc3Muc2xpY2UoMCwgaW5kZXgpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBlbHNlIGlmICgoaW5kZXggPSBwYXJzZS5leGVjKGFkZHJlc3MpKSkge1xuICAgICAgdXJsW2tleV0gPSBpbmRleFsxXTtcbiAgICAgIGFkZHJlc3MgPSBhZGRyZXNzLnNsaWNlKDAsIGluZGV4LmluZGV4KTtcbiAgICB9XG5cbiAgICB1cmxba2V5XSA9IHVybFtrZXldIHx8IChcbiAgICAgIHJlbGF0aXZlICYmIGluc3RydWN0aW9uWzNdID8gbG9jYXRpb25ba2V5XSB8fCAnJyA6ICcnXG4gICAgKTtcblxuICAgIC8vXG4gICAgLy8gSG9zdG5hbWUsIGhvc3QgYW5kIHByb3RvY29sIHNob3VsZCBiZSBsb3dlcmNhc2VkIHNvIHRoZXkgY2FuIGJlIHVzZWQgdG9cbiAgICAvLyBjcmVhdGUgYSBwcm9wZXIgYG9yaWdpbmAuXG4gICAgLy9cbiAgICBpZiAoaW5zdHJ1Y3Rpb25bNF0pIHVybFtrZXldID0gdXJsW2tleV0udG9Mb3dlckNhc2UoKTtcbiAgfVxuXG4gIC8vXG4gIC8vIEFsc28gcGFyc2UgdGhlIHN1cHBsaWVkIHF1ZXJ5IHN0cmluZyBpbiB0byBhbiBvYmplY3QuIElmIHdlJ3JlIHN1cHBsaWVkXG4gIC8vIHdpdGggYSBjdXN0b20gcGFyc2VyIGFzIGZ1bmN0aW9uIHVzZSB0aGF0IGluc3RlYWQgb2YgdGhlIGRlZmF1bHQgYnVpbGQtaW5cbiAgLy8gcGFyc2VyLlxuICAvL1xuICBpZiAocGFyc2VyKSB1cmwucXVlcnkgPSBwYXJzZXIodXJsLnF1ZXJ5KTtcblxuICAvL1xuICAvLyBJZiB0aGUgVVJMIGlzIHJlbGF0aXZlLCByZXNvbHZlIHRoZSBwYXRobmFtZSBhZ2FpbnN0IHRoZSBiYXNlIFVSTC5cbiAgLy9cbiAgaWYgKFxuICAgICAgcmVsYXRpdmVcbiAgICAmJiBsb2NhdGlvbi5zbGFzaGVzXG4gICAgJiYgdXJsLnBhdGhuYW1lLmNoYXJBdCgwKSAhPT0gJy8nXG4gICAgJiYgKHVybC5wYXRobmFtZSAhPT0gJycgfHwgbG9jYXRpb24ucGF0aG5hbWUgIT09ICcnKVxuICApIHtcbiAgICB1cmwucGF0aG5hbWUgPSByZXNvbHZlKHVybC5wYXRobmFtZSwgbG9jYXRpb24ucGF0aG5hbWUpO1xuICB9XG5cbiAgLy9cbiAgLy8gV2Ugc2hvdWxkIG5vdCBhZGQgcG9ydCBudW1iZXJzIGlmIHRoZXkgYXJlIGFscmVhZHkgdGhlIGRlZmF1bHQgcG9ydCBudW1iZXJcbiAgLy8gZm9yIGEgZ2l2ZW4gcHJvdG9jb2wuIEFzIHRoZSBob3N0IGFsc28gY29udGFpbnMgdGhlIHBvcnQgbnVtYmVyIHdlJ3JlIGdvaW5nXG4gIC8vIG92ZXJyaWRlIGl0IHdpdGggdGhlIGhvc3RuYW1lIHdoaWNoIGNvbnRhaW5zIG5vIHBvcnQgbnVtYmVyLlxuICAvL1xuICBpZiAoIXJlcXVpcmVkKHVybC5wb3J0LCB1cmwucHJvdG9jb2wpKSB7XG4gICAgdXJsLmhvc3QgPSB1cmwuaG9zdG5hbWU7XG4gICAgdXJsLnBvcnQgPSAnJztcbiAgfVxuXG4gIC8vXG4gIC8vIFBhcnNlIGRvd24gdGhlIGBhdXRoYCBmb3IgdGhlIHVzZXJuYW1lIGFuZCBwYXNzd29yZC5cbiAgLy9cbiAgdXJsLnVzZXJuYW1lID0gdXJsLnBhc3N3b3JkID0gJyc7XG4gIGlmICh1cmwuYXV0aCkge1xuICAgIGluc3RydWN0aW9uID0gdXJsLmF1dGguc3BsaXQoJzonKTtcbiAgICB1cmwudXNlcm5hbWUgPSBpbnN0cnVjdGlvblswXSB8fCAnJztcbiAgICB1cmwucGFzc3dvcmQgPSBpbnN0cnVjdGlvblsxXSB8fCAnJztcbiAgfVxuXG4gIHVybC5vcmlnaW4gPSB1cmwucHJvdG9jb2wgJiYgdXJsLmhvc3QgJiYgdXJsLnByb3RvY29sICE9PSAnZmlsZTonXG4gICAgPyB1cmwucHJvdG9jb2wgKycvLycrIHVybC5ob3N0XG4gICAgOiAnbnVsbCc7XG5cbiAgLy9cbiAgLy8gVGhlIGhyZWYgaXMganVzdCB0aGUgY29tcGlsZWQgcmVzdWx0LlxuICAvL1xuICB1cmwuaHJlZiA9IHVybC50b1N0cmluZygpO1xufVxuXG4vKipcbiAqIFRoaXMgaXMgY29udmVuaWVuY2UgbWV0aG9kIGZvciBjaGFuZ2luZyBwcm9wZXJ0aWVzIGluIHRoZSBVUkwgaW5zdGFuY2UgdG9cbiAqIGluc3VyZSB0aGF0IHRoZXkgYWxsIHByb3BhZ2F0ZSBjb3JyZWN0bHkuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHBhcnQgICAgICAgICAgUHJvcGVydHkgd2UgbmVlZCB0byBhZGp1c3QuXG4gKiBAcGFyYW0ge01peGVkfSB2YWx1ZSAgICAgICAgICBUaGUgbmV3bHkgYXNzaWduZWQgdmFsdWUuXG4gKiBAcGFyYW0ge0Jvb2xlYW58RnVuY3Rpb259IGZuICBXaGVuIHNldHRpbmcgdGhlIHF1ZXJ5LCBpdCB3aWxsIGJlIHRoZSBmdW5jdGlvblxuICogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdXNlZCB0byBwYXJzZSB0aGUgcXVlcnkuXG4gKiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBXaGVuIHNldHRpbmcgdGhlIHByb3RvY29sLCBkb3VibGUgc2xhc2ggd2lsbCBiZVxuICogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmVtb3ZlZCBmcm9tIHRoZSBmaW5hbCB1cmwgaWYgaXQgaXMgdHJ1ZS5cbiAqIEByZXR1cm5zIHtVUkx9IFVSTCBpbnN0YW5jZSBmb3IgY2hhaW5pbmcuXG4gKiBAcHVibGljXG4gKi9cbmZ1bmN0aW9uIHNldChwYXJ0LCB2YWx1ZSwgZm4pIHtcbiAgdmFyIHVybCA9IHRoaXM7XG5cbiAgc3dpdGNoIChwYXJ0KSB7XG4gICAgY2FzZSAncXVlcnknOlxuICAgICAgaWYgKCdzdHJpbmcnID09PSB0eXBlb2YgdmFsdWUgJiYgdmFsdWUubGVuZ3RoKSB7XG4gICAgICAgIHZhbHVlID0gKGZuIHx8IHFzLnBhcnNlKSh2YWx1ZSk7XG4gICAgICB9XG5cbiAgICAgIHVybFtwYXJ0XSA9IHZhbHVlO1xuICAgICAgYnJlYWs7XG5cbiAgICBjYXNlICdwb3J0JzpcbiAgICAgIHVybFtwYXJ0XSA9IHZhbHVlO1xuXG4gICAgICBpZiAoIXJlcXVpcmVkKHZhbHVlLCB1cmwucHJvdG9jb2wpKSB7XG4gICAgICAgIHVybC5ob3N0ID0gdXJsLmhvc3RuYW1lO1xuICAgICAgICB1cmxbcGFydF0gPSAnJztcbiAgICAgIH0gZWxzZSBpZiAodmFsdWUpIHtcbiAgICAgICAgdXJsLmhvc3QgPSB1cmwuaG9zdG5hbWUgKyc6JysgdmFsdWU7XG4gICAgICB9XG5cbiAgICAgIGJyZWFrO1xuXG4gICAgY2FzZSAnaG9zdG5hbWUnOlxuICAgICAgdXJsW3BhcnRdID0gdmFsdWU7XG5cbiAgICAgIGlmICh1cmwucG9ydCkgdmFsdWUgKz0gJzonKyB1cmwucG9ydDtcbiAgICAgIHVybC5ob3N0ID0gdmFsdWU7XG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ2hvc3QnOlxuICAgICAgdXJsW3BhcnRdID0gdmFsdWU7XG5cbiAgICAgIGlmICgvOlxcZCskLy50ZXN0KHZhbHVlKSkge1xuICAgICAgICB2YWx1ZSA9IHZhbHVlLnNwbGl0KCc6Jyk7XG4gICAgICAgIHVybC5wb3J0ID0gdmFsdWUucG9wKCk7XG4gICAgICAgIHVybC5ob3N0bmFtZSA9IHZhbHVlLmpvaW4oJzonKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHVybC5ob3N0bmFtZSA9IHZhbHVlO1xuICAgICAgICB1cmwucG9ydCA9ICcnO1xuICAgICAgfVxuXG4gICAgICBicmVhaztcblxuICAgIGNhc2UgJ3Byb3RvY29sJzpcbiAgICAgIHVybC5wcm90b2NvbCA9IHZhbHVlLnRvTG93ZXJDYXNlKCk7XG4gICAgICB1cmwuc2xhc2hlcyA9ICFmbjtcbiAgICAgIGJyZWFrO1xuXG4gICAgY2FzZSAncGF0aG5hbWUnOlxuICAgIGNhc2UgJ2hhc2gnOlxuICAgICAgaWYgKHZhbHVlKSB7XG4gICAgICAgIHZhciBjaGFyID0gcGFydCA9PT0gJ3BhdGhuYW1lJyA/ICcvJyA6ICcjJztcbiAgICAgICAgdXJsW3BhcnRdID0gdmFsdWUuY2hhckF0KDApICE9PSBjaGFyID8gY2hhciArIHZhbHVlIDogdmFsdWU7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB1cmxbcGFydF0gPSB2YWx1ZTtcbiAgICAgIH1cbiAgICAgIGJyZWFrO1xuXG4gICAgZGVmYXVsdDpcbiAgICAgIHVybFtwYXJ0XSA9IHZhbHVlO1xuICB9XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBydWxlcy5sZW5ndGg7IGkrKykge1xuICAgIHZhciBpbnMgPSBydWxlc1tpXTtcblxuICAgIGlmIChpbnNbNF0pIHVybFtpbnNbMV1dID0gdXJsW2luc1sxXV0udG9Mb3dlckNhc2UoKTtcbiAgfVxuXG4gIHVybC5vcmlnaW4gPSB1cmwucHJvdG9jb2wgJiYgdXJsLmhvc3QgJiYgdXJsLnByb3RvY29sICE9PSAnZmlsZTonXG4gICAgPyB1cmwucHJvdG9jb2wgKycvLycrIHVybC5ob3N0XG4gICAgOiAnbnVsbCc7XG5cbiAgdXJsLmhyZWYgPSB1cmwudG9TdHJpbmcoKTtcblxuICByZXR1cm4gdXJsO1xufVxuXG4vKipcbiAqIFRyYW5zZm9ybSB0aGUgcHJvcGVydGllcyBiYWNrIGluIHRvIGEgdmFsaWQgYW5kIGZ1bGwgVVJMIHN0cmluZy5cbiAqXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBzdHJpbmdpZnkgT3B0aW9uYWwgcXVlcnkgc3RyaW5naWZ5IGZ1bmN0aW9uLlxuICogQHJldHVybnMge1N0cmluZ30gQ29tcGlsZWQgdmVyc2lvbiBvZiB0aGUgVVJMLlxuICogQHB1YmxpY1xuICovXG5mdW5jdGlvbiB0b1N0cmluZyhzdHJpbmdpZnkpIHtcbiAgaWYgKCFzdHJpbmdpZnkgfHwgJ2Z1bmN0aW9uJyAhPT0gdHlwZW9mIHN0cmluZ2lmeSkgc3RyaW5naWZ5ID0gcXMuc3RyaW5naWZ5O1xuXG4gIHZhciBxdWVyeVxuICAgICwgdXJsID0gdGhpc1xuICAgICwgcHJvdG9jb2wgPSB1cmwucHJvdG9jb2w7XG5cbiAgaWYgKHByb3RvY29sICYmIHByb3RvY29sLmNoYXJBdChwcm90b2NvbC5sZW5ndGggLSAxKSAhPT0gJzonKSBwcm90b2NvbCArPSAnOic7XG5cbiAgdmFyIHJlc3VsdCA9IHByb3RvY29sICsgKHVybC5zbGFzaGVzID8gJy8vJyA6ICcnKTtcblxuICBpZiAodXJsLnVzZXJuYW1lKSB7XG4gICAgcmVzdWx0ICs9IHVybC51c2VybmFtZTtcbiAgICBpZiAodXJsLnBhc3N3b3JkKSByZXN1bHQgKz0gJzonKyB1cmwucGFzc3dvcmQ7XG4gICAgcmVzdWx0ICs9ICdAJztcbiAgfVxuXG4gIHJlc3VsdCArPSB1cmwuaG9zdCArIHVybC5wYXRobmFtZTtcblxuICBxdWVyeSA9ICdvYmplY3QnID09PSB0eXBlb2YgdXJsLnF1ZXJ5ID8gc3RyaW5naWZ5KHVybC5xdWVyeSkgOiB1cmwucXVlcnk7XG4gIGlmIChxdWVyeSkgcmVzdWx0ICs9ICc/JyAhPT0gcXVlcnkuY2hhckF0KDApID8gJz8nKyBxdWVyeSA6IHF1ZXJ5O1xuXG4gIGlmICh1cmwuaGFzaCkgcmVzdWx0ICs9IHVybC5oYXNoO1xuXG4gIHJldHVybiByZXN1bHQ7XG59XG5cblVybC5wcm90b3R5cGUgPSB7IHNldDogc2V0LCB0b1N0cmluZzogdG9TdHJpbmcgfTtcblxuLy9cbi8vIEV4cG9zZSB0aGUgVVJMIHBhcnNlciBhbmQgc29tZSBhZGRpdGlvbmFsIHByb3BlcnRpZXMgdGhhdCBtaWdodCBiZSB1c2VmdWwgZm9yXG4vLyBvdGhlcnMgb3IgdGVzdGluZy5cbi8vXG5VcmwuZXh0cmFjdFByb3RvY29sID0gZXh0cmFjdFByb3RvY29sO1xuVXJsLmxvY2F0aW9uID0gbG9sY2F0aW9uO1xuVXJsLnFzID0gcXM7XG5cbm1vZHVsZS5leHBvcnRzID0gVXJsO1xuIiwiLypcbiAqIFRoaXMgZGVsYXkgYWxsb3dzIHRoZSB0aHJlYWQgdG8gZmluaXNoIGFzc2lnbmluZyBpdHMgb24qIG1ldGhvZHNcbiAqIGJlZm9yZSBpbnZva2luZyB0aGUgZGVsYXkgY2FsbGJhY2suIFRoaXMgaXMgcHVyZWx5IGEgdGltaW5nIGhhY2suXG4gKiBodHRwOi8vZ2Vla2FieXRlLmJsb2dzcG90LmNvbS8yMDE0LzAxL2phdmFzY3JpcHQtZWZmZWN0LW9mLXNldHRpbmctc2V0dGltZW91dC5odG1sXG4gKlxuICogQHBhcmFtIHtjYWxsYmFjazogZnVuY3Rpb259IHRoZSBjYWxsYmFjayB3aGljaCB3aWxsIGJlIGludm9rZWQgYWZ0ZXIgdGhlIHRpbWVvdXRcbiAqIEBwYXJtYSB7Y29udGV4dDogb2JqZWN0fSB0aGUgY29udGV4dCBpbiB3aGljaCB0byBpbnZva2UgdGhlIGZ1bmN0aW9uXG4gKi9cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGRlbGF5KGNhbGxiYWNrLCBjb250ZXh0KSB7XG4gIHNldFRpbWVvdXQodGltZW91dENvbnRleHQgPT4gY2FsbGJhY2suY2FsbCh0aW1lb3V0Q29udGV4dCksIDQsIGNvbnRleHQpO1xufVxuIiwiZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gbG9nKG1ldGhvZCwgbWVzc2FnZSkge1xuICAvKiBlc2xpbnQtZGlzYWJsZSBuby1jb25zb2xlICovXG4gIGlmICh0eXBlb2YgcHJvY2VzcyAhPT0gJ3VuZGVmaW5lZCcgJiYgcHJvY2Vzcy5lbnYuTk9ERV9FTlYgIT09ICd0ZXN0Jykge1xuICAgIGNvbnNvbGVbbWV0aG9kXS5jYWxsKG51bGwsIG1lc3NhZ2UpO1xuICB9XG4gIC8qIGVzbGludC1lbmFibGUgbm8tY29uc29sZSAqL1xufVxuIiwiZXhwb3J0IGZ1bmN0aW9uIHJlamVjdChhcnJheSwgY2FsbGJhY2spIHtcbiAgY29uc3QgcmVzdWx0cyA9IFtdO1xuICBhcnJheS5mb3JFYWNoKGl0ZW1JbkFycmF5ID0+IHtcbiAgICBpZiAoIWNhbGxiYWNrKGl0ZW1JbkFycmF5KSkge1xuICAgICAgcmVzdWx0cy5wdXNoKGl0ZW1JbkFycmF5KTtcbiAgICB9XG4gIH0pO1xuXG4gIHJldHVybiByZXN1bHRzO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZmlsdGVyKGFycmF5LCBjYWxsYmFjaykge1xuICBjb25zdCByZXN1bHRzID0gW107XG4gIGFycmF5LmZvckVhY2goaXRlbUluQXJyYXkgPT4ge1xuICAgIGlmIChjYWxsYmFjayhpdGVtSW5BcnJheSkpIHtcbiAgICAgIHJlc3VsdHMucHVzaChpdGVtSW5BcnJheSk7XG4gICAgfVxuICB9KTtcblxuICByZXR1cm4gcmVzdWx0cztcbn1cbiIsImltcG9ydCB7IHJlamVjdCwgZmlsdGVyIH0gZnJvbSAnLi4vaGVscGVycy9hcnJheS1oZWxwZXJzJztcblxuLypcbiAqIEV2ZW50VGFyZ2V0IGlzIGFuIGludGVyZmFjZSBpbXBsZW1lbnRlZCBieSBvYmplY3RzIHRoYXQgY2FuXG4gKiByZWNlaXZlIGV2ZW50cyBhbmQgbWF5IGhhdmUgbGlzdGVuZXJzIGZvciB0aGVtLlxuICpcbiAqIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9FdmVudFRhcmdldFxuICovXG5jbGFzcyBFdmVudFRhcmdldCB7XG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHRoaXMubGlzdGVuZXJzID0ge307XG4gIH1cblxuICAvKlxuICAgKiBUaWVzIGEgbGlzdGVuZXIgZnVuY3Rpb24gdG8gYW4gZXZlbnQgdHlwZSB3aGljaCBjYW4gbGF0ZXIgYmUgaW52b2tlZCB2aWEgdGhlXG4gICAqIGRpc3BhdGNoRXZlbnQgbWV0aG9kLlxuICAgKlxuICAgKiBAcGFyYW0ge3N0cmluZ30gdHlwZSAtIHRoZSB0eXBlIG9mIGV2ZW50IChpZTogJ29wZW4nLCAnbWVzc2FnZScsIGV0Yy4pXG4gICAqIEBwYXJhbSB7ZnVuY3Rpb259IGxpc3RlbmVyIC0gY2FsbGJhY2sgZnVuY3Rpb24gdG8gaW52b2tlIHdoZW4gYW4gZXZlbnQgaXMgZGlzcGF0Y2hlZCBtYXRjaGluZyB0aGUgdHlwZVxuICAgKiBAcGFyYW0ge2Jvb2xlYW59IHVzZUNhcHR1cmUgLSBOL0EgVE9ETzogaW1wbGVtZW50IHVzZUNhcHR1cmUgZnVuY3Rpb25hbGl0eVxuICAgKi9cbiAgYWRkRXZlbnRMaXN0ZW5lcih0eXBlLCBsaXN0ZW5lciAvKiAsIHVzZUNhcHR1cmUgKi8pIHtcbiAgICBpZiAodHlwZW9mIGxpc3RlbmVyID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICBpZiAoIUFycmF5LmlzQXJyYXkodGhpcy5saXN0ZW5lcnNbdHlwZV0pKSB7XG4gICAgICAgIHRoaXMubGlzdGVuZXJzW3R5cGVdID0gW107XG4gICAgICB9XG5cbiAgICAgIC8vIE9ubHkgYWRkIHRoZSBzYW1lIGZ1bmN0aW9uIG9uY2VcbiAgICAgIGlmIChmaWx0ZXIodGhpcy5saXN0ZW5lcnNbdHlwZV0sIGl0ZW0gPT4gaXRlbSA9PT0gbGlzdGVuZXIpLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICB0aGlzLmxpc3RlbmVyc1t0eXBlXS5wdXNoKGxpc3RlbmVyKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvKlxuICAgKiBSZW1vdmVzIHRoZSBsaXN0ZW5lciBzbyBpdCB3aWxsIG5vIGxvbmdlciBiZSBpbnZva2VkIHZpYSB0aGUgZGlzcGF0Y2hFdmVudCBtZXRob2QuXG4gICAqXG4gICAqIEBwYXJhbSB7c3RyaW5nfSB0eXBlIC0gdGhlIHR5cGUgb2YgZXZlbnQgKGllOiAnb3BlbicsICdtZXNzYWdlJywgZXRjLilcbiAgICogQHBhcmFtIHtmdW5jdGlvbn0gbGlzdGVuZXIgLSBjYWxsYmFjayBmdW5jdGlvbiB0byBpbnZva2Ugd2hlbiBhbiBldmVudCBpcyBkaXNwYXRjaGVkIG1hdGNoaW5nIHRoZSB0eXBlXG4gICAqIEBwYXJhbSB7Ym9vbGVhbn0gdXNlQ2FwdHVyZSAtIE4vQSBUT0RPOiBpbXBsZW1lbnQgdXNlQ2FwdHVyZSBmdW5jdGlvbmFsaXR5XG4gICAqL1xuICByZW1vdmVFdmVudExpc3RlbmVyKHR5cGUsIHJlbW92aW5nTGlzdGVuZXIgLyogLCB1c2VDYXB0dXJlICovKSB7XG4gICAgY29uc3QgYXJyYXlPZkxpc3RlbmVycyA9IHRoaXMubGlzdGVuZXJzW3R5cGVdO1xuICAgIHRoaXMubGlzdGVuZXJzW3R5cGVdID0gcmVqZWN0KGFycmF5T2ZMaXN0ZW5lcnMsIGxpc3RlbmVyID0+IGxpc3RlbmVyID09PSByZW1vdmluZ0xpc3RlbmVyKTtcbiAgfVxuXG4gIC8qXG4gICAqIEludm9rZXMgYWxsIGxpc3RlbmVyIGZ1bmN0aW9ucyB0aGF0IGFyZSBsaXN0ZW5pbmcgdG8gdGhlIGdpdmVuIGV2ZW50LnR5cGUgcHJvcGVydHkuIEVhY2hcbiAgICogbGlzdGVuZXIgd2lsbCBiZSBwYXNzZWQgdGhlIGV2ZW50IGFzIHRoZSBmaXJzdCBhcmd1bWVudC5cbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9IGV2ZW50IC0gZXZlbnQgb2JqZWN0IHdoaWNoIHdpbGwgYmUgcGFzc2VkIHRvIGFsbCBsaXN0ZW5lcnMgb2YgdGhlIGV2ZW50LnR5cGUgcHJvcGVydHlcbiAgICovXG4gIGRpc3BhdGNoRXZlbnQoZXZlbnQsIC4uLmN1c3RvbUFyZ3VtZW50cykge1xuICAgIGNvbnN0IGV2ZW50TmFtZSA9IGV2ZW50LnR5cGU7XG4gICAgY29uc3QgbGlzdGVuZXJzID0gdGhpcy5saXN0ZW5lcnNbZXZlbnROYW1lXTtcblxuICAgIGlmICghQXJyYXkuaXNBcnJheShsaXN0ZW5lcnMpKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgbGlzdGVuZXJzLmZvckVhY2gobGlzdGVuZXIgPT4ge1xuICAgICAgaWYgKGN1c3RvbUFyZ3VtZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICAgIGxpc3RlbmVyLmFwcGx5KHRoaXMsIGN1c3RvbUFyZ3VtZW50cyk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBsaXN0ZW5lci5jYWxsKHRoaXMsIGV2ZW50KTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHJldHVybiB0cnVlO1xuICB9XG59XG5cbmV4cG9ydCBkZWZhdWx0IEV2ZW50VGFyZ2V0O1xuIiwiaW1wb3J0IHsgcmVqZWN0IH0gZnJvbSAnLi9oZWxwZXJzL2FycmF5LWhlbHBlcnMnO1xuXG4vKlxuICogVGhlIG5ldHdvcmsgYnJpZGdlIGlzIGEgd2F5IGZvciB0aGUgbW9jayB3ZWJzb2NrZXQgb2JqZWN0IHRvICdjb21tdW5pY2F0ZScgd2l0aFxuICogYWxsIGF2YWlsYWJsZSBzZXJ2ZXJzLiBUaGlzIGlzIGEgc2luZ2xldG9uIG9iamVjdCBzbyBpdCBpcyBpbXBvcnRhbnQgdGhhdCB5b3VcbiAqIGNsZWFuIHVwIHVybE1hcCB3aGVuZXZlciB5b3UgYXJlIGZpbmlzaGVkLlxuICovXG5jbGFzcyBOZXR3b3JrQnJpZGdlIHtcbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy51cmxNYXAgPSB7fTtcbiAgfVxuXG4gIC8qXG4gICAqIEF0dGFjaGVzIGEgd2Vic29ja2V0IG9iamVjdCB0byB0aGUgdXJsTWFwIGhhc2ggc28gdGhhdCBpdCBjYW4gZmluZCB0aGUgc2VydmVyXG4gICAqIGl0IGlzIGNvbm5lY3RlZCB0byBhbmQgdGhlIHNlcnZlciBpbiB0dXJuIGNhbiBmaW5kIGl0LlxuICAgKlxuICAgKiBAcGFyYW0ge29iamVjdH0gd2Vic29ja2V0IC0gd2Vic29ja2V0IG9iamVjdCB0byBhZGQgdG8gdGhlIHVybE1hcCBoYXNoXG4gICAqIEBwYXJhbSB7c3RyaW5nfSB1cmxcbiAgICovXG4gIGF0dGFjaFdlYlNvY2tldCh3ZWJzb2NrZXQsIHVybCkge1xuICAgIGNvbnN0IGNvbm5lY3Rpb25Mb29rdXAgPSB0aGlzLnVybE1hcFt1cmxdO1xuXG4gICAgaWYgKGNvbm5lY3Rpb25Mb29rdXAgJiYgY29ubmVjdGlvbkxvb2t1cC5zZXJ2ZXIgJiYgY29ubmVjdGlvbkxvb2t1cC53ZWJzb2NrZXRzLmluZGV4T2Yod2Vic29ja2V0KSA9PT0gLTEpIHtcbiAgICAgIGNvbm5lY3Rpb25Mb29rdXAud2Vic29ja2V0cy5wdXNoKHdlYnNvY2tldCk7XG4gICAgICByZXR1cm4gY29ubmVjdGlvbkxvb2t1cC5zZXJ2ZXI7XG4gICAgfVxuICB9XG5cbiAgLypcbiAgICogQXR0YWNoZXMgYSB3ZWJzb2NrZXQgdG8gYSByb29tXG4gICAqL1xuICBhZGRNZW1iZXJzaGlwVG9Sb29tKHdlYnNvY2tldCwgcm9vbSkge1xuICAgIGNvbnN0IGNvbm5lY3Rpb25Mb29rdXAgPSB0aGlzLnVybE1hcFt3ZWJzb2NrZXQudXJsXTtcblxuICAgIGlmIChjb25uZWN0aW9uTG9va3VwICYmIGNvbm5lY3Rpb25Mb29rdXAuc2VydmVyICYmIGNvbm5lY3Rpb25Mb29rdXAud2Vic29ja2V0cy5pbmRleE9mKHdlYnNvY2tldCkgIT09IC0xKSB7XG4gICAgICBpZiAoIWNvbm5lY3Rpb25Mb29rdXAucm9vbU1lbWJlcnNoaXBzW3Jvb21dKSB7XG4gICAgICAgIGNvbm5lY3Rpb25Mb29rdXAucm9vbU1lbWJlcnNoaXBzW3Jvb21dID0gW107XG4gICAgICB9XG5cbiAgICAgIGNvbm5lY3Rpb25Mb29rdXAucm9vbU1lbWJlcnNoaXBzW3Jvb21dLnB1c2god2Vic29ja2V0KTtcbiAgICB9XG4gIH1cblxuICAvKlxuICAgKiBBdHRhY2hlcyBhIHNlcnZlciBvYmplY3QgdG8gdGhlIHVybE1hcCBoYXNoIHNvIHRoYXQgaXQgY2FuIGZpbmQgYSB3ZWJzb2NrZXRzXG4gICAqIHdoaWNoIGFyZSBjb25uZWN0ZWQgdG8gaXQgYW5kIHNvIHRoYXQgd2Vic29ja2V0cyBjYW4gaW4gdHVybiBjYW4gZmluZCBpdC5cbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9IHNlcnZlciAtIHNlcnZlciBvYmplY3QgdG8gYWRkIHRvIHRoZSB1cmxNYXAgaGFzaFxuICAgKiBAcGFyYW0ge3N0cmluZ30gdXJsXG4gICAqL1xuICBhdHRhY2hTZXJ2ZXIoc2VydmVyLCB1cmwpIHtcbiAgICBjb25zdCBjb25uZWN0aW9uTG9va3VwID0gdGhpcy51cmxNYXBbdXJsXTtcblxuICAgIGlmICghY29ubmVjdGlvbkxvb2t1cCkge1xuICAgICAgdGhpcy51cmxNYXBbdXJsXSA9IHtcbiAgICAgICAgc2VydmVyLFxuICAgICAgICB3ZWJzb2NrZXRzOiBbXSxcbiAgICAgICAgcm9vbU1lbWJlcnNoaXBzOiB7fVxuICAgICAgfTtcblxuICAgICAgcmV0dXJuIHNlcnZlcjtcbiAgICB9XG4gIH1cblxuICAvKlxuICAgKiBGaW5kcyB0aGUgc2VydmVyIHdoaWNoIGlzICdydW5uaW5nJyBvbiB0aGUgZ2l2ZW4gdXJsLlxuICAgKlxuICAgKiBAcGFyYW0ge3N0cmluZ30gdXJsIC0gdGhlIHVybCB0byB1c2UgdG8gZmluZCB3aGljaCBzZXJ2ZXIgaXMgcnVubmluZyBvbiBpdFxuICAgKi9cbiAgc2VydmVyTG9va3VwKHVybCkge1xuICAgIGNvbnN0IGNvbm5lY3Rpb25Mb29rdXAgPSB0aGlzLnVybE1hcFt1cmxdO1xuXG4gICAgaWYgKGNvbm5lY3Rpb25Mb29rdXApIHtcbiAgICAgIHJldHVybiBjb25uZWN0aW9uTG9va3VwLnNlcnZlcjtcbiAgICB9XG4gIH1cblxuICAvKlxuICAgKiBGaW5kcyBhbGwgd2Vic29ja2V0cyB3aGljaCBpcyAnbGlzdGVuaW5nJyBvbiB0aGUgZ2l2ZW4gdXJsLlxuICAgKlxuICAgKiBAcGFyYW0ge3N0cmluZ30gdXJsIC0gdGhlIHVybCB0byB1c2UgdG8gZmluZCBhbGwgd2Vic29ja2V0cyB3aGljaCBhcmUgYXNzb2NpYXRlZCB3aXRoIGl0XG4gICAqIEBwYXJhbSB7c3RyaW5nfSByb29tIC0gaWYgYSByb29tIGlzIHByb3ZpZGVkLCB3aWxsIG9ubHkgcmV0dXJuIHNvY2tldHMgaW4gdGhpcyByb29tXG4gICAqIEBwYXJhbSB7Y2xhc3N9IGJyb2FkY2FzdGVyIC0gc29ja2V0IHRoYXQgaXMgYnJvYWRjYXN0aW5nIGFuZCBpcyB0byBiZSBleGNsdWRlZCBmcm9tIHRoZSBsb29rdXBcbiAgICovXG4gIHdlYnNvY2tldHNMb29rdXAodXJsLCByb29tLCBicm9hZGNhc3Rlcikge1xuICAgIGxldCB3ZWJzb2NrZXRzO1xuICAgIGNvbnN0IGNvbm5lY3Rpb25Mb29rdXAgPSB0aGlzLnVybE1hcFt1cmxdO1xuXG4gICAgd2Vic29ja2V0cyA9IGNvbm5lY3Rpb25Mb29rdXAgPyBjb25uZWN0aW9uTG9va3VwLndlYnNvY2tldHMgOiBbXTtcblxuICAgIGlmIChyb29tKSB7XG4gICAgICBjb25zdCBtZW1iZXJzID0gY29ubmVjdGlvbkxvb2t1cC5yb29tTWVtYmVyc2hpcHNbcm9vbV07XG4gICAgICB3ZWJzb2NrZXRzID0gbWVtYmVycyB8fCBbXTtcbiAgICB9XG5cbiAgICByZXR1cm4gYnJvYWRjYXN0ZXIgPyB3ZWJzb2NrZXRzLmZpbHRlcih3ZWJzb2NrZXQgPT4gd2Vic29ja2V0ICE9PSBicm9hZGNhc3RlcikgOiB3ZWJzb2NrZXRzO1xuICB9XG5cbiAgLypcbiAgICogUmVtb3ZlcyB0aGUgZW50cnkgYXNzb2NpYXRlZCB3aXRoIHRoZSB1cmwuXG4gICAqXG4gICAqIEBwYXJhbSB7c3RyaW5nfSB1cmxcbiAgICovXG4gIHJlbW92ZVNlcnZlcih1cmwpIHtcbiAgICBkZWxldGUgdGhpcy51cmxNYXBbdXJsXTtcbiAgfVxuXG4gIC8qXG4gICAqIFJlbW92ZXMgdGhlIGluZGl2aWR1YWwgd2Vic29ja2V0IGZyb20gdGhlIG1hcCBvZiBhc3NvY2lhdGVkIHdlYnNvY2tldHMuXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSB3ZWJzb2NrZXQgLSB3ZWJzb2NrZXQgb2JqZWN0IHRvIHJlbW92ZSBmcm9tIHRoZSB1cmwgbWFwXG4gICAqIEBwYXJhbSB7c3RyaW5nfSB1cmxcbiAgICovXG4gIHJlbW92ZVdlYlNvY2tldCh3ZWJzb2NrZXQsIHVybCkge1xuICAgIGNvbnN0IGNvbm5lY3Rpb25Mb29rdXAgPSB0aGlzLnVybE1hcFt1cmxdO1xuXG4gICAgaWYgKGNvbm5lY3Rpb25Mb29rdXApIHtcbiAgICAgIGNvbm5lY3Rpb25Mb29rdXAud2Vic29ja2V0cyA9IHJlamVjdChjb25uZWN0aW9uTG9va3VwLndlYnNvY2tldHMsIHNvY2tldCA9PiBzb2NrZXQgPT09IHdlYnNvY2tldCk7XG4gICAgfVxuICB9XG5cbiAgLypcbiAgICogUmVtb3ZlcyBhIHdlYnNvY2tldCBmcm9tIGEgcm9vbVxuICAgKi9cbiAgcmVtb3ZlTWVtYmVyc2hpcEZyb21Sb29tKHdlYnNvY2tldCwgcm9vbSkge1xuICAgIGNvbnN0IGNvbm5lY3Rpb25Mb29rdXAgPSB0aGlzLnVybE1hcFt3ZWJzb2NrZXQudXJsXTtcbiAgICBjb25zdCBtZW1iZXJzaGlwcyA9IGNvbm5lY3Rpb25Mb29rdXAucm9vbU1lbWJlcnNoaXBzW3Jvb21dO1xuXG4gICAgaWYgKGNvbm5lY3Rpb25Mb29rdXAgJiYgbWVtYmVyc2hpcHMgIT09IG51bGwpIHtcbiAgICAgIGNvbm5lY3Rpb25Mb29rdXAucm9vbU1lbWJlcnNoaXBzW3Jvb21dID0gcmVqZWN0KG1lbWJlcnNoaXBzLCBzb2NrZXQgPT4gc29ja2V0ID09PSB3ZWJzb2NrZXQpO1xuICAgIH1cbiAgfVxufVxuXG5leHBvcnQgZGVmYXVsdCBuZXcgTmV0d29ya0JyaWRnZSgpOyAvLyBOb3RlOiB0aGlzIGlzIGEgc2luZ2xldG9uXG4iLCIvKlxuICogaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL0Nsb3NlRXZlbnRcbiAqL1xuZXhwb3J0IGNvbnN0IENMT1NFX0NPREVTID0ge1xuICBDTE9TRV9OT1JNQUw6IDEwMDAsXG4gIENMT1NFX0dPSU5HX0FXQVk6IDEwMDEsXG4gIENMT1NFX1BST1RPQ09MX0VSUk9SOiAxMDAyLFxuICBDTE9TRV9VTlNVUFBPUlRFRDogMTAwMyxcbiAgQ0xPU0VfTk9fU1RBVFVTOiAxMDA1LFxuICBDTE9TRV9BQk5PUk1BTDogMTAwNixcbiAgVU5TVVBQT1JURURfREFUQTogMTAwNyxcbiAgUE9MSUNZX1ZJT0xBVElPTjogMTAwOCxcbiAgQ0xPU0VfVE9PX0xBUkdFOiAxMDA5LFxuICBNSVNTSU5HX0VYVEVOU0lPTjogMTAxMCxcbiAgSU5URVJOQUxfRVJST1I6IDEwMTEsXG4gIFNFUlZJQ0VfUkVTVEFSVDogMTAxMixcbiAgVFJZX0FHQUlOX0xBVEVSOiAxMDEzLFxuICBUTFNfSEFORFNIQUtFOiAxMDE1XG59O1xuXG5leHBvcnQgY29uc3QgRVJST1JfUFJFRklYID0ge1xuICBDT05TVFJVQ1RPUl9FUlJPUjogXCJGYWlsZWQgdG8gY29uc3RydWN0ICdXZWJTb2NrZXQnOlwiLFxuICBDTE9TRV9FUlJPUjogXCJGYWlsZWQgdG8gZXhlY3V0ZSAnY2xvc2UnIG9uICdXZWJTb2NrZXQnOlwiLFxuICBFVkVOVDoge1xuICAgIENPTlNUUlVDVDogXCJGYWlsZWQgdG8gY29uc3RydWN0ICdFdmVudCc6XCIsXG4gICAgTUVTU0FHRTogXCJGYWlsZWQgdG8gY29uc3RydWN0ICdNZXNzYWdlRXZlbnQnOlwiLFxuICAgIENMT1NFOiBcIkZhaWxlZCB0byBjb25zdHJ1Y3QgJ0Nsb3NlRXZlbnQnOlwiXG4gIH1cbn07XG4iLCJleHBvcnQgZGVmYXVsdCBjbGFzcyBFdmVudFByb3RvdHlwZSB7XG4gIC8vIE5vb3BzXG4gIHN0b3BQcm9wYWdhdGlvbigpIHt9XG4gIHN0b3BJbW1lZGlhdGVQcm9wYWdhdGlvbigpIHt9XG5cbiAgLy8gaWYgbm8gYXJndW1lbnRzIGFyZSBwYXNzZWQgdGhlbiB0aGUgdHlwZSBpcyBzZXQgdG8gXCJ1bmRlZmluZWRcIiBvblxuICAvLyBjaHJvbWUgYW5kIHNhZmFyaS5cbiAgaW5pdEV2ZW50KHR5cGUgPSAndW5kZWZpbmVkJywgYnViYmxlcyA9IGZhbHNlLCBjYW5jZWxhYmxlID0gZmFsc2UpIHtcbiAgICB0aGlzLnR5cGUgPSBgJHt0eXBlfWA7XG4gICAgdGhpcy5idWJibGVzID0gQm9vbGVhbihidWJibGVzKTtcbiAgICB0aGlzLmNhbmNlbGFibGUgPSBCb29sZWFuKGNhbmNlbGFibGUpO1xuICB9XG59XG4iLCJpbXBvcnQgRXZlbnRQcm90b3R5cGUgZnJvbSAnLi9wcm90b3R5cGUnO1xuaW1wb3J0IHsgRVJST1JfUFJFRklYIH0gZnJvbSAnLi4vY29uc3RhbnRzJztcblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgRXZlbnQgZXh0ZW5kcyBFdmVudFByb3RvdHlwZSB7XG4gIGNvbnN0cnVjdG9yKHR5cGUsIGV2ZW50SW5pdENvbmZpZyA9IHt9KSB7XG4gICAgc3VwZXIoKTtcblxuICAgIGlmICghdHlwZSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHtFUlJPUl9QUkVGSVguRVZFTlRfRVJST1J9IDEgYXJndW1lbnQgcmVxdWlyZWQsIGJ1dCBvbmx5IDAgcHJlc2VudC5gKTtcbiAgICB9XG5cbiAgICBpZiAodHlwZW9mIGV2ZW50SW5pdENvbmZpZyAhPT0gJ29iamVjdCcpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7RVJST1JfUFJFRklYLkVWRU5UX0VSUk9SfSBwYXJhbWV0ZXIgMiAoJ2V2ZW50SW5pdERpY3QnKSBpcyBub3QgYW4gb2JqZWN0LmApO1xuICAgIH1cblxuICAgIGNvbnN0IHsgYnViYmxlcywgY2FuY2VsYWJsZSB9ID0gZXZlbnRJbml0Q29uZmlnO1xuXG4gICAgdGhpcy50eXBlID0gYCR7dHlwZX1gO1xuICAgIHRoaXMudGltZVN0YW1wID0gRGF0ZS5ub3coKTtcbiAgICB0aGlzLnRhcmdldCA9IG51bGw7XG4gICAgdGhpcy5zcmNFbGVtZW50ID0gbnVsbDtcbiAgICB0aGlzLnJldHVyblZhbHVlID0gdHJ1ZTtcbiAgICB0aGlzLmlzVHJ1c3RlZCA9IGZhbHNlO1xuICAgIHRoaXMuZXZlbnRQaGFzZSA9IDA7XG4gICAgdGhpcy5kZWZhdWx0UHJldmVudGVkID0gZmFsc2U7XG4gICAgdGhpcy5jdXJyZW50VGFyZ2V0ID0gbnVsbDtcbiAgICB0aGlzLmNhbmNlbGFibGUgPSBjYW5jZWxhYmxlID8gQm9vbGVhbihjYW5jZWxhYmxlKSA6IGZhbHNlO1xuICAgIHRoaXMuY2FubmNlbEJ1YmJsZSA9IGZhbHNlO1xuICAgIHRoaXMuYnViYmxlcyA9IGJ1YmJsZXMgPyBCb29sZWFuKGJ1YmJsZXMpIDogZmFsc2U7XG4gIH1cbn1cbiIsImltcG9ydCBFdmVudFByb3RvdHlwZSBmcm9tICcuL3Byb3RvdHlwZSc7XG5pbXBvcnQgeyBFUlJPUl9QUkVGSVggfSBmcm9tICcuLi9jb25zdGFudHMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNZXNzYWdlRXZlbnQgZXh0ZW5kcyBFdmVudFByb3RvdHlwZSB7XG4gIGNvbnN0cnVjdG9yKHR5cGUsIGV2ZW50SW5pdENvbmZpZyA9IHt9KSB7XG4gICAgc3VwZXIoKTtcblxuICAgIGlmICghdHlwZSkge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHtFUlJPUl9QUkVGSVguRVZFTlQuTUVTU0FHRX0gMSBhcmd1bWVudCByZXF1aXJlZCwgYnV0IG9ubHkgMCBwcmVzZW50LmApO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZXZlbnRJbml0Q29uZmlnICE9PSAnb2JqZWN0Jykge1xuICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHtFUlJPUl9QUkVGSVguRVZFTlQuTUVTU0FHRX0gcGFyYW1ldGVyIDIgKCdldmVudEluaXREaWN0JykgaXMgbm90IGFuIG9iamVjdGApO1xuICAgIH1cblxuICAgIGNvbnN0IHsgYnViYmxlcywgY2FuY2VsYWJsZSwgZGF0YSwgb3JpZ2luLCBsYXN0RXZlbnRJZCwgcG9ydHMgfSA9IGV2ZW50SW5pdENvbmZpZztcblxuICAgIHRoaXMudHlwZSA9IGAke3R5cGV9YDtcbiAgICB0aGlzLnRpbWVTdGFtcCA9IERhdGUubm93KCk7XG4gICAgdGhpcy50YXJnZXQgPSBudWxsO1xuICAgIHRoaXMuc3JjRWxlbWVudCA9IG51bGw7XG4gICAgdGhpcy5yZXR1cm5WYWx1ZSA9IHRydWU7XG4gICAgdGhpcy5pc1RydXN0ZWQgPSBmYWxzZTtcbiAgICB0aGlzLmV2ZW50UGhhc2UgPSAwO1xuICAgIHRoaXMuZGVmYXVsdFByZXZlbnRlZCA9IGZhbHNlO1xuICAgIHRoaXMuY3VycmVudFRhcmdldCA9IG51bGw7XG4gICAgdGhpcy5jYW5jZWxhYmxlID0gY2FuY2VsYWJsZSA/IEJvb2xlYW4oY2FuY2VsYWJsZSkgOiBmYWxzZTtcbiAgICB0aGlzLmNhbm5jZWxCdWJibGUgPSBmYWxzZTtcbiAgICB0aGlzLmJ1YmJsZXMgPSBidWJibGVzID8gQm9vbGVhbihidWJibGVzKSA6IGZhbHNlO1xuICAgIHRoaXMub3JpZ2luID0gYCR7b3JpZ2lufWA7XG4gICAgdGhpcy5wb3J0cyA9IHR5cGVvZiBwb3J0cyA9PT0gJ3VuZGVmaW5lZCcgPyBudWxsIDogcG9ydHM7XG4gICAgdGhpcy5kYXRhID0gdHlwZW9mIGRhdGEgPT09ICd1bmRlZmluZWQnID8gbnVsbCA6IGRhdGE7XG4gICAgdGhpcy5sYXN0RXZlbnRJZCA9IGAke2xhc3RFdmVudElkIHx8ICcnfWA7XG4gIH1cbn1cbiIsImltcG9ydCBFdmVudFByb3RvdHlwZSBmcm9tICcuL3Byb3RvdHlwZSc7XG5pbXBvcnQgeyBFUlJPUl9QUkVGSVggfSBmcm9tICcuLi9jb25zdGFudHMnO1xuXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBDbG9zZUV2ZW50IGV4dGVuZHMgRXZlbnRQcm90b3R5cGUge1xuICBjb25zdHJ1Y3Rvcih0eXBlLCBldmVudEluaXRDb25maWcgPSB7fSkge1xuICAgIHN1cGVyKCk7XG5cbiAgICBpZiAoIXR5cGUpIHtcbiAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7RVJST1JfUFJFRklYLkVWRU5ULkNMT1NFfSAxIGFyZ3VtZW50IHJlcXVpcmVkLCBidXQgb25seSAwIHByZXNlbnQuYCk7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBldmVudEluaXRDb25maWcgIT09ICdvYmplY3QnKSB7XG4gICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke0VSUk9SX1BSRUZJWC5FVkVOVC5DTE9TRX0gcGFyYW1ldGVyIDIgKCdldmVudEluaXREaWN0JykgaXMgbm90IGFuIG9iamVjdGApO1xuICAgIH1cblxuICAgIGNvbnN0IHsgYnViYmxlcywgY2FuY2VsYWJsZSwgY29kZSwgcmVhc29uLCB3YXNDbGVhbiB9ID0gZXZlbnRJbml0Q29uZmlnO1xuXG4gICAgdGhpcy50eXBlID0gYCR7dHlwZX1gO1xuICAgIHRoaXMudGltZVN0YW1wID0gRGF0ZS5ub3coKTtcbiAgICB0aGlzLnRhcmdldCA9IG51bGw7XG4gICAgdGhpcy5zcmNFbGVtZW50ID0gbnVsbDtcbiAgICB0aGlzLnJldHVyblZhbHVlID0gdHJ1ZTtcbiAgICB0aGlzLmlzVHJ1c3RlZCA9IGZhbHNlO1xuICAgIHRoaXMuZXZlbnRQaGFzZSA9IDA7XG4gICAgdGhpcy5kZWZhdWx0UHJldmVudGVkID0gZmFsc2U7XG4gICAgdGhpcy5jdXJyZW50VGFyZ2V0ID0gbnVsbDtcbiAgICB0aGlzLmNhbmNlbGFibGUgPSBjYW5jZWxhYmxlID8gQm9vbGVhbihjYW5jZWxhYmxlKSA6IGZhbHNlO1xuICAgIHRoaXMuY2FuY2VsQnViYmxlID0gZmFsc2U7XG4gICAgdGhpcy5idWJibGVzID0gYnViYmxlcyA/IEJvb2xlYW4oYnViYmxlcykgOiBmYWxzZTtcbiAgICB0aGlzLmNvZGUgPSB0eXBlb2YgY29kZSA9PT0gJ251bWJlcicgPyBwYXJzZUludChjb2RlLCAxMCkgOiAwO1xuICAgIHRoaXMucmVhc29uID0gYCR7cmVhc29uIHx8ICcnfWA7XG4gICAgdGhpcy53YXNDbGVhbiA9IHdhc0NsZWFuID8gQm9vbGVhbih3YXNDbGVhbikgOiBmYWxzZTtcbiAgfVxufVxuIiwiaW1wb3J0IEV2ZW50IGZyb20gJy4vZXZlbnQnO1xuaW1wb3J0IE1lc3NhZ2VFdmVudCBmcm9tICcuL21lc3NhZ2UnO1xuaW1wb3J0IENsb3NlRXZlbnQgZnJvbSAnLi9jbG9zZSc7XG5cbi8qXG4gKiBDcmVhdGVzIGFuIEV2ZW50IG9iamVjdCBhbmQgZXh0ZW5kcyBpdCB0byBhbGxvdyBmdWxsIG1vZGlmaWNhdGlvbiBvZlxuICogaXRzIHByb3BlcnRpZXMuXG4gKlxuICogQHBhcmFtIHtvYmplY3R9IGNvbmZpZyAtIHdpdGhpbiBjb25maWcgeW91IHdpbGwgbmVlZCB0byBwYXNzIHR5cGUgYW5kIG9wdGlvbmFsbHkgdGFyZ2V0XG4gKi9cbmZ1bmN0aW9uIGNyZWF0ZUV2ZW50KGNvbmZpZykge1xuICBjb25zdCB7IHR5cGUsIHRhcmdldCB9ID0gY29uZmlnO1xuICBjb25zdCBldmVudE9iamVjdCA9IG5ldyBFdmVudCh0eXBlKTtcblxuICBpZiAodGFyZ2V0KSB7XG4gICAgZXZlbnRPYmplY3QudGFyZ2V0ID0gdGFyZ2V0O1xuICAgIGV2ZW50T2JqZWN0LnNyY0VsZW1lbnQgPSB0YXJnZXQ7XG4gICAgZXZlbnRPYmplY3QuY3VycmVudFRhcmdldCA9IHRhcmdldDtcbiAgfVxuXG4gIHJldHVybiBldmVudE9iamVjdDtcbn1cblxuLypcbiAqIENyZWF0ZXMgYSBNZXNzYWdlRXZlbnQgb2JqZWN0IGFuZCBleHRlbmRzIGl0IHRvIGFsbG93IGZ1bGwgbW9kaWZpY2F0aW9uIG9mXG4gKiBpdHMgcHJvcGVydGllcy5cbiAqXG4gKiBAcGFyYW0ge29iamVjdH0gY29uZmlnIC0gd2l0aGluIGNvbmZpZzogdHlwZSwgb3JpZ2luLCBkYXRhIGFuZCBvcHRpb25hbGx5IHRhcmdldFxuICovXG5mdW5jdGlvbiBjcmVhdGVNZXNzYWdlRXZlbnQoY29uZmlnKSB7XG4gIGNvbnN0IHsgdHlwZSwgb3JpZ2luLCBkYXRhLCB0YXJnZXQgfSA9IGNvbmZpZztcbiAgY29uc3QgbWVzc2FnZUV2ZW50ID0gbmV3IE1lc3NhZ2VFdmVudCh0eXBlLCB7XG4gICAgZGF0YSxcbiAgICBvcmlnaW5cbiAgfSk7XG5cbiAgaWYgKHRhcmdldCkge1xuICAgIG1lc3NhZ2VFdmVudC50YXJnZXQgPSB0YXJnZXQ7XG4gICAgbWVzc2FnZUV2ZW50LnNyY0VsZW1lbnQgPSB0YXJnZXQ7XG4gICAgbWVzc2FnZUV2ZW50LmN1cnJlbnRUYXJnZXQgPSB0YXJnZXQ7XG4gIH1cblxuICByZXR1cm4gbWVzc2FnZUV2ZW50O1xufVxuXG4vKlxuICogQ3JlYXRlcyBhIENsb3NlRXZlbnQgb2JqZWN0IGFuZCBleHRlbmRzIGl0IHRvIGFsbG93IGZ1bGwgbW9kaWZpY2F0aW9uIG9mXG4gKiBpdHMgcHJvcGVydGllcy5cbiAqXG4gKiBAcGFyYW0ge29iamVjdH0gY29uZmlnIC0gd2l0aGluIGNvbmZpZzogdHlwZSBhbmQgb3B0aW9uYWxseSB0YXJnZXQsIGNvZGUsIGFuZCByZWFzb25cbiAqL1xuZnVuY3Rpb24gY3JlYXRlQ2xvc2VFdmVudChjb25maWcpIHtcbiAgY29uc3QgeyBjb2RlLCByZWFzb24sIHR5cGUsIHRhcmdldCB9ID0gY29uZmlnO1xuICBsZXQgeyB3YXNDbGVhbiB9ID0gY29uZmlnO1xuXG4gIGlmICghd2FzQ2xlYW4pIHtcbiAgICB3YXNDbGVhbiA9IGNvZGUgPT09IDEwMDA7XG4gIH1cblxuICBjb25zdCBjbG9zZUV2ZW50ID0gbmV3IENsb3NlRXZlbnQodHlwZSwge1xuICAgIGNvZGUsXG4gICAgcmVhc29uLFxuICAgIHdhc0NsZWFuXG4gIH0pO1xuXG4gIGlmICh0YXJnZXQpIHtcbiAgICBjbG9zZUV2ZW50LnRhcmdldCA9IHRhcmdldDtcbiAgICBjbG9zZUV2ZW50LnNyY0VsZW1lbnQgPSB0YXJnZXQ7XG4gICAgY2xvc2VFdmVudC5jdXJyZW50VGFyZ2V0ID0gdGFyZ2V0O1xuICB9XG5cbiAgcmV0dXJuIGNsb3NlRXZlbnQ7XG59XG5cbmV4cG9ydCB7IGNyZWF0ZUV2ZW50LCBjcmVhdGVNZXNzYWdlRXZlbnQsIGNyZWF0ZUNsb3NlRXZlbnQgfTtcbiIsImltcG9ydCBXZWJTb2NrZXQgZnJvbSAnLi4vd2Vic29ja2V0JztcbmltcG9ydCBkZWxheSBmcm9tICcuLi9oZWxwZXJzL2RlbGF5JztcbmltcG9ydCBuZXR3b3JrQnJpZGdlIGZyb20gJy4uL25ldHdvcmstYnJpZGdlJztcbmltcG9ydCB7IGNyZWF0ZUNsb3NlRXZlbnQsIGNyZWF0ZUV2ZW50IH0gZnJvbSAnLi4vZXZlbnQvZmFjdG9yeSc7XG5cbmV4cG9ydCBmdW5jdGlvbiBjbG9zZVdlYlNvY2tldENvbm5lY3Rpb24oY29udGV4dCwgY29kZSwgcmVhc29uKSB7XG4gIGNvbnRleHQucmVhZHlTdGF0ZSA9IFdlYlNvY2tldC5DTE9TSU5HO1xuXG4gIGNvbnN0IHNlcnZlciA9IG5ldHdvcmtCcmlkZ2Uuc2VydmVyTG9va3VwKGNvbnRleHQudXJsKTtcbiAgY29uc3QgY2xvc2VFdmVudCA9IGNyZWF0ZUNsb3NlRXZlbnQoe1xuICAgIHR5cGU6ICdjbG9zZScsXG4gICAgdGFyZ2V0OiBjb250ZXh0LFxuICAgIGNvZGUsXG4gICAgcmVhc29uXG4gIH0pO1xuXG4gIGRlbGF5KCgpID0+IHtcbiAgICBuZXR3b3JrQnJpZGdlLnJlbW92ZVdlYlNvY2tldChjb250ZXh0LCBjb250ZXh0LnVybCk7XG5cbiAgICBjb250ZXh0LnJlYWR5U3RhdGUgPSBXZWJTb2NrZXQuQ0xPU0VEO1xuICAgIGNvbnRleHQuZGlzcGF0Y2hFdmVudChjbG9zZUV2ZW50KTtcblxuICAgIGlmIChzZXJ2ZXIpIHtcbiAgICAgIHNlcnZlci5kaXNwYXRjaEV2ZW50KGNsb3NlRXZlbnQsIHNlcnZlcik7XG4gICAgfVxuICB9LCBjb250ZXh0KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZhaWxXZWJTb2NrZXRDb25uZWN0aW9uKGNvbnRleHQsIGNvZGUsIHJlYXNvbikge1xuICBjb250ZXh0LnJlYWR5U3RhdGUgPSBXZWJTb2NrZXQuQ0xPU0lORztcblxuICBjb25zdCBzZXJ2ZXIgPSBuZXR3b3JrQnJpZGdlLnNlcnZlckxvb2t1cChjb250ZXh0LnVybCk7XG4gIGNvbnN0IGNsb3NlRXZlbnQgPSBjcmVhdGVDbG9zZUV2ZW50KHtcbiAgICB0eXBlOiAnY2xvc2UnLFxuICAgIHRhcmdldDogY29udGV4dCxcbiAgICBjb2RlLFxuICAgIHJlYXNvbixcbiAgICB3YXNDbGVhbjogZmFsc2VcbiAgfSk7XG5cbiAgY29uc3QgZXJyb3JFdmVudCA9IGNyZWF0ZUV2ZW50KHtcbiAgICB0eXBlOiAnZXJyb3InLFxuICAgIHRhcmdldDogY29udGV4dFxuICB9KTtcblxuICBkZWxheSgoKSA9PiB7XG4gICAgbmV0d29ya0JyaWRnZS5yZW1vdmVXZWJTb2NrZXQoY29udGV4dCwgY29udGV4dC51cmwpO1xuXG4gICAgY29udGV4dC5yZWFkeVN0YXRlID0gV2ViU29ja2V0LkNMT1NFRDtcbiAgICBjb250ZXh0LmRpc3BhdGNoRXZlbnQoZXJyb3JFdmVudCk7XG4gICAgY29udGV4dC5kaXNwYXRjaEV2ZW50KGNsb3NlRXZlbnQpO1xuXG4gICAgaWYgKHNlcnZlcikge1xuICAgICAgc2VydmVyLmRpc3BhdGNoRXZlbnQoY2xvc2VFdmVudCwgc2VydmVyKTtcbiAgICB9XG4gIH0sIGNvbnRleHQpO1xufVxuIiwiZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gbm9ybWFsaXplU2VuZERhdGEoZGF0YSkge1xuICBpZiAoT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKGRhdGEpICE9PSAnW29iamVjdCBCbG9iXScgJiYgIShkYXRhIGluc3RhbmNlb2YgQXJyYXlCdWZmZXIpKSB7XG4gICAgZGF0YSA9IFN0cmluZyhkYXRhKTtcbiAgfVxuXG4gIHJldHVybiBkYXRhO1xufVxuIiwiaW1wb3J0IHsgQ0xPU0VfQ09ERVMgfSBmcm9tICcuLi9jb25zdGFudHMnO1xuaW1wb3J0IHsgY2xvc2VXZWJTb2NrZXRDb25uZWN0aW9uIH0gZnJvbSAnLi4vYWxnb3JpdGhtcy9jbG9zZSc7XG5pbXBvcnQgbm9ybWFsaXplU2VuZERhdGEgZnJvbSAnLi9ub3JtYWxpemUtc2VuZCc7XG5pbXBvcnQgeyBjcmVhdGVNZXNzYWdlRXZlbnQgfSBmcm9tICcuLi9ldmVudC9mYWN0b3J5JztcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gcHJveHlGYWN0b3J5KHRhcmdldCkge1xuICBjb25zdCBoYW5kbGVyID0ge1xuICAgIGdldChvYmosIHByb3ApIHtcbiAgICAgIGlmIChwcm9wID09PSAnY2xvc2UnKSB7XG4gICAgICAgIHJldHVybiBmdW5jdGlvbiBjbG9zZShvcHRpb25zID0ge30pIHtcbiAgICAgICAgICBjb25zdCBjb2RlID0gb3B0aW9ucy5jb2RlIHx8IENMT1NFX0NPREVTLkNMT1NFX05PUk1BTDtcbiAgICAgICAgICBjb25zdCByZWFzb24gPSBvcHRpb25zLnJlYXNvbiB8fCAnJztcblxuICAgICAgICAgIGNsb3NlV2ViU29ja2V0Q29ubmVjdGlvbih0YXJnZXQsIGNvZGUsIHJlYXNvbik7XG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIGlmIChwcm9wID09PSAnc2VuZCcpIHtcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIHNlbmQoZGF0YSkge1xuICAgICAgICAgIGRhdGEgPSBub3JtYWxpemVTZW5kRGF0YShkYXRhKTtcblxuICAgICAgICAgIHRhcmdldC5kaXNwYXRjaEV2ZW50KFxuICAgICAgICAgICAgY3JlYXRlTWVzc2FnZUV2ZW50KHtcbiAgICAgICAgICAgICAgdHlwZTogJ21lc3NhZ2UnLFxuICAgICAgICAgICAgICBkYXRhLFxuICAgICAgICAgICAgICBvcmlnaW46IHRoaXMudXJsLFxuICAgICAgICAgICAgICB0YXJnZXRcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgKTtcbiAgICAgICAgfTtcbiAgICAgIH1cblxuICAgICAgaWYgKHByb3AgPT09ICdvbicpIHtcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIG9uV3JhcHBlcih0eXBlLCBjYikge1xuICAgICAgICAgIHRhcmdldC5hZGRFdmVudExpc3RlbmVyKGBzZXJ2ZXI6OiR7dHlwZX1gLCBjYik7XG4gICAgICAgIH07XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBvYmpbcHJvcF07XG4gICAgfVxuICB9O1xuXG4gIGNvbnN0IHByb3h5ID0gbmV3IFByb3h5KHRhcmdldCwgaGFuZGxlcik7XG4gIHJldHVybiBwcm94eTtcbn1cbiIsImV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGxlbmd0aEluVXRmOEJ5dGVzKHN0cikge1xuICAvLyBNYXRjaGVzIG9ubHkgdGhlIDEwLi4gYnl0ZXMgdGhhdCBhcmUgbm9uLWluaXRpYWwgY2hhcmFjdGVycyBpbiBhIG11bHRpLWJ5dGUgc2VxdWVuY2UuXG4gIGNvbnN0IG0gPSBlbmNvZGVVUklDb21wb25lbnQoc3RyKS5tYXRjaCgvJVs4OUFCYWJdL2cpO1xuICByZXR1cm4gc3RyLmxlbmd0aCArIChtID8gbS5sZW5ndGggOiAwKTtcbn1cbiIsImltcG9ydCBVUkwgZnJvbSAndXJsLXBhcnNlJztcbmltcG9ydCB7IEVSUk9SX1BSRUZJWCB9IGZyb20gJy4uL2NvbnN0YW50cyc7XG5cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHVybFZlcmlmaWNhdGlvbih1cmwpIHtcbiAgY29uc3QgdXJsUmVjb3JkID0gbmV3IFVSTCh1cmwpO1xuICBjb25zdCB7IHBhdGhuYW1lLCBwcm90b2NvbCwgaGFzaCB9ID0gdXJsUmVjb3JkO1xuXG4gIGlmICghdXJsKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHtFUlJPUl9QUkVGSVguQ09OU1RSVUNUT1JfRVJST1J9IDEgYXJndW1lbnQgcmVxdWlyZWQsIGJ1dCBvbmx5IDAgcHJlc2VudC5gKTtcbiAgfVxuXG4gIGlmICghcGF0aG5hbWUpIHtcbiAgICB1cmxSZWNvcmQucGF0aG5hbWUgPSAnLyc7XG4gIH1cblxuICBpZiAocHJvdG9jb2wgPT09ICcnKSB7XG4gICAgdGhyb3cgbmV3IFN5bnRheEVycm9yKGAke0VSUk9SX1BSRUZJWC5DT05TVFJVQ1RPUl9FUlJPUn0gVGhlIFVSTCAnJHt1cmxSZWNvcmQudG9TdHJpbmcoKX0nIGlzIGludmFsaWQuYCk7XG4gIH1cblxuICBpZiAocHJvdG9jb2wgIT09ICd3czonICYmIHByb3RvY29sICE9PSAnd3NzOicpIHtcbiAgICB0aHJvdyBuZXcgU3ludGF4RXJyb3IoXG4gICAgICBgJHtFUlJPUl9QUkVGSVguQ09OU1RSVUNUT1JfRVJST1J9IFRoZSBVUkwncyBzY2hlbWUgbXVzdCBiZSBlaXRoZXIgJ3dzJyBvciAnd3NzJy4gJyR7cHJvdG9jb2x9JyBpcyBub3QgYWxsb3dlZC5gXG4gICAgKTtcbiAgfVxuXG4gIGlmIChoYXNoICE9PSAnJykge1xuICAgIC8qIGVzbGludC1kaXNhYmxlIG1heC1sZW4gKi9cbiAgICB0aHJvdyBuZXcgU3ludGF4RXJyb3IoXG4gICAgICBgJHtcbiAgICAgICAgRVJST1JfUFJFRklYLkNPTlNUUlVDVE9SX0VSUk9SXG4gICAgICB9IFRoZSBVUkwgY29udGFpbnMgYSBmcmFnbWVudCBpZGVudGlmaWVyICgnJHtoYXNofScpLiBGcmFnbWVudCBpZGVudGlmaWVycyBhcmUgbm90IGFsbG93ZWQgaW4gV2ViU29ja2V0IFVSTHMuYFxuICAgICk7XG4gICAgLyogZXNsaW50LWVuYWJsZSBtYXgtbGVuICovXG4gIH1cblxuICByZXR1cm4gdXJsUmVjb3JkLnRvU3RyaW5nKCk7XG59XG4iLCJpbXBvcnQgeyBFUlJPUl9QUkVGSVggfSBmcm9tICcuLi9jb25zdGFudHMnO1xuXG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBwcm90b2NvbFZlcmlmaWNhdGlvbihwcm90b2NvbHMgPSBbXSkge1xuICBpZiAoIUFycmF5LmlzQXJyYXkocHJvdG9jb2xzKSAmJiB0eXBlb2YgcHJvdG9jb2xzICE9PSAnc3RyaW5nJykge1xuICAgIHRocm93IG5ldyBTeW50YXhFcnJvcihgJHtFUlJPUl9QUkVGSVguQ09OU1RSVUNUT1JfRVJST1J9IFRoZSBzdWJwcm90b2NvbCAnJHtwcm90b2NvbHMudG9TdHJpbmcoKX0nIGlzIGludmFsaWQuYCk7XG4gIH1cblxuICBpZiAodHlwZW9mIHByb3RvY29scyA9PT0gJ3N0cmluZycpIHtcbiAgICBwcm90b2NvbHMgPSBbcHJvdG9jb2xzXTtcbiAgfVxuXG4gIGNvbnN0IHVuaXEgPSBwcm90b2NvbHNcbiAgICAubWFwKHAgPT4gKHsgY291bnQ6IDEsIHByb3RvY29sOiBwIH0pKVxuICAgIC5yZWR1Y2UoKGEsIGIpID0+IHtcbiAgICAgIGFbYi5wcm90b2NvbF0gPSAoYVtiLnByb3RvY29sXSB8fCAwKSArIGIuY291bnQ7XG4gICAgICByZXR1cm4gYTtcbiAgICB9LCB7fSk7XG5cbiAgY29uc3QgZHVwbGljYXRlcyA9IE9iamVjdC5rZXlzKHVuaXEpLmZpbHRlcihhID0+IHVuaXFbYV0gPiAxKTtcblxuICBpZiAoZHVwbGljYXRlcy5sZW5ndGggPiAwKSB7XG4gICAgdGhyb3cgbmV3IFN5bnRheEVycm9yKGAke0VSUk9SX1BSRUZJWC5DT05TVFJVQ1RPUl9FUlJPUn0gVGhlIHN1YnByb3RvY29sICcke2R1cGxpY2F0ZXNbMF19JyBpcyBkdXBsaWNhdGVkLmApO1xuICB9XG5cbiAgcmV0dXJuIHByb3RvY29scztcbn1cbiIsImltcG9ydCBkZWxheSBmcm9tICcuL2hlbHBlcnMvZGVsYXknO1xuaW1wb3J0IGxvZ2dlciBmcm9tICcuL2hlbHBlcnMvbG9nZ2VyJztcbmltcG9ydCBFdmVudFRhcmdldCBmcm9tICcuL2V2ZW50L3RhcmdldCc7XG5pbXBvcnQgbmV0d29ya0JyaWRnZSBmcm9tICcuL25ldHdvcmstYnJpZGdlJztcbmltcG9ydCBwcm94eUZhY3RvcnkgZnJvbSAnLi9oZWxwZXJzL3Byb3h5LWZhY3RvcnknO1xuaW1wb3J0IGxlbmd0aEluVXRmOEJ5dGVzIGZyb20gJy4vaGVscGVycy9ieXRlLWxlbmd0aCc7XG5pbXBvcnQgeyBDTE9TRV9DT0RFUywgRVJST1JfUFJFRklYIH0gZnJvbSAnLi9jb25zdGFudHMnO1xuaW1wb3J0IHVybFZlcmlmaWNhdGlvbiBmcm9tICcuL2hlbHBlcnMvdXJsLXZlcmlmaWNhdGlvbic7XG5pbXBvcnQgbm9ybWFsaXplU2VuZERhdGEgZnJvbSAnLi9oZWxwZXJzL25vcm1hbGl6ZS1zZW5kJztcbmltcG9ydCBwcm90b2NvbFZlcmlmaWNhdGlvbiBmcm9tICcuL2hlbHBlcnMvcHJvdG9jb2wtdmVyaWZpY2F0aW9uJztcbmltcG9ydCB7IGNyZWF0ZUV2ZW50LCBjcmVhdGVNZXNzYWdlRXZlbnQsIGNyZWF0ZUNsb3NlRXZlbnQgfSBmcm9tICcuL2V2ZW50L2ZhY3RvcnknO1xuaW1wb3J0IHsgY2xvc2VXZWJTb2NrZXRDb25uZWN0aW9uLCBmYWlsV2ViU29ja2V0Q29ubmVjdGlvbiB9IGZyb20gJy4vYWxnb3JpdGhtcy9jbG9zZSc7XG5cbi8qXG4gKiBUaGUgbWFpbiB3ZWJzb2NrZXQgY2xhc3Mgd2hpY2ggaXMgZGVzaWduZWQgdG8gbWltaWNrIHRoZSBuYXRpdmUgV2ViU29ja2V0IGNsYXNzIGFzIGNsb3NlXG4gKiBhcyBwb3NzaWJsZS5cbiAqXG4gKiBodHRwczovL2h0bWwuc3BlYy53aGF0d2cub3JnL211bHRpcGFnZS93ZWItc29ja2V0cy5odG1sXG4gKi9cbmNsYXNzIFdlYlNvY2tldCBleHRlbmRzIEV2ZW50VGFyZ2V0IHtcbiAgY29uc3RydWN0b3IodXJsLCBwcm90b2NvbHMpIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy51cmwgPSB1cmxWZXJpZmljYXRpb24odXJsKTtcbiAgICBwcm90b2NvbHMgPSBwcm90b2NvbFZlcmlmaWNhdGlvbihwcm90b2NvbHMpO1xuICAgIHRoaXMucHJvdG9jb2wgPSBwcm90b2NvbHNbMF0gfHwgJyc7XG5cbiAgICB0aGlzLmJpbmFyeVR5cGUgPSAnYmxvYic7XG4gICAgdGhpcy5yZWFkeVN0YXRlID0gV2ViU29ja2V0LkNPTk5FQ1RJTkc7XG5cbiAgICBjb25zdCBzZXJ2ZXIgPSBuZXR3b3JrQnJpZGdlLmF0dGFjaFdlYlNvY2tldCh0aGlzLCB0aGlzLnVybCk7XG5cbiAgICAvKlxuICAgICAqIFRoaXMgZGVsYXkgaXMgbmVlZGVkIHNvIHRoYXQgd2UgZG9udCB0cmlnZ2VyIGFuIGV2ZW50IGJlZm9yZSB0aGUgY2FsbGJhY2tzIGhhdmUgYmVlblxuICAgICAqIHNldHVwLiBGb3IgZXhhbXBsZTpcbiAgICAgKlxuICAgICAqIHZhciBzb2NrZXQgPSBuZXcgV2ViU29ja2V0KCd3czovL2xvY2FsaG9zdCcpO1xuICAgICAqXG4gICAgICogSWYgd2UgZG9udCBoYXZlIHRoZSBkZWxheSB0aGVuIHRoZSBldmVudCB3b3VsZCBiZSB0cmlnZ2VyZWQgcmlnaHQgaGVyZSBhbmQgdGhpcyBpc1xuICAgICAqIGJlZm9yZSB0aGUgb25vcGVuIGhhZCBhIGNoYW5jZSB0byByZWdpc3RlciBpdHNlbGYuXG4gICAgICpcbiAgICAgKiBzb2NrZXQub25vcGVuID0gKCkgPT4geyAvLyB0aGlzIHdvdWxkIG5ldmVyIGJlIGNhbGxlZCB9O1xuICAgICAqXG4gICAgICogYW5kIHdpdGggdGhlIGRlbGF5IHRoZSBldmVudCBnZXRzIHRyaWdnZXJlZCBoZXJlIGFmdGVyIGFsbCBvZiB0aGUgY2FsbGJhY2tzIGhhdmUgYmVlblxuICAgICAqIHJlZ2lzdGVyZWQgOi0pXG4gICAgICovXG4gICAgZGVsYXkoZnVuY3Rpb24gZGVsYXlDYWxsYmFjaygpIHtcbiAgICAgIGlmIChzZXJ2ZXIpIHtcbiAgICAgICAgaWYgKFxuICAgICAgICAgIHNlcnZlci5vcHRpb25zLnZlcmlmeUNsaWVudCAmJlxuICAgICAgICAgIHR5cGVvZiBzZXJ2ZXIub3B0aW9ucy52ZXJpZnlDbGllbnQgPT09ICdmdW5jdGlvbicgJiZcbiAgICAgICAgICAhc2VydmVyLm9wdGlvbnMudmVyaWZ5Q2xpZW50KClcbiAgICAgICAgKSB7XG4gICAgICAgICAgdGhpcy5yZWFkeVN0YXRlID0gV2ViU29ja2V0LkNMT1NFRDtcblxuICAgICAgICAgIGxvZ2dlcihcbiAgICAgICAgICAgICdlcnJvcicsXG4gICAgICAgICAgICBgV2ViU29ja2V0IGNvbm5lY3Rpb24gdG8gJyR7dGhpcy51cmx9JyBmYWlsZWQ6IEhUVFAgQXV0aGVudGljYXRpb24gZmFpbGVkOyBubyB2YWxpZCBjcmVkZW50aWFscyBhdmFpbGFibGVgXG4gICAgICAgICAgKTtcblxuICAgICAgICAgIG5ldHdvcmtCcmlkZ2UucmVtb3ZlV2ViU29ja2V0KHRoaXMsIHRoaXMudXJsKTtcbiAgICAgICAgICB0aGlzLmRpc3BhdGNoRXZlbnQoY3JlYXRlRXZlbnQoeyB0eXBlOiAnZXJyb3InLCB0YXJnZXQ6IHRoaXMgfSkpO1xuICAgICAgICAgIHRoaXMuZGlzcGF0Y2hFdmVudChjcmVhdGVDbG9zZUV2ZW50KHsgdHlwZTogJ2Nsb3NlJywgdGFyZ2V0OiB0aGlzLCBjb2RlOiBDTE9TRV9DT0RFUy5DTE9TRV9OT1JNQUwgfSkpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGlmIChzZXJ2ZXIub3B0aW9ucy5zZWxlY3RQcm90b2NvbCAmJiB0eXBlb2Ygc2VydmVyLm9wdGlvbnMuc2VsZWN0UHJvdG9jb2wgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgIGNvbnN0IHNlbGVjdGVkUHJvdG9jb2wgPSBzZXJ2ZXIub3B0aW9ucy5zZWxlY3RQcm90b2NvbChwcm90b2NvbHMpO1xuICAgICAgICAgICAgY29uc3QgaXNGaWxsZWQgPSBzZWxlY3RlZFByb3RvY29sICE9PSAnJztcbiAgICAgICAgICAgIGNvbnN0IGlzUmVxdWVzdGVkID0gcHJvdG9jb2xzLmluZGV4T2Yoc2VsZWN0ZWRQcm90b2NvbCkgIT09IC0xO1xuICAgICAgICAgICAgaWYgKGlzRmlsbGVkICYmICFpc1JlcXVlc3RlZCkge1xuICAgICAgICAgICAgICB0aGlzLnJlYWR5U3RhdGUgPSBXZWJTb2NrZXQuQ0xPU0VEO1xuXG4gICAgICAgICAgICAgIGxvZ2dlcignZXJyb3InLCBgV2ViU29ja2V0IGNvbm5lY3Rpb24gdG8gJyR7dGhpcy51cmx9JyBmYWlsZWQ6IEludmFsaWQgU3ViLVByb3RvY29sYCk7XG5cbiAgICAgICAgICAgICAgbmV0d29ya0JyaWRnZS5yZW1vdmVXZWJTb2NrZXQodGhpcywgdGhpcy51cmwpO1xuICAgICAgICAgICAgICB0aGlzLmRpc3BhdGNoRXZlbnQoY3JlYXRlRXZlbnQoeyB0eXBlOiAnZXJyb3InLCB0YXJnZXQ6IHRoaXMgfSkpO1xuICAgICAgICAgICAgICB0aGlzLmRpc3BhdGNoRXZlbnQoY3JlYXRlQ2xvc2VFdmVudCh7IHR5cGU6ICdjbG9zZScsIHRhcmdldDogdGhpcywgY29kZTogQ0xPU0VfQ09ERVMuQ0xPU0VfTk9STUFMIH0pKTtcbiAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhpcy5wcm90b2NvbCA9IHNlbGVjdGVkUHJvdG9jb2w7XG4gICAgICAgICAgfVxuICAgICAgICAgIHRoaXMucmVhZHlTdGF0ZSA9IFdlYlNvY2tldC5PUEVOO1xuICAgICAgICAgIHRoaXMuZGlzcGF0Y2hFdmVudChjcmVhdGVFdmVudCh7IHR5cGU6ICdvcGVuJywgdGFyZ2V0OiB0aGlzIH0pKTtcbiAgICAgICAgICBzZXJ2ZXIuZGlzcGF0Y2hFdmVudChjcmVhdGVFdmVudCh7IHR5cGU6ICdjb25uZWN0aW9uJyB9KSwgcHJveHlGYWN0b3J5KHRoaXMpKTtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5yZWFkeVN0YXRlID0gV2ViU29ja2V0LkNMT1NFRDtcbiAgICAgICAgdGhpcy5kaXNwYXRjaEV2ZW50KGNyZWF0ZUV2ZW50KHsgdHlwZTogJ2Vycm9yJywgdGFyZ2V0OiB0aGlzIH0pKTtcbiAgICAgICAgdGhpcy5kaXNwYXRjaEV2ZW50KGNyZWF0ZUNsb3NlRXZlbnQoeyB0eXBlOiAnY2xvc2UnLCB0YXJnZXQ6IHRoaXMsIGNvZGU6IENMT1NFX0NPREVTLkNMT1NFX05PUk1BTCB9KSk7XG5cbiAgICAgICAgbG9nZ2VyKCdlcnJvcicsIGBXZWJTb2NrZXQgY29ubmVjdGlvbiB0byAnJHt0aGlzLnVybH0nIGZhaWxlZGApO1xuICAgICAgfVxuICAgIH0sIHRoaXMpO1xuICB9XG5cbiAgZ2V0IG9ub3BlbigpIHtcbiAgICByZXR1cm4gdGhpcy5saXN0ZW5lcnMub3BlbjtcbiAgfVxuXG4gIGdldCBvbm1lc3NhZ2UoKSB7XG4gICAgcmV0dXJuIHRoaXMubGlzdGVuZXJzLm1lc3NhZ2U7XG4gIH1cblxuICBnZXQgb25jbG9zZSgpIHtcbiAgICByZXR1cm4gdGhpcy5saXN0ZW5lcnMuY2xvc2U7XG4gIH1cblxuICBnZXQgb25lcnJvcigpIHtcbiAgICByZXR1cm4gdGhpcy5saXN0ZW5lcnMuZXJyb3I7XG4gIH1cblxuICBzZXQgb25vcGVuKGxpc3RlbmVyKSB7XG4gICAgZGVsZXRlIHRoaXMubGlzdGVuZXJzLm9wZW47XG4gICAgdGhpcy5hZGRFdmVudExpc3RlbmVyKCdvcGVuJywgbGlzdGVuZXIpO1xuICB9XG5cbiAgc2V0IG9ubWVzc2FnZShsaXN0ZW5lcikge1xuICAgIGRlbGV0ZSB0aGlzLmxpc3RlbmVycy5tZXNzYWdlO1xuICAgIHRoaXMuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGxpc3RlbmVyKTtcbiAgfVxuXG4gIHNldCBvbmNsb3NlKGxpc3RlbmVyKSB7XG4gICAgZGVsZXRlIHRoaXMubGlzdGVuZXJzLmNsb3NlO1xuICAgIHRoaXMuYWRkRXZlbnRMaXN0ZW5lcignY2xvc2UnLCBsaXN0ZW5lcik7XG4gIH1cblxuICBzZXQgb25lcnJvcihsaXN0ZW5lcikge1xuICAgIGRlbGV0ZSB0aGlzLmxpc3RlbmVycy5lcnJvcjtcbiAgICB0aGlzLmFkZEV2ZW50TGlzdGVuZXIoJ2Vycm9yJywgbGlzdGVuZXIpO1xuICB9XG5cbiAgc2VuZChkYXRhKSB7XG4gICAgaWYgKHRoaXMucmVhZHlTdGF0ZSA9PT0gV2ViU29ja2V0LkNMT1NJTkcgfHwgdGhpcy5yZWFkeVN0YXRlID09PSBXZWJTb2NrZXQuQ0xPU0VEKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1dlYlNvY2tldCBpcyBhbHJlYWR5IGluIENMT1NJTkcgb3IgQ0xPU0VEIHN0YXRlJyk7XG4gICAgfVxuXG4gICAgLy8gVE9ETzogaGFuZGxlIGJ1ZmZlcmVkQW1vdW50XG5cbiAgICBjb25zdCBtZXNzYWdlRXZlbnQgPSBjcmVhdGVNZXNzYWdlRXZlbnQoe1xuICAgICAgdHlwZTogJ3NlcnZlcjo6bWVzc2FnZScsXG4gICAgICBvcmlnaW46IHRoaXMudXJsLFxuICAgICAgZGF0YTogbm9ybWFsaXplU2VuZERhdGEoZGF0YSlcbiAgICB9KTtcblxuICAgIGNvbnN0IHNlcnZlciA9IG5ldHdvcmtCcmlkZ2Uuc2VydmVyTG9va3VwKHRoaXMudXJsKTtcblxuICAgIGlmIChzZXJ2ZXIpIHtcbiAgICAgIGRlbGF5KCgpID0+IHtcbiAgICAgICAgdGhpcy5kaXNwYXRjaEV2ZW50KG1lc3NhZ2VFdmVudCwgZGF0YSk7XG4gICAgICB9LCBzZXJ2ZXIpO1xuICAgIH1cbiAgfVxuXG4gIGNsb3NlKGNvZGUsIHJlYXNvbikge1xuICAgIGlmIChjb2RlICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIGlmICh0eXBlb2YgY29kZSAhPT0gJ251bWJlcicgfHwgKGNvZGUgIT09IDEwMDAgJiYgKGNvZGUgPCAzMDAwIHx8IGNvZGUgPiA0OTk5KSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcbiAgICAgICAgICBgJHtFUlJPUl9QUkVGSVguQ0xPU0VfRVJST1J9IFRoZSBjb2RlIG11c3QgYmUgZWl0aGVyIDEwMDAsIG9yIGJldHdlZW4gMzAwMCBhbmQgNDk5OS4gJHtjb2RlfSBpcyBuZWl0aGVyLmBcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAocmVhc29uICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIGNvbnN0IGxlbmd0aCA9IGxlbmd0aEluVXRmOEJ5dGVzKHJlYXNvbik7XG5cbiAgICAgIGlmIChsZW5ndGggPiAxMjMpIHtcbiAgICAgICAgdGhyb3cgbmV3IFN5bnRheEVycm9yKGAke0VSUk9SX1BSRUZJWC5DTE9TRV9FUlJPUn0gVGhlIG1lc3NhZ2UgbXVzdCBub3QgYmUgZ3JlYXRlciB0aGFuIDEyMyBieXRlcy5gKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAodGhpcy5yZWFkeVN0YXRlID09PSBXZWJTb2NrZXQuQ0xPU0lORyB8fCB0aGlzLnJlYWR5U3RhdGUgPT09IFdlYlNvY2tldC5DTE9TRUQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5yZWFkeVN0YXRlID09PSBXZWJTb2NrZXQuQ09OTkVDVElORykge1xuICAgICAgZmFpbFdlYlNvY2tldENvbm5lY3Rpb24odGhpcywgY29kZSwgcmVhc29uKTtcbiAgICB9IGVsc2Uge1xuICAgICAgY2xvc2VXZWJTb2NrZXRDb25uZWN0aW9uKHRoaXMsIGNvZGUsIHJlYXNvbik7XG4gICAgfVxuICB9XG59XG5cbldlYlNvY2tldC5DT05ORUNUSU5HID0gMDtcbldlYlNvY2tldC5wcm90b3R5cGUuQ09OTkVDVElORyA9IFdlYlNvY2tldC5DT05ORUNUSU5HO1xuV2ViU29ja2V0Lk9QRU4gPSAxO1xuV2ViU29ja2V0LnByb3RvdHlwZS5PUEVOID0gV2ViU29ja2V0Lk9QRU47XG5XZWJTb2NrZXQuQ0xPU0lORyA9IDI7XG5XZWJTb2NrZXQucHJvdG90eXBlLkNMT1NJTkcgPSBXZWJTb2NrZXQuQ0xPU0lORztcbldlYlNvY2tldC5DTE9TRUQgPSAzO1xuV2ViU29ja2V0LnByb3RvdHlwZS5DTE9TRUQgPSBXZWJTb2NrZXQuQ0xPU0VEO1xuXG5leHBvcnQgZGVmYXVsdCBXZWJTb2NrZXQ7XG4iLCJleHBvcnQgZGVmYXVsdCBhcnIgPT5cbiAgYXJyLnJlZHVjZSgoZGVkdXBlZCwgYikgPT4ge1xuICAgIGlmIChkZWR1cGVkLmluZGV4T2YoYikgPiAtMSkgcmV0dXJuIGRlZHVwZWQ7XG4gICAgcmV0dXJuIGRlZHVwZWQuY29uY2F0KGIpO1xuICB9LCBbXSk7XG4iLCJleHBvcnQgZGVmYXVsdCBmdW5jdGlvbiByZXRyaWV2ZUdsb2JhbE9iamVjdCgpIHtcbiAgaWYgKHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgcmV0dXJuIHdpbmRvdztcbiAgfVxuXG4gIHJldHVybiB0eXBlb2YgcHJvY2VzcyA9PT0gJ29iamVjdCcgJiYgdHlwZW9mIHJlcXVpcmUgPT09ICdmdW5jdGlvbicgJiYgdHlwZW9mIGdsb2JhbCA9PT0gJ29iamVjdCcgPyBnbG9iYWwgOiB0aGlzO1xufVxuIiwiaW1wb3J0IFVSTCBmcm9tICd1cmwtcGFyc2UnO1xuaW1wb3J0IFdlYlNvY2tldCBmcm9tICcuL3dlYnNvY2tldCc7XG5pbXBvcnQgZGVkdXBlIGZyb20gJy4vaGVscGVycy9kZWR1cGUnO1xuaW1wb3J0IEV2ZW50VGFyZ2V0IGZyb20gJy4vZXZlbnQvdGFyZ2V0JztcbmltcG9ydCB7IENMT1NFX0NPREVTIH0gZnJvbSAnLi9jb25zdGFudHMnO1xuaW1wb3J0IG5ldHdvcmtCcmlkZ2UgZnJvbSAnLi9uZXR3b3JrLWJyaWRnZSc7XG5pbXBvcnQgZ2xvYmFsT2JqZWN0IGZyb20gJy4vaGVscGVycy9nbG9iYWwtb2JqZWN0JztcbmltcG9ydCBub3JtYWxpemVTZW5kRGF0YSBmcm9tICcuL2hlbHBlcnMvbm9ybWFsaXplLXNlbmQnO1xuaW1wb3J0IHsgY3JlYXRlRXZlbnQsIGNyZWF0ZU1lc3NhZ2VFdmVudCwgY3JlYXRlQ2xvc2VFdmVudCB9IGZyb20gJy4vZXZlbnQvZmFjdG9yeSc7XG5cbmNsYXNzIFNlcnZlciBleHRlbmRzIEV2ZW50VGFyZ2V0IHtcbiAgY29uc3RydWN0b3IodXJsLCBvcHRpb25zID0ge30pIHtcbiAgICBzdXBlcigpO1xuICAgIGNvbnN0IHVybFJlY29yZCA9IG5ldyBVUkwodXJsKTtcblxuICAgIGlmICghdXJsUmVjb3JkLnBhdGhuYW1lKSB7XG4gICAgICB1cmxSZWNvcmQucGF0aG5hbWUgPSAnLyc7XG4gICAgfVxuXG4gICAgdGhpcy51cmwgPSB1cmxSZWNvcmQudG9TdHJpbmcoKTtcblxuICAgIHRoaXMub3JpZ2luYWxXZWJTb2NrZXQgPSBudWxsO1xuICAgIGNvbnN0IHNlcnZlciA9IG5ldHdvcmtCcmlkZ2UuYXR0YWNoU2VydmVyKHRoaXMsIHRoaXMudXJsKTtcblxuICAgIGlmICghc2VydmVyKSB7XG4gICAgICB0aGlzLmRpc3BhdGNoRXZlbnQoY3JlYXRlRXZlbnQoeyB0eXBlOiAnZXJyb3InIH0pKTtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQSBtb2NrIHNlcnZlciBpcyBhbHJlYWR5IGxpc3RlbmluZyBvbiB0aGlzIHVybCcpO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2Ygb3B0aW9ucy52ZXJpZnlDbGllbnQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICBvcHRpb25zLnZlcmlmeUNsaWVudCA9IG51bGw7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBvcHRpb25zLnNlbGVjdFByb3RvY29sID09PSAndW5kZWZpbmVkJykge1xuICAgICAgb3B0aW9ucy5zZWxlY3RQcm90b2NvbCA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcbiAgICB0aGlzLnN0YXJ0KCk7XG4gIH1cblxuICAvKlxuICAgKiBBdHRhY2hlcyB0aGUgbW9jayB3ZWJzb2NrZXQgb2JqZWN0IHRvIHRoZSBnbG9iYWwgb2JqZWN0XG4gICAqL1xuICBzdGFydCgpIHtcbiAgICBjb25zdCBnbG9iYWxPYmogPSBnbG9iYWxPYmplY3QoKTtcblxuICAgIGlmIChnbG9iYWxPYmouV2ViU29ja2V0KSB7XG4gICAgICB0aGlzLm9yaWdpbmFsV2ViU29ja2V0ID0gZ2xvYmFsT2JqLldlYlNvY2tldDtcbiAgICB9XG5cbiAgICBnbG9iYWxPYmouV2ViU29ja2V0ID0gV2ViU29ja2V0O1xuICB9XG5cbiAgLypcbiAgICogUmVtb3ZlcyB0aGUgbW9jayB3ZWJzb2NrZXQgb2JqZWN0IGZyb20gdGhlIGdsb2JhbCBvYmplY3RcbiAgICovXG4gIHN0b3AoY2FsbGJhY2sgPSAoKSA9PiB7fSkge1xuICAgIGNvbnN0IGdsb2JhbE9iaiA9IGdsb2JhbE9iamVjdCgpO1xuXG4gICAgaWYgKHRoaXMub3JpZ2luYWxXZWJTb2NrZXQpIHtcbiAgICAgIGdsb2JhbE9iai5XZWJTb2NrZXQgPSB0aGlzLm9yaWdpbmFsV2ViU29ja2V0O1xuICAgIH0gZWxzZSB7XG4gICAgICBkZWxldGUgZ2xvYmFsT2JqLldlYlNvY2tldDtcbiAgICB9XG5cbiAgICB0aGlzLm9yaWdpbmFsV2ViU29ja2V0ID0gbnVsbDtcblxuICAgIG5ldHdvcmtCcmlkZ2UucmVtb3ZlU2VydmVyKHRoaXMudXJsKTtcblxuICAgIGlmICh0eXBlb2YgY2FsbGJhY2sgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIGNhbGxiYWNrKCk7XG4gICAgfVxuICB9XG5cbiAgLypcbiAgICogVGhpcyBpcyB0aGUgbWFpbiBmdW5jdGlvbiBmb3IgdGhlIG1vY2sgc2VydmVyIHRvIHN1YnNjcmliZSB0byB0aGUgb24gZXZlbnRzLlxuICAgKlxuICAgKiBpZTogbW9ja1NlcnZlci5vbignY29ubmVjdGlvbicsIGZ1bmN0aW9uKCkgeyBjb25zb2xlLmxvZygnYSBtb2NrIGNsaWVudCBjb25uZWN0ZWQnKTsgfSk7XG4gICAqXG4gICAqIEBwYXJhbSB7c3RyaW5nfSB0eXBlIC0gVGhlIGV2ZW50IGtleSB0byBzdWJzY3JpYmUgdG8uIFZhbGlkIGtleXMgYXJlOiBjb25uZWN0aW9uLCBtZXNzYWdlLCBhbmQgY2xvc2UuXG4gICAqIEBwYXJhbSB7ZnVuY3Rpb259IGNhbGxiYWNrIC0gVGhlIGNhbGxiYWNrIHdoaWNoIHNob3VsZCBiZSBjYWxsZWQgd2hlbiBhIGNlcnRhaW4gZXZlbnQgaXMgZmlyZWQuXG4gICAqL1xuICBvbih0eXBlLCBjYWxsYmFjaykge1xuICAgIHRoaXMuYWRkRXZlbnRMaXN0ZW5lcih0eXBlLCBjYWxsYmFjayk7XG4gIH1cblxuICAvKlxuICAgKiBDbG9zZXMgdGhlIGNvbm5lY3Rpb24gYW5kIHRyaWdnZXJzIHRoZSBvbmNsb3NlIG1ldGhvZCBvZiBhbGwgbGlzdGVuaW5nXG4gICAqIHdlYnNvY2tldHMuIEFmdGVyIHRoYXQgaXQgcmVtb3ZlcyBpdHNlbGYgZnJvbSB0aGUgdXJsTWFwIHNvIGFub3RoZXIgc2VydmVyXG4gICAqIGNvdWxkIGFkZCBpdHNlbGYgdG8gdGhlIHVybC5cbiAgICpcbiAgICogQHBhcmFtIHtvYmplY3R9IG9wdGlvbnNcbiAgICovXG4gIGNsb3NlKG9wdGlvbnMgPSB7fSkge1xuICAgIGNvbnN0IHsgY29kZSwgcmVhc29uLCB3YXNDbGVhbiB9ID0gb3B0aW9ucztcbiAgICBjb25zdCBsaXN0ZW5lcnMgPSBuZXR3b3JrQnJpZGdlLndlYnNvY2tldHNMb29rdXAodGhpcy51cmwpO1xuXG4gICAgLy8gUmVtb3ZlIHNlcnZlciBiZWZvcmUgbm90aWZpY2F0aW9ucyB0byBwcmV2ZW50IGltbWVkaWF0ZSByZWNvbm5lY3RzIGZyb21cbiAgICAvLyBzb2NrZXQgb25jbG9zZSBoYW5kbGVyc1xuICAgIG5ldHdvcmtCcmlkZ2UucmVtb3ZlU2VydmVyKHRoaXMudXJsKTtcblxuICAgIGxpc3RlbmVycy5mb3JFYWNoKHNvY2tldCA9PiB7XG4gICAgICBzb2NrZXQucmVhZHlTdGF0ZSA9IFdlYlNvY2tldC5DTE9TRTtcbiAgICAgIHNvY2tldC5kaXNwYXRjaEV2ZW50KFxuICAgICAgICBjcmVhdGVDbG9zZUV2ZW50KHtcbiAgICAgICAgICB0eXBlOiAnY2xvc2UnLFxuICAgICAgICAgIHRhcmdldDogc29ja2V0LFxuICAgICAgICAgIGNvZGU6IGNvZGUgfHwgQ0xPU0VfQ09ERVMuQ0xPU0VfTk9STUFMLFxuICAgICAgICAgIHJlYXNvbjogcmVhc29uIHx8ICcnLFxuICAgICAgICAgIHdhc0NsZWFuXG4gICAgICAgIH0pXG4gICAgICApO1xuICAgIH0pO1xuXG4gICAgdGhpcy5kaXNwYXRjaEV2ZW50KGNyZWF0ZUNsb3NlRXZlbnQoeyB0eXBlOiAnY2xvc2UnIH0pLCB0aGlzKTtcbiAgfVxuXG4gIC8qXG4gICAqIFNlbmRzIGEgZ2VuZXJpYyBtZXNzYWdlIGV2ZW50IHRvIGFsbCBtb2NrIGNsaWVudHMuXG4gICAqL1xuICBlbWl0KGV2ZW50LCBkYXRhLCBvcHRpb25zID0ge30pIHtcbiAgICBsZXQgeyB3ZWJzb2NrZXRzIH0gPSBvcHRpb25zO1xuXG4gICAgaWYgKCF3ZWJzb2NrZXRzKSB7XG4gICAgICB3ZWJzb2NrZXRzID0gbmV0d29ya0JyaWRnZS53ZWJzb2NrZXRzTG9va3VwKHRoaXMudXJsKTtcbiAgICB9XG5cbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgIT09ICdvYmplY3QnIHx8IGFyZ3VtZW50cy5sZW5ndGggPiAzKSB7XG4gICAgICBkYXRhID0gQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzLCAxLCBhcmd1bWVudHMubGVuZ3RoKTtcbiAgICAgIGRhdGEgPSBkYXRhLm1hcChpdGVtID0+IG5vcm1hbGl6ZVNlbmREYXRhKGl0ZW0pKTtcbiAgICB9IGVsc2Uge1xuICAgICAgZGF0YSA9IG5vcm1hbGl6ZVNlbmREYXRhKGRhdGEpO1xuICAgIH1cblxuICAgIHdlYnNvY2tldHMuZm9yRWFjaChzb2NrZXQgPT4ge1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoZGF0YSkpIHtcbiAgICAgICAgc29ja2V0LmRpc3BhdGNoRXZlbnQoXG4gICAgICAgICAgY3JlYXRlTWVzc2FnZUV2ZW50KHtcbiAgICAgICAgICAgIHR5cGU6IGV2ZW50LFxuICAgICAgICAgICAgZGF0YSxcbiAgICAgICAgICAgIG9yaWdpbjogdGhpcy51cmwsXG4gICAgICAgICAgICB0YXJnZXQ6IHNvY2tldFxuICAgICAgICAgIH0pLFxuICAgICAgICAgIC4uLmRhdGFcbiAgICAgICAgKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHNvY2tldC5kaXNwYXRjaEV2ZW50KFxuICAgICAgICAgIGNyZWF0ZU1lc3NhZ2VFdmVudCh7XG4gICAgICAgICAgICB0eXBlOiBldmVudCxcbiAgICAgICAgICAgIGRhdGEsXG4gICAgICAgICAgICBvcmlnaW46IHRoaXMudXJsLFxuICAgICAgICAgICAgdGFyZ2V0OiBzb2NrZXRcbiAgICAgICAgICB9KVxuICAgICAgICApO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgLypcbiAgICogUmV0dXJucyBhbiBhcnJheSBvZiB3ZWJzb2NrZXRzIHdoaWNoIGFyZSBsaXN0ZW5pbmcgdG8gdGhpcyBzZXJ2ZXJcbiAgICogVE9PRDogdGhpcyBzaG91bGQgcmV0dXJuIGEgc2V0IGFuZCBub3QgYmUgYSBtZXRob2RcbiAgICovXG4gIGNsaWVudHMoKSB7XG4gICAgcmV0dXJuIG5ldHdvcmtCcmlkZ2Uud2Vic29ja2V0c0xvb2t1cCh0aGlzLnVybCk7XG4gIH1cblxuICAvKlxuICAgKiBQcmVwYXJlcyBhIG1ldGhvZCB0byBzdWJtaXQgYW4gZXZlbnQgdG8gbWVtYmVycyBvZiB0aGUgcm9vbVxuICAgKlxuICAgKiBlLmcuIHNlcnZlci50bygnbXktcm9vbScpLmVtaXQoJ2hpIScpO1xuICAgKi9cbiAgdG8ocm9vbSwgYnJvYWRjYXN0ZXIsIGJyb2FkY2FzdExpc3QgPSBbXSkge1xuICAgIGNvbnN0IHNlbGYgPSB0aGlzO1xuICAgIGNvbnN0IHdlYnNvY2tldHMgPSBkZWR1cGUoYnJvYWRjYXN0TGlzdC5jb25jYXQobmV0d29ya0JyaWRnZS53ZWJzb2NrZXRzTG9va3VwKHRoaXMudXJsLCByb29tLCBicm9hZGNhc3RlcikpKTtcblxuICAgIHJldHVybiB7XG4gICAgICB0bzogKGNoYWluZWRSb29tLCBjaGFpbmVkQnJvYWRjYXN0ZXIpID0+IHRoaXMudG8uY2FsbCh0aGlzLCBjaGFpbmVkUm9vbSwgY2hhaW5lZEJyb2FkY2FzdGVyLCB3ZWJzb2NrZXRzKSxcbiAgICAgIGVtaXQoZXZlbnQsIGRhdGEpIHtcbiAgICAgICAgc2VsZi5lbWl0KGV2ZW50LCBkYXRhLCB7IHdlYnNvY2tldHMgfSk7XG4gICAgICB9XG4gICAgfTtcbiAgfVxuXG4gIC8qXG4gICAqIEFsaWFzIGZvciBTZXJ2ZXIudG9cbiAgICovXG4gIGluKC4uLmFyZ3MpIHtcbiAgICByZXR1cm4gdGhpcy50by5hcHBseShudWxsLCBhcmdzKTtcbiAgfVxuXG4gIC8qXG4gICAqIFNpbXVsYXRlIGFuIGV2ZW50IGZyb20gdGhlIHNlcnZlciB0byB0aGUgY2xpZW50cy4gVXNlZnVsIGZvclxuICAgKiBzaW11bGF0aW5nIGVycm9ycy5cbiAgICovXG4gIHNpbXVsYXRlKGV2ZW50LCBldmVudFByb3BzID0ge30pIHtcbiAgICBjb25zdCBsaXN0ZW5lcnMgPSBuZXR3b3JrQnJpZGdlLndlYnNvY2tldHNMb29rdXAodGhpcy51cmwpO1xuXG4gICAgaWYgKGV2ZW50ID09PSAnZXJyb3InKSB7XG4gICAgICBsaXN0ZW5lcnMuZm9yRWFjaChzb2NrZXQgPT4ge1xuICAgICAgICBzb2NrZXQucmVhZHlTdGF0ZSA9IFdlYlNvY2tldC5DTE9TRTtcbiAgICAgICAgY29uc3QgZXZlbnRDb25maWcgPSBPYmplY3QuYXNzaWduKHt0eXBlOiAnZXJyb3InfSwgZXZlbnRQcm9wcyk7XG4gICAgICAgIHNvY2tldC5kaXNwYXRjaEV2ZW50KGNyZWF0ZUV2ZW50KGV2ZW50Q29uZmlnKSk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cbn1cblxuLypcbiAqIEFsdGVybmF0aXZlIGNvbnN0cnVjdG9yIHRvIHN1cHBvcnQgbmFtZXNwYWNlcyBpbiBzb2NrZXQuaW9cbiAqXG4gKiBodHRwOi8vc29ja2V0LmlvL2RvY3Mvcm9vbXMtYW5kLW5hbWVzcGFjZXMvI2N1c3RvbS1uYW1lc3BhY2VzXG4gKi9cblNlcnZlci5vZiA9IGZ1bmN0aW9uIG9mKHVybCkge1xuICByZXR1cm4gbmV3IFNlcnZlcih1cmwpO1xufTtcblxuZXhwb3J0IGRlZmF1bHQgU2VydmVyO1xuIiwiaW1wb3J0IFVSTCBmcm9tICd1cmwtcGFyc2UnO1xuaW1wb3J0IGRlbGF5IGZyb20gJy4vaGVscGVycy9kZWxheSc7XG5pbXBvcnQgRXZlbnRUYXJnZXQgZnJvbSAnLi9ldmVudC90YXJnZXQnO1xuaW1wb3J0IG5ldHdvcmtCcmlkZ2UgZnJvbSAnLi9uZXR3b3JrLWJyaWRnZSc7XG5pbXBvcnQgeyBDTE9TRV9DT0RFUyB9IGZyb20gJy4vY29uc3RhbnRzJztcbmltcG9ydCBsb2dnZXIgZnJvbSAnLi9oZWxwZXJzL2xvZ2dlcic7XG5pbXBvcnQgeyBjcmVhdGVFdmVudCwgY3JlYXRlTWVzc2FnZUV2ZW50LCBjcmVhdGVDbG9zZUV2ZW50IH0gZnJvbSAnLi9ldmVudC9mYWN0b3J5JztcblxuLypcbiAqIFRoZSBzb2NrZXQtaW8gY2xhc3MgaXMgZGVzaWduZWQgdG8gbWltaWNrIHRoZSByZWFsIEFQSSBhcyBjbG9zZWx5IGFzIHBvc3NpYmxlLlxuICpcbiAqIGh0dHA6Ly9zb2NrZXQuaW8vZG9jcy9cbiAqL1xuY2xhc3MgU29ja2V0SU8gZXh0ZW5kcyBFdmVudFRhcmdldCB7XG4gIC8qXG4gICAqIEBwYXJhbSB7c3RyaW5nfSB1cmxcbiAgICovXG4gIGNvbnN0cnVjdG9yKHVybCA9ICdzb2NrZXQuaW8nLCBwcm90b2NvbCA9ICcnKSB7XG4gICAgc3VwZXIoKTtcblxuICAgIHRoaXMuYmluYXJ5VHlwZSA9ICdibG9iJztcbiAgICBjb25zdCB1cmxSZWNvcmQgPSBuZXcgVVJMKHVybCk7XG5cbiAgICBpZiAoIXVybFJlY29yZC5wYXRobmFtZSkge1xuICAgICAgdXJsUmVjb3JkLnBhdGhuYW1lID0gJy8nO1xuICAgIH1cblxuICAgIHRoaXMudXJsID0gdXJsUmVjb3JkLnRvU3RyaW5nKCk7XG4gICAgdGhpcy5yZWFkeVN0YXRlID0gU29ja2V0SU8uQ09OTkVDVElORztcbiAgICB0aGlzLnByb3RvY29sID0gJyc7XG5cbiAgICBpZiAodHlwZW9mIHByb3RvY29sID09PSAnc3RyaW5nJyB8fCAodHlwZW9mIHByb3RvY29sID09PSAnb2JqZWN0JyAmJiBwcm90b2NvbCAhPT0gbnVsbCkpIHtcbiAgICAgIHRoaXMucHJvdG9jb2wgPSBwcm90b2NvbDtcbiAgICB9IGVsc2UgaWYgKEFycmF5LmlzQXJyYXkocHJvdG9jb2wpICYmIHByb3RvY29sLmxlbmd0aCA+IDApIHtcbiAgICAgIHRoaXMucHJvdG9jb2wgPSBwcm90b2NvbFswXTtcbiAgICB9XG5cbiAgICBjb25zdCBzZXJ2ZXIgPSBuZXR3b3JrQnJpZGdlLmF0dGFjaFdlYlNvY2tldCh0aGlzLCB0aGlzLnVybCk7XG5cbiAgICAvKlxuICAgICAqIERlbGF5IHRyaWdnZXJpbmcgdGhlIGNvbm5lY3Rpb24gZXZlbnRzIHNvIHRoZXkgY2FuIGJlIGRlZmluZWQgaW4gdGltZS5cbiAgICAgKi9cbiAgICBkZWxheShmdW5jdGlvbiBkZWxheUNhbGxiYWNrKCkge1xuICAgICAgaWYgKHNlcnZlcikge1xuICAgICAgICB0aGlzLnJlYWR5U3RhdGUgPSBTb2NrZXRJTy5PUEVOO1xuICAgICAgICBzZXJ2ZXIuZGlzcGF0Y2hFdmVudChjcmVhdGVFdmVudCh7IHR5cGU6ICdjb25uZWN0aW9uJyB9KSwgc2VydmVyLCB0aGlzKTtcbiAgICAgICAgc2VydmVyLmRpc3BhdGNoRXZlbnQoY3JlYXRlRXZlbnQoeyB0eXBlOiAnY29ubmVjdCcgfSksIHNlcnZlciwgdGhpcyk7IC8vIGFsaWFzXG4gICAgICAgIHRoaXMuZGlzcGF0Y2hFdmVudChjcmVhdGVFdmVudCh7IHR5cGU6ICdjb25uZWN0JywgdGFyZ2V0OiB0aGlzIH0pKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMucmVhZHlTdGF0ZSA9IFNvY2tldElPLkNMT1NFRDtcbiAgICAgICAgdGhpcy5kaXNwYXRjaEV2ZW50KGNyZWF0ZUV2ZW50KHsgdHlwZTogJ2Vycm9yJywgdGFyZ2V0OiB0aGlzIH0pKTtcbiAgICAgICAgdGhpcy5kaXNwYXRjaEV2ZW50KFxuICAgICAgICAgIGNyZWF0ZUNsb3NlRXZlbnQoe1xuICAgICAgICAgICAgdHlwZTogJ2Nsb3NlJyxcbiAgICAgICAgICAgIHRhcmdldDogdGhpcyxcbiAgICAgICAgICAgIGNvZGU6IENMT1NFX0NPREVTLkNMT1NFX05PUk1BTFxuICAgICAgICAgIH0pXG4gICAgICAgICk7XG5cbiAgICAgICAgbG9nZ2VyKCdlcnJvcicsIGBTb2NrZXQuaW8gY29ubmVjdGlvbiB0byAnJHt0aGlzLnVybH0nIGZhaWxlZGApO1xuICAgICAgfVxuICAgIH0sIHRoaXMpO1xuXG4gICAgLyoqXG4gICAgICBBZGQgYW4gYWxpYXNlZCBldmVudCBsaXN0ZW5lciBmb3IgY2xvc2UgLyBkaXNjb25uZWN0XG4gICAgICovXG4gICAgdGhpcy5hZGRFdmVudExpc3RlbmVyKCdjbG9zZScsIGV2ZW50ID0+IHtcbiAgICAgIHRoaXMuZGlzcGF0Y2hFdmVudChcbiAgICAgICAgY3JlYXRlQ2xvc2VFdmVudCh7XG4gICAgICAgICAgdHlwZTogJ2Rpc2Nvbm5lY3QnLFxuICAgICAgICAgIHRhcmdldDogZXZlbnQudGFyZ2V0LFxuICAgICAgICAgIGNvZGU6IGV2ZW50LmNvZGVcbiAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfSk7XG4gIH1cblxuICAvKlxuICAgKiBDbG9zZXMgdGhlIFNvY2tldElPIGNvbm5lY3Rpb24gb3IgY29ubmVjdGlvbiBhdHRlbXB0LCBpZiBhbnkuXG4gICAqIElmIHRoZSBjb25uZWN0aW9uIGlzIGFscmVhZHkgQ0xPU0VELCB0aGlzIG1ldGhvZCBkb2VzIG5vdGhpbmcuXG4gICAqL1xuICBjbG9zZSgpIHtcbiAgICBpZiAodGhpcy5yZWFkeVN0YXRlICE9PSBTb2NrZXRJTy5PUEVOKSB7XG4gICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cblxuICAgIGNvbnN0IHNlcnZlciA9IG5ldHdvcmtCcmlkZ2Uuc2VydmVyTG9va3VwKHRoaXMudXJsKTtcbiAgICBuZXR3b3JrQnJpZGdlLnJlbW92ZVdlYlNvY2tldCh0aGlzLCB0aGlzLnVybCk7XG5cbiAgICB0aGlzLnJlYWR5U3RhdGUgPSBTb2NrZXRJTy5DTE9TRUQ7XG4gICAgdGhpcy5kaXNwYXRjaEV2ZW50KFxuICAgICAgY3JlYXRlQ2xvc2VFdmVudCh7XG4gICAgICAgIHR5cGU6ICdjbG9zZScsXG4gICAgICAgIHRhcmdldDogdGhpcyxcbiAgICAgICAgY29kZTogQ0xPU0VfQ09ERVMuQ0xPU0VfTk9STUFMXG4gICAgICB9KVxuICAgICk7XG5cbiAgICBpZiAoc2VydmVyKSB7XG4gICAgICBzZXJ2ZXIuZGlzcGF0Y2hFdmVudChcbiAgICAgICAgY3JlYXRlQ2xvc2VFdmVudCh7XG4gICAgICAgICAgdHlwZTogJ2Rpc2Nvbm5lY3QnLFxuICAgICAgICAgIHRhcmdldDogdGhpcyxcbiAgICAgICAgICBjb2RlOiBDTE9TRV9DT0RFUy5DTE9TRV9OT1JNQUxcbiAgICAgICAgfSksXG4gICAgICAgIHNlcnZlclxuICAgICAgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIC8qXG4gICAqIEFsaWFzIGZvciBTb2NrZXQjY2xvc2VcbiAgICpcbiAgICogaHR0cHM6Ly9naXRodWIuY29tL3NvY2tldGlvL3NvY2tldC5pby1jbGllbnQvYmxvYi9tYXN0ZXIvbGliL3NvY2tldC5qcyNMMzgzXG4gICAqL1xuICBkaXNjb25uZWN0KCkge1xuICAgIHJldHVybiB0aGlzLmNsb3NlKCk7XG4gIH1cblxuICAvKlxuICAgKiBTdWJtaXRzIGFuIGV2ZW50IHRvIHRoZSBzZXJ2ZXIgd2l0aCBhIHBheWxvYWRcbiAgICovXG4gIGVtaXQoZXZlbnQsIC4uLmRhdGEpIHtcbiAgICBpZiAodGhpcy5yZWFkeVN0YXRlICE9PSBTb2NrZXRJTy5PUEVOKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1NvY2tldElPIGlzIGFscmVhZHkgaW4gQ0xPU0lORyBvciBDTE9TRUQgc3RhdGUnKTtcbiAgICB9XG5cbiAgICBjb25zdCBtZXNzYWdlRXZlbnQgPSBjcmVhdGVNZXNzYWdlRXZlbnQoe1xuICAgICAgdHlwZTogZXZlbnQsXG4gICAgICBvcmlnaW46IHRoaXMudXJsLFxuICAgICAgZGF0YVxuICAgIH0pO1xuXG4gICAgY29uc3Qgc2VydmVyID0gbmV0d29ya0JyaWRnZS5zZXJ2ZXJMb29rdXAodGhpcy51cmwpO1xuXG4gICAgaWYgKHNlcnZlcikge1xuICAgICAgc2VydmVyLmRpc3BhdGNoRXZlbnQobWVzc2FnZUV2ZW50LCAuLi5kYXRhKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIC8qXG4gICAqIFN1Ym1pdHMgYSAnbWVzc2FnZScgZXZlbnQgdG8gdGhlIHNlcnZlci5cbiAgICpcbiAgICogU2hvdWxkIGJlaGF2ZSBleGFjdGx5IGxpa2UgV2ViU29ja2V0I3NlbmRcbiAgICpcbiAgICogaHR0cHM6Ly9naXRodWIuY29tL3NvY2tldGlvL3NvY2tldC5pby1jbGllbnQvYmxvYi9tYXN0ZXIvbGliL3NvY2tldC5qcyNMMTEzXG4gICAqL1xuICBzZW5kKGRhdGEpIHtcbiAgICB0aGlzLmVtaXQoJ21lc3NhZ2UnLCBkYXRhKTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIC8qXG4gICAqIEZvciBicm9hZGNhc3RpbmcgZXZlbnRzIHRvIG90aGVyIGNvbm5lY3RlZCBzb2NrZXRzLlxuICAgKlxuICAgKiBlLmcuIHNvY2tldC5icm9hZGNhc3QuZW1pdCgnaGkhJyk7XG4gICAqIGUuZy4gc29ja2V0LmJyb2FkY2FzdC50bygnbXktcm9vbScpLmVtaXQoJ2hpIScpO1xuICAgKi9cbiAgZ2V0IGJyb2FkY2FzdCgpIHtcbiAgICBpZiAodGhpcy5yZWFkeVN0YXRlICE9PSBTb2NrZXRJTy5PUEVOKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1NvY2tldElPIGlzIGFscmVhZHkgaW4gQ0xPU0lORyBvciBDTE9TRUQgc3RhdGUnKTtcbiAgICB9XG5cbiAgICBjb25zdCBzZWxmID0gdGhpcztcbiAgICBjb25zdCBzZXJ2ZXIgPSBuZXR3b3JrQnJpZGdlLnNlcnZlckxvb2t1cCh0aGlzLnVybCk7XG4gICAgaWYgKCFzZXJ2ZXIpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgU29ja2V0SU8gY2FuIG5vdCBmaW5kIGEgc2VydmVyIGF0IHRoZSBzcGVjaWZpZWQgVVJMICgke3RoaXMudXJsfSlgKTtcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgZW1pdChldmVudCwgZGF0YSkge1xuICAgICAgICBzZXJ2ZXIuZW1pdChldmVudCwgZGF0YSwgeyB3ZWJzb2NrZXRzOiBuZXR3b3JrQnJpZGdlLndlYnNvY2tldHNMb29rdXAoc2VsZi51cmwsIG51bGwsIHNlbGYpIH0pO1xuICAgICAgICByZXR1cm4gc2VsZjtcbiAgICAgIH0sXG4gICAgICB0byhyb29tKSB7XG4gICAgICAgIHJldHVybiBzZXJ2ZXIudG8ocm9vbSwgc2VsZik7XG4gICAgICB9LFxuICAgICAgaW4ocm9vbSkge1xuICAgICAgICByZXR1cm4gc2VydmVyLmluKHJvb20sIHNlbGYpO1xuICAgICAgfVxuICAgIH07XG4gIH1cblxuICAvKlxuICAgKiBGb3IgcmVnaXN0ZXJpbmcgZXZlbnRzIHRvIGJlIHJlY2VpdmVkIGZyb20gdGhlIHNlcnZlclxuICAgKi9cbiAgb24odHlwZSwgY2FsbGJhY2spIHtcbiAgICB0aGlzLmFkZEV2ZW50TGlzdGVuZXIodHlwZSwgY2FsbGJhY2spO1xuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgLypcbiAgICogUmVtb3ZlIGV2ZW50IGxpc3RlbmVyXG4gICAqXG4gICAqIGh0dHBzOi8vc29ja2V0LmlvL2RvY3MvY2xpZW50LWFwaS8jc29ja2V0LW9uLWV2ZW50bmFtZS1jYWxsYmFja1xuICAgKi9cbiAgb2ZmKHR5cGUpIHtcbiAgICB0aGlzLnJlbW92ZUV2ZW50TGlzdGVuZXIodHlwZSk7XG4gIH1cblxuICAvKlxuICAgKiBKb2luIGEgcm9vbSBvbiBhIHNlcnZlclxuICAgKlxuICAgKiBodHRwOi8vc29ja2V0LmlvL2RvY3Mvcm9vbXMtYW5kLW5hbWVzcGFjZXMvI2pvaW5pbmctYW5kLWxlYXZpbmdcbiAgICovXG4gIGpvaW4ocm9vbSkge1xuICAgIG5ldHdvcmtCcmlkZ2UuYWRkTWVtYmVyc2hpcFRvUm9vbSh0aGlzLCByb29tKTtcbiAgfVxuXG4gIC8qXG4gICAqIEdldCB0aGUgd2Vic29ja2V0IHRvIGxlYXZlIHRoZSByb29tXG4gICAqXG4gICAqIGh0dHA6Ly9zb2NrZXQuaW8vZG9jcy9yb29tcy1hbmQtbmFtZXNwYWNlcy8jam9pbmluZy1hbmQtbGVhdmluZ1xuICAgKi9cbiAgbGVhdmUocm9vbSkge1xuICAgIG5ldHdvcmtCcmlkZ2UucmVtb3ZlTWVtYmVyc2hpcEZyb21Sb29tKHRoaXMsIHJvb20pO1xuICB9XG5cbiAgdG8ocm9vbSkge1xuICAgIHJldHVybiB0aGlzLmJyb2FkY2FzdC50byhyb29tKTtcbiAgfVxuXG4gIGluKCkge1xuICAgIHJldHVybiB0aGlzLnRvLmFwcGx5KG51bGwsIGFyZ3VtZW50cyk7XG4gIH1cblxuICAvKlxuICAgKiBJbnZva2VzIGFsbCBsaXN0ZW5lciBmdW5jdGlvbnMgdGhhdCBhcmUgbGlzdGVuaW5nIHRvIHRoZSBnaXZlbiBldmVudC50eXBlIHByb3BlcnR5LiBFYWNoXG4gICAqIGxpc3RlbmVyIHdpbGwgYmUgcGFzc2VkIHRoZSBldmVudCBhcyB0aGUgZmlyc3QgYXJndW1lbnQuXG4gICAqXG4gICAqIEBwYXJhbSB7b2JqZWN0fSBldmVudCAtIGV2ZW50IG9iamVjdCB3aGljaCB3aWxsIGJlIHBhc3NlZCB0byBhbGwgbGlzdGVuZXJzIG9mIHRoZSBldmVudC50eXBlIHByb3BlcnR5XG4gICAqL1xuICBkaXNwYXRjaEV2ZW50KGV2ZW50LCAuLi5jdXN0b21Bcmd1bWVudHMpIHtcbiAgICBjb25zdCBldmVudE5hbWUgPSBldmVudC50eXBlO1xuICAgIGNvbnN0IGxpc3RlbmVycyA9IHRoaXMubGlzdGVuZXJzW2V2ZW50TmFtZV07XG5cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkobGlzdGVuZXJzKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIGxpc3RlbmVycy5mb3JFYWNoKGxpc3RlbmVyID0+IHtcbiAgICAgIGlmIChjdXN0b21Bcmd1bWVudHMubGVuZ3RoID4gMCkge1xuICAgICAgICBsaXN0ZW5lci5hcHBseSh0aGlzLCBjdXN0b21Bcmd1bWVudHMpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gUmVndWxhciBXZWJTb2NrZXRzIGV4cGVjdCBhIE1lc3NhZ2VFdmVudCBidXQgU29ja2V0aW8uaW8ganVzdCB3YW50cyByYXcgZGF0YVxuICAgICAgICAvLyAgcGF5bG9hZCBpbnN0YW5jZW9mIE1lc3NhZ2VFdmVudCB3b3JrcywgYnV0IHlvdSBjYW4ndCBpc250YW5jZSBvZiBOb2RlRXZlbnRcbiAgICAgICAgLy8gIGZvciBub3cgd2UgZGV0ZWN0IGlmIHRoZSBvdXRwdXQgaGFzIGRhdGEgZGVmaW5lZCBvbiBpdFxuICAgICAgICBsaXN0ZW5lci5jYWxsKHRoaXMsIGV2ZW50LmRhdGEgPyBldmVudC5kYXRhIDogZXZlbnQpO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG59XG5cblNvY2tldElPLkNPTk5FQ1RJTkcgPSAwO1xuU29ja2V0SU8uT1BFTiA9IDE7XG5Tb2NrZXRJTy5DTE9TSU5HID0gMjtcblNvY2tldElPLkNMT1NFRCA9IDM7XG5cbi8qXG4gKiBTdGF0aWMgY29uc3RydWN0b3IgbWV0aG9kcyBmb3IgdGhlIElPIFNvY2tldFxuICovXG5jb25zdCBJTyA9IGZ1bmN0aW9uIGlvQ29uc3RydWN0b3IodXJsLCBwcm90b2NvbCkge1xuICByZXR1cm4gbmV3IFNvY2tldElPKHVybCwgcHJvdG9jb2wpO1xufTtcblxuLypcbiAqIEFsaWFzIHRoZSByYXcgSU8oKSBjb25zdHJ1Y3RvclxuICovXG5JTy5jb25uZWN0ID0gZnVuY3Rpb24gaW9Db25uZWN0KHVybCwgcHJvdG9jb2wpIHtcbiAgLyogZXNsaW50LWRpc2FibGUgbmV3LWNhcCAqL1xuICByZXR1cm4gSU8odXJsLCBwcm90b2NvbCk7XG4gIC8qIGVzbGludC1lbmFibGUgbmV3LWNhcCAqL1xufTtcblxuZXhwb3J0IGRlZmF1bHQgSU87XG4iLCJpbXBvcnQgTW9ja1NlcnZlciBmcm9tICcuL3NlcnZlcic7XG5pbXBvcnQgTW9ja1NvY2tldElPIGZyb20gJy4vc29ja2V0LWlvJztcbmltcG9ydCBNb2NrV2ViU29ja2V0IGZyb20gJy4vd2Vic29ja2V0JztcblxuZXhwb3J0IGNvbnN0IFNlcnZlciA9IE1vY2tTZXJ2ZXI7XG5leHBvcnQgY29uc3QgV2ViU29ja2V0ID0gTW9ja1dlYlNvY2tldDtcbmV4cG9ydCBjb25zdCBTb2NrZXRJTyA9IE1vY2tTb2NrZXRJTztcbiJdLCJuYW1lcyI6WyJnbG9iYWwiLCJxcyIsInJlcXVpcmVkIiwiY29uc3QiLCJ0aGlzIiwic3VwZXIiLCJXZWJTb2NrZXQiLCJVUkwiLCJsb2dnZXIiLCJTZXJ2ZXIiLCJnbG9iYWxPYmplY3QiLCJTb2NrZXRJTyIsIk1vY2tTZXJ2ZXIiLCJNb2NrV2ViU29ja2V0IiwiTW9ja1NvY2tldElPIl0sIm1h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
