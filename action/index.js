var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS({
  "node_modules/@actions/core/lib/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toCommandProperties = exports.toCommandValue = void 0;
    function toCommandValue(input) {
      if (input === null || input === void 0) {
        return "";
      } else if (typeof input === "string" || input instanceof String) {
        return input;
      }
      return JSON.stringify(input);
    }
    exports.toCommandValue = toCommandValue;
    function toCommandProperties(annotationProperties) {
      if (!Object.keys(annotationProperties).length) {
        return {};
      }
      return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
      };
    }
    exports.toCommandProperties = toCommandProperties;
  }
});

// node_modules/@actions/core/lib/command.js
var require_command = __commonJS({
  "node_modules/@actions/core/lib/command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.issue = exports.issueCommand = void 0;
    var os = __importStar(require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, properties, message) {
      const cmd = new Command(command, properties, message);
      process.stdout.write(cmd.toString() + os.EOL);
    }
    exports.issueCommand = issueCommand;
    function issue(name, message = "") {
      issueCommand(name, {}, message);
    }
    exports.issue = issue;
    var CMD_STRING = "::";
    var Command = class {
      constructor(command, properties, message) {
        if (!command) {
          command = "missing.command";
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
      }
      toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
          cmdStr += " ";
          let first = true;
          for (const key in this.properties) {
            if (this.properties.hasOwnProperty(key)) {
              const val = this.properties[key];
              if (val) {
                if (first) {
                  first = false;
                } else {
                  cmdStr += ",";
                }
                cmdStr += `${key}=${escapeProperty(val)}`;
              }
            }
          }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
      }
    };
    function escapeData(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    }
    function escapeProperty(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
    }
  }
});

// node_modules/uuid/dist/esm-node/rng.js
function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    import_crypto.default.randomFillSync(rnds8Pool);
    poolPtr = 0;
  }
  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}
var import_crypto, rnds8Pool, poolPtr;
var init_rng = __esm({
  "node_modules/uuid/dist/esm-node/rng.js"() {
    import_crypto = __toESM(require("crypto"));
    rnds8Pool = new Uint8Array(256);
    poolPtr = rnds8Pool.length;
  }
});

// node_modules/uuid/dist/esm-node/regex.js
var regex_default;
var init_regex = __esm({
  "node_modules/uuid/dist/esm-node/regex.js"() {
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// node_modules/uuid/dist/esm-node/validate.js
function validate(uuid) {
  return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default;
var init_validate = __esm({
  "node_modules/uuid/dist/esm-node/validate.js"() {
    init_regex();
    validate_default = validate;
  }
});

// node_modules/uuid/dist/esm-node/stringify.js
function stringify(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
var byteToHex, stringify_default;
var init_stringify = __esm({
  "node_modules/uuid/dist/esm-node/stringify.js"() {
    init_validate();
    byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// node_modules/uuid/dist/esm-node/v1.js
function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  let msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  let nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  const tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "node_modules/uuid/dist/esm-node/v1.js"() {
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// node_modules/uuid/dist/esm-node/parse.js
function parse(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  let v;
  const arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "node_modules/uuid/dist/esm-node/parse.js"() {
    init_validate();
    parse_default = parse;
  }
});

// node_modules/uuid/dist/esm-node/v35.js
function stringToBytes(str2) {
  str2 = unescape(encodeURIComponent(str2));
  const bytes = [];
  for (let i = 0; i < str2.length; ++i) {
    bytes.push(str2.charCodeAt(i));
  }
  return bytes;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 15 | version2;
    bytes[8] = bytes[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }
      return buf;
    }
    return stringify_default(bytes);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "node_modules/uuid/dist/esm-node/v35.js"() {
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// node_modules/uuid/dist/esm-node/md5.js
function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto2.default.createHash("md5").update(bytes).digest();
}
var import_crypto2, md5_default;
var init_md5 = __esm({
  "node_modules/uuid/dist/esm-node/md5.js"() {
    import_crypto2 = __toESM(require("crypto"));
    md5_default = md5;
  }
});

// node_modules/uuid/dist/esm-node/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "node_modules/uuid/dist/esm-node/v3.js"() {
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// node_modules/uuid/dist/esm-node/v4.js
function v4(options, buf, offset) {
  options = options || {};
  const rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "node_modules/uuid/dist/esm-node/v4.js"() {
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// node_modules/uuid/dist/esm-node/sha1.js
function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto3.default.createHash("sha1").update(bytes).digest();
}
var import_crypto3, sha1_default;
var init_sha1 = __esm({
  "node_modules/uuid/dist/esm-node/sha1.js"() {
    import_crypto3 = __toESM(require("crypto"));
    sha1_default = sha1;
  }
});

// node_modules/uuid/dist/esm-node/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "node_modules/uuid/dist/esm-node/v5.js"() {
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// node_modules/uuid/dist/esm-node/nil.js
var nil_default;
var init_nil = __esm({
  "node_modules/uuid/dist/esm-node/nil.js"() {
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// node_modules/uuid/dist/esm-node/version.js
function version(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "node_modules/uuid/dist/esm-node/version.js"() {
    init_validate();
    version_default = version;
  }
});

// node_modules/uuid/dist/esm-node/index.js
var esm_node_exports = {};
__export(esm_node_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_node = __esm({
  "node_modules/uuid/dist/esm-node/index.js"() {
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS({
  "node_modules/@actions/core/lib/file-command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.prepareKeyValueMessage = exports.issueFileCommand = void 0;
    var fs = __importStar(require("fs"));
    var os = __importStar(require("os"));
    var uuid_1 = (init_esm_node(), __toCommonJS(esm_node_exports));
    var utils_1 = require_utils();
    function issueFileCommand(command, message) {
      const filePath = process.env[`GITHUB_${command}`];
      if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
      }
      if (!fs.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
      }
      fs.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: "utf8"
      });
    }
    exports.issueFileCommand = issueFileCommand;
    function prepareKeyValueMessage(key, value) {
      const delimiter = `ghadelimiter_${uuid_1.v4()}`;
      const convertedValue = utils_1.toCommandValue(value);
      if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
      }
      if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
      }
      return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`;
    }
    exports.prepareKeyValueMessage = prepareKeyValueMessage;
  }
});

// node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS({
  "node_modules/@actions/http-client/lib/proxy.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.checkBypass = exports.getProxyUrl = void 0;
    function getProxyUrl(reqUrl) {
      const usingSsl = reqUrl.protocol === "https:";
      if (checkBypass(reqUrl)) {
        return void 0;
      }
      const proxyVar = (() => {
        if (usingSsl) {
          return process.env["https_proxy"] || process.env["HTTPS_PROXY"];
        } else {
          return process.env["http_proxy"] || process.env["HTTP_PROXY"];
        }
      })();
      if (proxyVar) {
        return new URL(proxyVar);
      } else {
        return void 0;
      }
    }
    exports.getProxyUrl = getProxyUrl;
    function checkBypass(reqUrl) {
      if (!reqUrl.hostname) {
        return false;
      }
      const noProxy = process.env["no_proxy"] || process.env["NO_PROXY"] || "";
      if (!noProxy) {
        return false;
      }
      let reqPort;
      if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
      } else if (reqUrl.protocol === "http:") {
        reqPort = 80;
      } else if (reqUrl.protocol === "https:") {
        reqPort = 443;
      }
      const upperReqHosts = [reqUrl.hostname.toUpperCase()];
      if (typeof reqPort === "number") {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
      }
      for (const upperNoProxyItem of noProxy.split(",").map((x) => x.trim().toUpperCase()).filter((x) => x)) {
        if (upperReqHosts.some((x) => x === upperNoProxyItem)) {
          return true;
        }
      }
      return false;
    }
    exports.checkBypass = checkBypass;
  }
});

// node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS({
  "node_modules/tunnel/lib/tunnel.js"(exports) {
    "use strict";
    var net = require("net");
    var tls = require("tls");
    var http = require("http");
    var https = require("https");
    var events = require("events");
    var assert = require("assert");
    var util = require("util");
    exports.httpOverHttp = httpOverHttp;
    exports.httpsOverHttp = httpsOverHttp;
    exports.httpOverHttps = httpOverHttps;
    exports.httpsOverHttps = httpsOverHttps;
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      return agent;
    }
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      return agent;
    }
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function TunnelingAgent(options) {
      var self = this;
      self.options = options || {};
      self.proxyOptions = self.options.proxy || {};
      self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
      self.requests = [];
      self.sockets = [];
      self.on("free", function onFree(socket, host, port, localAddress) {
        var options2 = toOptions(host, port, localAddress);
        for (var i = 0, len = self.requests.length; i < len; ++i) {
          var pending = self.requests[i];
          if (pending.host === options2.host && pending.port === options2.port) {
            self.requests.splice(i, 1);
            pending.request.onSocket(socket);
            return;
          }
        }
        socket.destroy();
        self.removeSocket(socket);
      });
    }
    util.inherits(TunnelingAgent, events.EventEmitter);
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
      var self = this;
      var options = mergeOptions({ request: req }, self.options, toOptions(host, port, localAddress));
      if (self.sockets.length >= this.maxSockets) {
        self.requests.push(options);
        return;
      }
      self.createSocket(options, function(socket) {
        socket.on("free", onFree);
        socket.on("close", onCloseOrRemove);
        socket.on("agentRemove", onCloseOrRemove);
        req.onSocket(socket);
        function onFree() {
          self.emit("free", socket, options);
        }
        function onCloseOrRemove(err) {
          self.removeSocket(socket);
          socket.removeListener("free", onFree);
          socket.removeListener("close", onCloseOrRemove);
          socket.removeListener("agentRemove", onCloseOrRemove);
        }
      });
    };
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self = this;
      var placeholder = {};
      self.sockets.push(placeholder);
      var connectOptions = mergeOptions({}, self.proxyOptions, {
        method: "CONNECT",
        path: options.host + ":" + options.port,
        agent: false,
        headers: {
          host: options.host + ":" + options.port
        }
      });
      if (options.localAddress) {
        connectOptions.localAddress = options.localAddress;
      }
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {};
        connectOptions.headers["Proxy-Authorization"] = "Basic " + new Buffer(connectOptions.proxyAuth).toString("base64");
      }
      debug("making CONNECT request");
      var connectReq = self.request(connectOptions);
      connectReq.useChunkedEncodingByDefault = false;
      connectReq.once("response", onResponse);
      connectReq.once("upgrade", onUpgrade);
      connectReq.once("connect", onConnect);
      connectReq.once("error", onError);
      connectReq.end();
      function onResponse(res) {
        res.upgrade = true;
      }
      function onUpgrade(res, socket, head) {
        process.nextTick(function() {
          onConnect(res, socket, head);
        });
      }
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners();
        socket.removeAllListeners();
        if (res.statusCode !== 200) {
          debug(
            "tunneling socket could not be established, statusCode=%d",
            res.statusCode
          );
          socket.destroy();
          var error2 = new Error("tunneling socket could not be established, statusCode=" + res.statusCode);
          error2.code = "ECONNRESET";
          options.request.emit("error", error2);
          self.removeSocket(placeholder);
          return;
        }
        if (head.length > 0) {
          debug("got illegal response body from proxy");
          socket.destroy();
          var error2 = new Error("got illegal response body from proxy");
          error2.code = "ECONNRESET";
          options.request.emit("error", error2);
          self.removeSocket(placeholder);
          return;
        }
        debug("tunneling connection has established");
        self.sockets[self.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
      function onError(cause) {
        connectReq.removeAllListeners();
        debug(
          "tunneling socket could not be established, cause=%s\n",
          cause.message,
          cause.stack
        );
        var error2 = new Error("tunneling socket could not be established, cause=" + cause.message);
        error2.code = "ECONNRESET";
        options.request.emit("error", error2);
        self.removeSocket(placeholder);
      }
    };
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket);
      if (pos === -1) {
        return;
      }
      this.sockets.splice(pos, 1);
      var pending = this.requests.shift();
      if (pending) {
        this.createSocket(pending, function(socket2) {
          pending.request.onSocket(socket2);
        });
      }
    };
    function createSecureSocket(options, cb) {
      var self = this;
      TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
        var hostHeader = options.request.getHeader("host");
        var tlsOptions = mergeOptions({}, self.options, {
          socket,
          servername: hostHeader ? hostHeader.replace(/:.*$/, "") : options.host
        });
        var secureSocket = tls.connect(0, tlsOptions);
        self.sockets[self.sockets.indexOf(socket)] = secureSocket;
        cb(secureSocket);
      });
    }
    function toOptions(host, port, localAddress) {
      if (typeof host === "string") {
        return {
          host,
          port,
          localAddress
        };
      }
      return host;
    }
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i];
        if (typeof overrides === "object") {
          var keys = Object.keys(overrides);
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j];
            if (overrides[k] !== void 0) {
              target[k] = overrides[k];
            }
          }
        }
      }
      return target;
    }
    var debug;
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug = function() {
        var args = Array.prototype.slice.call(arguments);
        if (typeof args[0] === "string") {
          args[0] = "TUNNEL: " + args[0];
        } else {
          args.unshift("TUNNEL:");
        }
        console.error.apply(console, args);
      };
    } else {
      debug = function() {
      };
    }
    exports.debug = debug;
  }
});

// node_modules/tunnel/index.js
var require_tunnel2 = __commonJS({
  "node_modules/tunnel/index.js"(exports, module2) {
    module2.exports = require_tunnel();
  }
});

// node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS({
  "node_modules/@actions/http-client/lib/index.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.HttpClient = exports.isHttps = exports.HttpClientResponse = exports.HttpClientError = exports.getProxyUrl = exports.MediaTypes = exports.Headers = exports.HttpCodes = void 0;
    var http = __importStar(require("http"));
    var https = __importStar(require("https"));
    var pm = __importStar(require_proxy());
    var tunnel = __importStar(require_tunnel2());
    var HttpCodes;
    (function(HttpCodes2) {
      HttpCodes2[HttpCodes2["OK"] = 200] = "OK";
      HttpCodes2[HttpCodes2["MultipleChoices"] = 300] = "MultipleChoices";
      HttpCodes2[HttpCodes2["MovedPermanently"] = 301] = "MovedPermanently";
      HttpCodes2[HttpCodes2["ResourceMoved"] = 302] = "ResourceMoved";
      HttpCodes2[HttpCodes2["SeeOther"] = 303] = "SeeOther";
      HttpCodes2[HttpCodes2["NotModified"] = 304] = "NotModified";
      HttpCodes2[HttpCodes2["UseProxy"] = 305] = "UseProxy";
      HttpCodes2[HttpCodes2["SwitchProxy"] = 306] = "SwitchProxy";
      HttpCodes2[HttpCodes2["TemporaryRedirect"] = 307] = "TemporaryRedirect";
      HttpCodes2[HttpCodes2["PermanentRedirect"] = 308] = "PermanentRedirect";
      HttpCodes2[HttpCodes2["BadRequest"] = 400] = "BadRequest";
      HttpCodes2[HttpCodes2["Unauthorized"] = 401] = "Unauthorized";
      HttpCodes2[HttpCodes2["PaymentRequired"] = 402] = "PaymentRequired";
      HttpCodes2[HttpCodes2["Forbidden"] = 403] = "Forbidden";
      HttpCodes2[HttpCodes2["NotFound"] = 404] = "NotFound";
      HttpCodes2[HttpCodes2["MethodNotAllowed"] = 405] = "MethodNotAllowed";
      HttpCodes2[HttpCodes2["NotAcceptable"] = 406] = "NotAcceptable";
      HttpCodes2[HttpCodes2["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
      HttpCodes2[HttpCodes2["RequestTimeout"] = 408] = "RequestTimeout";
      HttpCodes2[HttpCodes2["Conflict"] = 409] = "Conflict";
      HttpCodes2[HttpCodes2["Gone"] = 410] = "Gone";
      HttpCodes2[HttpCodes2["TooManyRequests"] = 429] = "TooManyRequests";
      HttpCodes2[HttpCodes2["InternalServerError"] = 500] = "InternalServerError";
      HttpCodes2[HttpCodes2["NotImplemented"] = 501] = "NotImplemented";
      HttpCodes2[HttpCodes2["BadGateway"] = 502] = "BadGateway";
      HttpCodes2[HttpCodes2["ServiceUnavailable"] = 503] = "ServiceUnavailable";
      HttpCodes2[HttpCodes2["GatewayTimeout"] = 504] = "GatewayTimeout";
    })(HttpCodes = exports.HttpCodes || (exports.HttpCodes = {}));
    var Headers;
    (function(Headers2) {
      Headers2["Accept"] = "accept";
      Headers2["ContentType"] = "content-type";
    })(Headers = exports.Headers || (exports.Headers = {}));
    var MediaTypes;
    (function(MediaTypes2) {
      MediaTypes2["ApplicationJson"] = "application/json";
    })(MediaTypes = exports.MediaTypes || (exports.MediaTypes = {}));
    function getProxyUrl(serverUrl) {
      const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
      return proxyUrl ? proxyUrl.href : "";
    }
    exports.getProxyUrl = getProxyUrl;
    var HttpRedirectCodes = [
      HttpCodes.MovedPermanently,
      HttpCodes.ResourceMoved,
      HttpCodes.SeeOther,
      HttpCodes.TemporaryRedirect,
      HttpCodes.PermanentRedirect
    ];
    var HttpResponseRetryCodes = [
      HttpCodes.BadGateway,
      HttpCodes.ServiceUnavailable,
      HttpCodes.GatewayTimeout
    ];
    var RetryableHttpVerbs = ["OPTIONS", "GET", "DELETE", "HEAD"];
    var ExponentialBackoffCeiling = 10;
    var ExponentialBackoffTimeSlice = 5;
    var HttpClientError = class extends Error {
      constructor(message, statusCode) {
        super(message);
        this.name = "HttpClientError";
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, HttpClientError.prototype);
      }
    };
    exports.HttpClientError = HttpClientError;
    var HttpClientResponse = class {
      constructor(message) {
        this.message = message;
      }
      readBody() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
            let output = Buffer.alloc(0);
            this.message.on("data", (chunk) => {
              output = Buffer.concat([output, chunk]);
            });
            this.message.on("end", () => {
              resolve(output.toString());
            });
          }));
        });
      }
    };
    exports.HttpClientResponse = HttpClientResponse;
    function isHttps(requestUrl) {
      const parsedUrl = new URL(requestUrl);
      return parsedUrl.protocol === "https:";
    }
    exports.isHttps = isHttps;
    var HttpClient = class {
      constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
          if (requestOptions.ignoreSslError != null) {
            this._ignoreSslError = requestOptions.ignoreSslError;
          }
          this._socketTimeout = requestOptions.socketTimeout;
          if (requestOptions.allowRedirects != null) {
            this._allowRedirects = requestOptions.allowRedirects;
          }
          if (requestOptions.allowRedirectDowngrade != null) {
            this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
          }
          if (requestOptions.maxRedirects != null) {
            this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
          }
          if (requestOptions.keepAlive != null) {
            this._keepAlive = requestOptions.keepAlive;
          }
          if (requestOptions.allowRetries != null) {
            this._allowRetries = requestOptions.allowRetries;
          }
          if (requestOptions.maxRetries != null) {
            this._maxRetries = requestOptions.maxRetries;
          }
        }
      }
      options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("OPTIONS", requestUrl, null, additionalHeaders || {});
        });
      }
      get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("GET", requestUrl, null, additionalHeaders || {});
        });
      }
      del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("DELETE", requestUrl, null, additionalHeaders || {});
        });
      }
      post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("POST", requestUrl, data, additionalHeaders || {});
        });
      }
      patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PATCH", requestUrl, data, additionalHeaders || {});
        });
      }
      put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PUT", requestUrl, data, additionalHeaders || {});
        });
      }
      head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("HEAD", requestUrl, null, additionalHeaders || {});
        });
      }
      sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request(verb, requestUrl, stream, additionalHeaders);
        });
      }
      /**
       * Gets a typed object from an endpoint
       * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
       */
      getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          const res = yield this.get(requestUrl, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.post(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.put(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.patch(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      /**
       * Makes a raw http request.
       * All other methods such as get, post, patch, and request ultimately call this.
       * Prefer get, del, post and patch
       */
      request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._disposed) {
            throw new Error("Client has already been disposed.");
          }
          const parsedUrl = new URL(requestUrl);
          let info2 = this._prepareRequest(verb, parsedUrl, headers);
          const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb) ? this._maxRetries + 1 : 1;
          let numTries = 0;
          let response;
          do {
            response = yield this.requestRaw(info2, data);
            if (response && response.message && response.message.statusCode === HttpCodes.Unauthorized) {
              let authenticationHandler;
              for (const handler of this.handlers) {
                if (handler.canHandleAuthentication(response)) {
                  authenticationHandler = handler;
                  break;
                }
              }
              if (authenticationHandler) {
                return authenticationHandler.handleAuthentication(this, info2, data);
              } else {
                return response;
              }
            }
            let redirectsRemaining = this._maxRedirects;
            while (response.message.statusCode && HttpRedirectCodes.includes(response.message.statusCode) && this._allowRedirects && redirectsRemaining > 0) {
              const redirectUrl = response.message.headers["location"];
              if (!redirectUrl) {
                break;
              }
              const parsedRedirectUrl = new URL(redirectUrl);
              if (parsedUrl.protocol === "https:" && parsedUrl.protocol !== parsedRedirectUrl.protocol && !this._allowRedirectDowngrade) {
                throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
              }
              yield response.readBody();
              if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                for (const header in headers) {
                  if (header.toLowerCase() === "authorization") {
                    delete headers[header];
                  }
                }
              }
              info2 = this._prepareRequest(verb, parsedRedirectUrl, headers);
              response = yield this.requestRaw(info2, data);
              redirectsRemaining--;
            }
            if (!response.message.statusCode || !HttpResponseRetryCodes.includes(response.message.statusCode)) {
              return response;
            }
            numTries += 1;
            if (numTries < maxTries) {
              yield response.readBody();
              yield this._performExponentialBackoff(numTries);
            }
          } while (numTries < maxTries);
          return response;
        });
      }
      /**
       * Needs to be called if keepAlive is set to true in request options.
       */
      dispose() {
        if (this._agent) {
          this._agent.destroy();
        }
        this._disposed = true;
      }
      /**
       * Raw request.
       * @param info
       * @param data
       */
      requestRaw(info2, data) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => {
            function callbackForResult(err, res) {
              if (err) {
                reject(err);
              } else if (!res) {
                reject(new Error("Unknown error"));
              } else {
                resolve(res);
              }
            }
            this.requestRawWithCallback(info2, data, callbackForResult);
          });
        });
      }
      /**
       * Raw request with callback.
       * @param info
       * @param data
       * @param onResult
       */
      requestRawWithCallback(info2, data, onResult) {
        if (typeof data === "string") {
          if (!info2.options.headers) {
            info2.options.headers = {};
          }
          info2.options.headers["Content-Length"] = Buffer.byteLength(data, "utf8");
        }
        let callbackCalled = false;
        function handleResult(err, res) {
          if (!callbackCalled) {
            callbackCalled = true;
            onResult(err, res);
          }
        }
        const req = info2.httpModule.request(info2.options, (msg) => {
          const res = new HttpClientResponse(msg);
          handleResult(void 0, res);
        });
        let socket;
        req.on("socket", (sock) => {
          socket = sock;
        });
        req.setTimeout(this._socketTimeout || 3 * 6e4, () => {
          if (socket) {
            socket.end();
          }
          handleResult(new Error(`Request timeout: ${info2.options.path}`));
        });
        req.on("error", function(err) {
          handleResult(err);
        });
        if (data && typeof data === "string") {
          req.write(data, "utf8");
        }
        if (data && typeof data !== "string") {
          data.on("close", function() {
            req.end();
          });
          data.pipe(req);
        } else {
          req.end();
        }
      }
      /**
       * Gets an http agent. This function is useful when you need an http agent that handles
       * routing through a proxy server - depending upon the url and proxy environment variables.
       * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
       */
      getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
      }
      _prepareRequest(method, requestUrl, headers) {
        const info2 = {};
        info2.parsedUrl = requestUrl;
        const usingSsl = info2.parsedUrl.protocol === "https:";
        info2.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info2.options = {};
        info2.options.host = info2.parsedUrl.hostname;
        info2.options.port = info2.parsedUrl.port ? parseInt(info2.parsedUrl.port) : defaultPort;
        info2.options.path = (info2.parsedUrl.pathname || "") + (info2.parsedUrl.search || "");
        info2.options.method = method;
        info2.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
          info2.options.headers["user-agent"] = this.userAgent;
        }
        info2.options.agent = this._getAgent(info2.parsedUrl);
        if (this.handlers) {
          for (const handler of this.handlers) {
            handler.prepareRequest(info2.options);
          }
        }
        return info2;
      }
      _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
          return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
      }
      _getExistingOrDefaultHeader(additionalHeaders, header, _default2) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
          clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default2;
      }
      _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
          agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
          agent = this._agent;
        }
        if (agent) {
          return agent;
        }
        const usingSsl = parsedUrl.protocol === "https:";
        let maxSockets = 100;
        if (this.requestOptions) {
          maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        if (proxyUrl && proxyUrl.hostname) {
          const agentOptions = {
            maxSockets,
            keepAlive: this._keepAlive,
            proxy: Object.assign(Object.assign({}, (proxyUrl.username || proxyUrl.password) && {
              proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
            }), { host: proxyUrl.hostname, port: proxyUrl.port })
          };
          let tunnelAgent;
          const overHttps = proxyUrl.protocol === "https:";
          if (usingSsl) {
            tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
          } else {
            tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
          }
          agent = tunnelAgent(agentOptions);
          this._proxyAgent = agent;
        }
        if (this._keepAlive && !agent) {
          const options = { keepAlive: this._keepAlive, maxSockets };
          agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
          this._agent = agent;
        }
        if (!agent) {
          agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
          agent.options = Object.assign(agent.options || {}, {
            rejectUnauthorized: false
          });
        }
        return agent;
      }
      _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
          retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
          const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
          return new Promise((resolve) => setTimeout(() => resolve(), ms));
        });
      }
      _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            const statusCode = res.message.statusCode || 0;
            const response = {
              statusCode,
              result: null,
              headers: {}
            };
            if (statusCode === HttpCodes.NotFound) {
              resolve(response);
            }
            function dateTimeDeserializer(key, value) {
              if (typeof value === "string") {
                const a = new Date(value);
                if (!isNaN(a.valueOf())) {
                  return a;
                }
              }
              return value;
            }
            let obj;
            let contents;
            try {
              contents = yield res.readBody();
              if (contents && contents.length > 0) {
                if (options && options.deserializeDates) {
                  obj = JSON.parse(contents, dateTimeDeserializer);
                } else {
                  obj = JSON.parse(contents);
                }
                response.result = obj;
              }
              response.headers = res.message.headers;
            } catch (err) {
            }
            if (statusCode > 299) {
              let msg;
              if (obj && obj.message) {
                msg = obj.message;
              } else if (contents && contents.length > 0) {
                msg = contents;
              } else {
                msg = `Failed request: (${statusCode})`;
              }
              const err = new HttpClientError(msg, statusCode);
              err.result = response.result;
              reject(err);
            } else {
              resolve(response);
            }
          }));
        });
      }
    };
    exports.HttpClient = HttpClient;
    var lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => (c[k.toLowerCase()] = obj[k], c), {});
  }
});

// node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS({
  "node_modules/@actions/http-client/lib/auth.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.PersonalAccessTokenCredentialHandler = exports.BearerCredentialHandler = exports.BasicCredentialHandler = void 0;
    var BasicCredentialHandler = class {
      constructor(username, password) {
        this.username = username;
        this.password = password;
      }
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BasicCredentialHandler = BasicCredentialHandler;
    var BearerCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Bearer ${this.token}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BearerCredentialHandler = BearerCredentialHandler;
    var PersonalAccessTokenCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
  }
});

// node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS({
  "node_modules/@actions/core/lib/oidc-utils.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.OidcClient = void 0;
    var http_client_1 = require_lib();
    var auth_1 = require_auth();
    var core_1 = require_core();
    var OidcClient = class {
      static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
          allowRetries: allowRetry,
          maxRetries: maxRetry
        };
        return new http_client_1.HttpClient("actions/oidc-client", [new auth_1.BearerCredentialHandler(OidcClient.getRequestToken())], requestOptions);
      }
      static getRequestToken() {
        const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
        if (!token) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
        }
        return token;
      }
      static getIDTokenUrl() {
        const runtimeUrl = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
        if (!runtimeUrl) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
        }
        return runtimeUrl;
      }
      static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
          const httpclient = OidcClient.createHttpClient();
          const res = yield httpclient.getJson(id_token_url).catch((error2) => {
            throw new Error(`Failed to get ID Token. 
 
        Error Code : ${error2.statusCode}
 
        Error Message: ${error2.result.message}`);
          });
          const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
          if (!id_token) {
            throw new Error("Response json body do not have ID Token field");
          }
          return id_token;
        });
      }
      static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
          try {
            let id_token_url = OidcClient.getIDTokenUrl();
            if (audience) {
              const encodedAudience = encodeURIComponent(audience);
              id_token_url = `${id_token_url}&audience=${encodedAudience}`;
            }
            core_1.debug(`ID token url is ${id_token_url}`);
            const id_token = yield OidcClient.getCall(id_token_url);
            core_1.setSecret(id_token);
            return id_token;
          } catch (error2) {
            throw new Error(`Error message: ${error2.message}`);
          }
        });
      }
    };
    exports.OidcClient = OidcClient;
  }
});

// node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS({
  "node_modules/@actions/core/lib/summary.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.summary = exports.markdownSummary = exports.SUMMARY_DOCS_URL = exports.SUMMARY_ENV_VAR = void 0;
    var os_1 = require("os");
    var fs_1 = require("fs");
    var { access, appendFile, writeFile } = fs_1.promises;
    exports.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
    exports.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    var Summary = class {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._filePath) {
            return this._filePath;
          }
          const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR];
          if (!pathFromEnv) {
            throw new Error(`Unable to find environment variable for $${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          }
          try {
            yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
          } catch (_a) {
            throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
          }
          this._filePath = pathFromEnv;
          return this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
        if (!content) {
          return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(options) {
        return __awaiter(this, void 0, void 0, function* () {
          const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
          const filePath = yield this.filePath();
          const writeFunc = overwrite ? writeFile : appendFile;
          yield writeFunc(filePath, this._buffer, { encoding: "utf8" });
          return this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return __awaiter(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: true });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        this._buffer = "";
        return this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(os_1.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(code, lang) {
        const attrs = Object.assign({}, lang && { lang });
        const element = this.wrap("pre", this.wrap("code", code), attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(items, ordered = false) {
        const tag = ordered ? "ol" : "ul";
        const listItems = items.map((item) => this.wrap("li", item)).join("");
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(rows) {
        const tableBody = rows.map((row) => {
          const cells = row.map((cell) => {
            if (typeof cell === "string") {
              return this.wrap("td", cell);
            }
            const { header, data, colspan, rowspan } = cell;
            const tag = header ? "th" : "td";
            const attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
            return this.wrap(tag, data, attrs);
          }).join("");
          return this.wrap("tr", cells);
        }).join("");
        const element = this.wrap("table", tableBody);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(label, content) {
        const element = this.wrap("details", this.wrap("summary", label) + content);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, width && { width }), height && { height });
        const element = this.wrap("img", null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag) ? tag : "h1";
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const element = this.wrap("hr", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const element = this.wrap("br", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(text, cite) {
        const attrs = Object.assign({}, cite && { cite });
        const element = this.wrap("blockquote", text, attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(text, href) {
        const element = this.wrap("a", text, { href });
        return this.addRaw(element).addEOL();
      }
    };
    var _summary = new Summary();
    exports.markdownSummary = _summary;
    exports.summary = _summary;
  }
});

// node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS({
  "node_modules/@actions/core/lib/path-utils.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = void 0;
    var path = __importStar(require("path"));
    function toPosixPath(pth) {
      return pth.replace(/[\\]/g, "/");
    }
    exports.toPosixPath = toPosixPath;
    function toWin32Path(pth) {
      return pth.replace(/[/]/g, "\\");
    }
    exports.toWin32Path = toWin32Path;
    function toPlatformPath(pth) {
      return pth.replace(/[/\\]/g, path.sep);
    }
    exports.toPlatformPath = toPlatformPath;
  }
});

// node_modules/@actions/core/lib/core.js
var require_core = __commonJS({
  "node_modules/@actions/core/lib/core.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getIDToken = exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.notice = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getMultilineInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
    var command_1 = require_command();
    var file_command_1 = require_file_command();
    var utils_1 = require_utils();
    var os = __importStar(require("os"));
    var path = __importStar(require("path"));
    var oidc_utils_1 = require_oidc_utils();
    var ExitCode;
    (function(ExitCode2) {
      ExitCode2[ExitCode2["Success"] = 0] = "Success";
      ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
    })(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
    function exportVariable(name, val) {
      const convertedVal = utils_1.toCommandValue(val);
      process.env[name] = convertedVal;
      const filePath = process.env["GITHUB_ENV"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("ENV", file_command_1.prepareKeyValueMessage(name, val));
      }
      command_1.issueCommand("set-env", { name }, convertedVal);
    }
    exports.exportVariable = exportVariable;
    function setSecret(secret) {
      command_1.issueCommand("add-mask", {}, secret);
    }
    exports.setSecret = setSecret;
    function addPath(inputPath) {
      const filePath = process.env["GITHUB_PATH"] || "";
      if (filePath) {
        file_command_1.issueFileCommand("PATH", inputPath);
      } else {
        command_1.issueCommand("add-path", {}, inputPath);
      }
      process.env["PATH"] = `${inputPath}${path.delimiter}${process.env["PATH"]}`;
    }
    exports.addPath = addPath;
    function getInput2(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      if (options && options.trimWhitespace === false) {
        return val;
      }
      return val.trim();
    }
    exports.getInput = getInput2;
    function getMultilineInput(name, options) {
      const inputs = getInput2(name, options).split("\n").filter((x) => x !== "");
      if (options && options.trimWhitespace === false) {
        return inputs;
      }
      return inputs.map((input) => input.trim());
    }
    exports.getMultilineInput = getMultilineInput;
    function getBooleanInput(name, options) {
      const trueValue = ["true", "True", "TRUE"];
      const falseValue = ["false", "False", "FALSE"];
      const val = getInput2(name, options);
      if (trueValue.includes(val))
        return true;
      if (falseValue.includes(val))
        return false;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    exports.getBooleanInput = getBooleanInput;
    function setOutput(name, value) {
      const filePath = process.env["GITHUB_OUTPUT"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("OUTPUT", file_command_1.prepareKeyValueMessage(name, value));
      }
      process.stdout.write(os.EOL);
      command_1.issueCommand("set-output", { name }, utils_1.toCommandValue(value));
    }
    exports.setOutput = setOutput;
    function setCommandEcho(enabled) {
      command_1.issue("echo", enabled ? "on" : "off");
    }
    exports.setCommandEcho = setCommandEcho;
    function setFailed(message) {
      process.exitCode = ExitCode.Failure;
      error2(message);
    }
    exports.setFailed = setFailed;
    function isDebug() {
      return process.env["RUNNER_DEBUG"] === "1";
    }
    exports.isDebug = isDebug;
    function debug(message) {
      command_1.issueCommand("debug", {}, message);
    }
    exports.debug = debug;
    function error2(message, properties = {}) {
      command_1.issueCommand("error", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.error = error2;
    function warning(message, properties = {}) {
      command_1.issueCommand("warning", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.warning = warning;
    function notice(message, properties = {}) {
      command_1.issueCommand("notice", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.notice = notice;
    function info2(message) {
      process.stdout.write(message + os.EOL);
    }
    exports.info = info2;
    function startGroup(name) {
      command_1.issue("group", name);
    }
    exports.startGroup = startGroup;
    function endGroup() {
      command_1.issue("endgroup");
    }
    exports.endGroup = endGroup;
    function group(name, fn) {
      return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
          result = yield fn();
        } finally {
          endGroup();
        }
        return result;
      });
    }
    exports.group = group;
    function saveState(name, value) {
      const filePath = process.env["GITHUB_STATE"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("STATE", file_command_1.prepareKeyValueMessage(name, value));
      }
      command_1.issueCommand("save-state", { name }, utils_1.toCommandValue(value));
    }
    exports.saveState = saveState;
    function getState(name) {
      return process.env[`STATE_${name}`] || "";
    }
    exports.getState = getState;
    function getIDToken(aud) {
      return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
      });
    }
    exports.getIDToken = getIDToken;
    var summary_1 = require_summary();
    Object.defineProperty(exports, "summary", { enumerable: true, get: function() {
      return summary_1.summary;
    } });
    var summary_2 = require_summary();
    Object.defineProperty(exports, "markdownSummary", { enumerable: true, get: function() {
      return summary_2.markdownSummary;
    } });
    var path_utils_1 = require_path_utils();
    Object.defineProperty(exports, "toPosixPath", { enumerable: true, get: function() {
      return path_utils_1.toPosixPath;
    } });
    Object.defineProperty(exports, "toWin32Path", { enumerable: true, get: function() {
      return path_utils_1.toWin32Path;
    } });
    Object.defineProperty(exports, "toPlatformPath", { enumerable: true, get: function() {
      return path_utils_1.toPlatformPath;
    } });
  }
});

// src/config.ts
var import_node_process = require("process");
var import_core = __toESM(require_core());

// node_modules/js-yaml/dist/js-yaml.mjs
function isNothing(subject) {
  return typeof subject === "undefined" || subject === null;
}
function isObject(subject) {
  return typeof subject === "object" && subject !== null;
}
function toArray(sequence) {
  if (Array.isArray(sequence))
    return sequence;
  else if (isNothing(sequence))
    return [];
  return [sequence];
}
function extend(target, source) {
  var index, length, key, sourceKeys;
  if (source) {
    sourceKeys = Object.keys(source);
    for (index = 0, length = sourceKeys.length; index < length; index += 1) {
      key = sourceKeys[index];
      target[key] = source[key];
    }
  }
  return target;
}
function repeat(string, count) {
  var result = "", cycle;
  for (cycle = 0; cycle < count; cycle += 1) {
    result += string;
  }
  return result;
}
function isNegativeZero(number) {
  return number === 0 && Number.NEGATIVE_INFINITY === 1 / number;
}
var isNothing_1 = isNothing;
var isObject_1 = isObject;
var toArray_1 = toArray;
var repeat_1 = repeat;
var isNegativeZero_1 = isNegativeZero;
var extend_1 = extend;
var common = {
  isNothing: isNothing_1,
  isObject: isObject_1,
  toArray: toArray_1,
  repeat: repeat_1,
  isNegativeZero: isNegativeZero_1,
  extend: extend_1
};
function formatError(exception2, compact) {
  var where = "", message = exception2.reason || "(unknown reason)";
  if (!exception2.mark)
    return message;
  if (exception2.mark.name) {
    where += 'in "' + exception2.mark.name + '" ';
  }
  where += "(" + (exception2.mark.line + 1) + ":" + (exception2.mark.column + 1) + ")";
  if (!compact && exception2.mark.snippet) {
    where += "\n\n" + exception2.mark.snippet;
  }
  return message + " " + where;
}
function YAMLException$1(reason, mark) {
  Error.call(this);
  this.name = "YAMLException";
  this.reason = reason;
  this.mark = mark;
  this.message = formatError(this, false);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  } else {
    this.stack = new Error().stack || "";
  }
}
YAMLException$1.prototype = Object.create(Error.prototype);
YAMLException$1.prototype.constructor = YAMLException$1;
YAMLException$1.prototype.toString = function toString(compact) {
  return this.name + ": " + formatError(this, compact);
};
var exception = YAMLException$1;
function getLine(buffer, lineStart, lineEnd, position, maxLineLength) {
  var head = "";
  var tail = "";
  var maxHalfLength = Math.floor(maxLineLength / 2) - 1;
  if (position - lineStart > maxHalfLength) {
    head = " ... ";
    lineStart = position - maxHalfLength + head.length;
  }
  if (lineEnd - position > maxHalfLength) {
    tail = " ...";
    lineEnd = position + maxHalfLength - tail.length;
  }
  return {
    str: head + buffer.slice(lineStart, lineEnd).replace(/\t/g, "\u2192") + tail,
    pos: position - lineStart + head.length
    // relative position
  };
}
function padStart(string, max) {
  return common.repeat(" ", max - string.length) + string;
}
function makeSnippet(mark, options) {
  options = Object.create(options || null);
  if (!mark.buffer)
    return null;
  if (!options.maxLength)
    options.maxLength = 79;
  if (typeof options.indent !== "number")
    options.indent = 1;
  if (typeof options.linesBefore !== "number")
    options.linesBefore = 3;
  if (typeof options.linesAfter !== "number")
    options.linesAfter = 2;
  var re = /\r?\n|\r|\0/g;
  var lineStarts = [0];
  var lineEnds = [];
  var match;
  var foundLineNo = -1;
  while (match = re.exec(mark.buffer)) {
    lineEnds.push(match.index);
    lineStarts.push(match.index + match[0].length);
    if (mark.position <= match.index && foundLineNo < 0) {
      foundLineNo = lineStarts.length - 2;
    }
  }
  if (foundLineNo < 0)
    foundLineNo = lineStarts.length - 1;
  var result = "", i, line;
  var lineNoLength = Math.min(mark.line + options.linesAfter, lineEnds.length).toString().length;
  var maxLineLength = options.maxLength - (options.indent + lineNoLength + 3);
  for (i = 1; i <= options.linesBefore; i++) {
    if (foundLineNo - i < 0)
      break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo - i],
      lineEnds[foundLineNo - i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo - i]),
      maxLineLength
    );
    result = common.repeat(" ", options.indent) + padStart((mark.line - i + 1).toString(), lineNoLength) + " | " + line.str + "\n" + result;
  }
  line = getLine(mark.buffer, lineStarts[foundLineNo], lineEnds[foundLineNo], mark.position, maxLineLength);
  result += common.repeat(" ", options.indent) + padStart((mark.line + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  result += common.repeat("-", options.indent + lineNoLength + 3 + line.pos) + "^\n";
  for (i = 1; i <= options.linesAfter; i++) {
    if (foundLineNo + i >= lineEnds.length)
      break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo + i],
      lineEnds[foundLineNo + i],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo + i]),
      maxLineLength
    );
    result += common.repeat(" ", options.indent) + padStart((mark.line + i + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  }
  return result.replace(/\n$/, "");
}
var snippet = makeSnippet;
var TYPE_CONSTRUCTOR_OPTIONS = [
  "kind",
  "multi",
  "resolve",
  "construct",
  "instanceOf",
  "predicate",
  "represent",
  "representName",
  "defaultStyle",
  "styleAliases"
];
var YAML_NODE_KINDS = [
  "scalar",
  "sequence",
  "mapping"
];
function compileStyleAliases(map2) {
  var result = {};
  if (map2 !== null) {
    Object.keys(map2).forEach(function(style) {
      map2[style].forEach(function(alias) {
        result[String(alias)] = style;
      });
    });
  }
  return result;
}
function Type$1(tag, options) {
  options = options || {};
  Object.keys(options).forEach(function(name) {
    if (TYPE_CONSTRUCTOR_OPTIONS.indexOf(name) === -1) {
      throw new exception('Unknown option "' + name + '" is met in definition of "' + tag + '" YAML type.');
    }
  });
  this.options = options;
  this.tag = tag;
  this.kind = options["kind"] || null;
  this.resolve = options["resolve"] || function() {
    return true;
  };
  this.construct = options["construct"] || function(data) {
    return data;
  };
  this.instanceOf = options["instanceOf"] || null;
  this.predicate = options["predicate"] || null;
  this.represent = options["represent"] || null;
  this.representName = options["representName"] || null;
  this.defaultStyle = options["defaultStyle"] || null;
  this.multi = options["multi"] || false;
  this.styleAliases = compileStyleAliases(options["styleAliases"] || null);
  if (YAML_NODE_KINDS.indexOf(this.kind) === -1) {
    throw new exception('Unknown kind "' + this.kind + '" is specified for "' + tag + '" YAML type.');
  }
}
var type = Type$1;
function compileList(schema2, name) {
  var result = [];
  schema2[name].forEach(function(currentType) {
    var newIndex = result.length;
    result.forEach(function(previousType, previousIndex) {
      if (previousType.tag === currentType.tag && previousType.kind === currentType.kind && previousType.multi === currentType.multi) {
        newIndex = previousIndex;
      }
    });
    result[newIndex] = currentType;
  });
  return result;
}
function compileMap() {
  var result = {
    scalar: {},
    sequence: {},
    mapping: {},
    fallback: {},
    multi: {
      scalar: [],
      sequence: [],
      mapping: [],
      fallback: []
    }
  }, index, length;
  function collectType(type2) {
    if (type2.multi) {
      result.multi[type2.kind].push(type2);
      result.multi["fallback"].push(type2);
    } else {
      result[type2.kind][type2.tag] = result["fallback"][type2.tag] = type2;
    }
  }
  for (index = 0, length = arguments.length; index < length; index += 1) {
    arguments[index].forEach(collectType);
  }
  return result;
}
function Schema$1(definition) {
  return this.extend(definition);
}
Schema$1.prototype.extend = function extend2(definition) {
  var implicit = [];
  var explicit = [];
  if (definition instanceof type) {
    explicit.push(definition);
  } else if (Array.isArray(definition)) {
    explicit = explicit.concat(definition);
  } else if (definition && (Array.isArray(definition.implicit) || Array.isArray(definition.explicit))) {
    if (definition.implicit)
      implicit = implicit.concat(definition.implicit);
    if (definition.explicit)
      explicit = explicit.concat(definition.explicit);
  } else {
    throw new exception("Schema.extend argument should be a Type, [ Type ], or a schema definition ({ implicit: [...], explicit: [...] })");
  }
  implicit.forEach(function(type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
    }
    if (type$1.loadKind && type$1.loadKind !== "scalar") {
      throw new exception("There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.");
    }
    if (type$1.multi) {
      throw new exception("There is a multi type in the implicit list of a schema. Multi tags can only be listed as explicit.");
    }
  });
  explicit.forEach(function(type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
    }
  });
  var result = Object.create(Schema$1.prototype);
  result.implicit = (this.implicit || []).concat(implicit);
  result.explicit = (this.explicit || []).concat(explicit);
  result.compiledImplicit = compileList(result, "implicit");
  result.compiledExplicit = compileList(result, "explicit");
  result.compiledTypeMap = compileMap(result.compiledImplicit, result.compiledExplicit);
  return result;
};
var schema = Schema$1;
var str = new type("tag:yaml.org,2002:str", {
  kind: "scalar",
  construct: function(data) {
    return data !== null ? data : "";
  }
});
var seq = new type("tag:yaml.org,2002:seq", {
  kind: "sequence",
  construct: function(data) {
    return data !== null ? data : [];
  }
});
var map = new type("tag:yaml.org,2002:map", {
  kind: "mapping",
  construct: function(data) {
    return data !== null ? data : {};
  }
});
var failsafe = new schema({
  explicit: [
    str,
    seq,
    map
  ]
});
function resolveYamlNull(data) {
  if (data === null)
    return true;
  var max = data.length;
  return max === 1 && data === "~" || max === 4 && (data === "null" || data === "Null" || data === "NULL");
}
function constructYamlNull() {
  return null;
}
function isNull(object) {
  return object === null;
}
var _null = new type("tag:yaml.org,2002:null", {
  kind: "scalar",
  resolve: resolveYamlNull,
  construct: constructYamlNull,
  predicate: isNull,
  represent: {
    canonical: function() {
      return "~";
    },
    lowercase: function() {
      return "null";
    },
    uppercase: function() {
      return "NULL";
    },
    camelcase: function() {
      return "Null";
    },
    empty: function() {
      return "";
    }
  },
  defaultStyle: "lowercase"
});
function resolveYamlBoolean(data) {
  if (data === null)
    return false;
  var max = data.length;
  return max === 4 && (data === "true" || data === "True" || data === "TRUE") || max === 5 && (data === "false" || data === "False" || data === "FALSE");
}
function constructYamlBoolean(data) {
  return data === "true" || data === "True" || data === "TRUE";
}
function isBoolean(object) {
  return Object.prototype.toString.call(object) === "[object Boolean]";
}
var bool = new type("tag:yaml.org,2002:bool", {
  kind: "scalar",
  resolve: resolveYamlBoolean,
  construct: constructYamlBoolean,
  predicate: isBoolean,
  represent: {
    lowercase: function(object) {
      return object ? "true" : "false";
    },
    uppercase: function(object) {
      return object ? "TRUE" : "FALSE";
    },
    camelcase: function(object) {
      return object ? "True" : "False";
    }
  },
  defaultStyle: "lowercase"
});
function isHexCode(c) {
  return 48 <= c && c <= 57 || 65 <= c && c <= 70 || 97 <= c && c <= 102;
}
function isOctCode(c) {
  return 48 <= c && c <= 55;
}
function isDecCode(c) {
  return 48 <= c && c <= 57;
}
function resolveYamlInteger(data) {
  if (data === null)
    return false;
  var max = data.length, index = 0, hasDigits = false, ch;
  if (!max)
    return false;
  ch = data[index];
  if (ch === "-" || ch === "+") {
    ch = data[++index];
  }
  if (ch === "0") {
    if (index + 1 === max)
      return true;
    ch = data[++index];
    if (ch === "b") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_")
          continue;
        if (ch !== "0" && ch !== "1")
          return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "x") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_")
          continue;
        if (!isHexCode(data.charCodeAt(index)))
          return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "o") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_")
          continue;
        if (!isOctCode(data.charCodeAt(index)))
          return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
  }
  if (ch === "_")
    return false;
  for (; index < max; index++) {
    ch = data[index];
    if (ch === "_")
      continue;
    if (!isDecCode(data.charCodeAt(index))) {
      return false;
    }
    hasDigits = true;
  }
  if (!hasDigits || ch === "_")
    return false;
  return true;
}
function constructYamlInteger(data) {
  var value = data, sign = 1, ch;
  if (value.indexOf("_") !== -1) {
    value = value.replace(/_/g, "");
  }
  ch = value[0];
  if (ch === "-" || ch === "+") {
    if (ch === "-")
      sign = -1;
    value = value.slice(1);
    ch = value[0];
  }
  if (value === "0")
    return 0;
  if (ch === "0") {
    if (value[1] === "b")
      return sign * parseInt(value.slice(2), 2);
    if (value[1] === "x")
      return sign * parseInt(value.slice(2), 16);
    if (value[1] === "o")
      return sign * parseInt(value.slice(2), 8);
  }
  return sign * parseInt(value, 10);
}
function isInteger(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 === 0 && !common.isNegativeZero(object));
}
var int = new type("tag:yaml.org,2002:int", {
  kind: "scalar",
  resolve: resolveYamlInteger,
  construct: constructYamlInteger,
  predicate: isInteger,
  represent: {
    binary: function(obj) {
      return obj >= 0 ? "0b" + obj.toString(2) : "-0b" + obj.toString(2).slice(1);
    },
    octal: function(obj) {
      return obj >= 0 ? "0o" + obj.toString(8) : "-0o" + obj.toString(8).slice(1);
    },
    decimal: function(obj) {
      return obj.toString(10);
    },
    /* eslint-disable max-len */
    hexadecimal: function(obj) {
      return obj >= 0 ? "0x" + obj.toString(16).toUpperCase() : "-0x" + obj.toString(16).toUpperCase().slice(1);
    }
  },
  defaultStyle: "decimal",
  styleAliases: {
    binary: [2, "bin"],
    octal: [8, "oct"],
    decimal: [10, "dec"],
    hexadecimal: [16, "hex"]
  }
});
var YAML_FLOAT_PATTERN = new RegExp(
  // 2.5e4, 2.5 and integers
  "^(?:[-+]?(?:[0-9][0-9_]*)(?:\\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|\\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?\\.(?:inf|Inf|INF)|\\.(?:nan|NaN|NAN))$"
);
function resolveYamlFloat(data) {
  if (data === null)
    return false;
  if (!YAML_FLOAT_PATTERN.test(data) || // Quick hack to not allow integers end with `_`
  // Probably should update regexp & check speed
  data[data.length - 1] === "_") {
    return false;
  }
  return true;
}
function constructYamlFloat(data) {
  var value, sign;
  value = data.replace(/_/g, "").toLowerCase();
  sign = value[0] === "-" ? -1 : 1;
  if ("+-".indexOf(value[0]) >= 0) {
    value = value.slice(1);
  }
  if (value === ".inf") {
    return sign === 1 ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
  } else if (value === ".nan") {
    return NaN;
  }
  return sign * parseFloat(value, 10);
}
var SCIENTIFIC_WITHOUT_DOT = /^[-+]?[0-9]+e/;
function representYamlFloat(object, style) {
  var res;
  if (isNaN(object)) {
    switch (style) {
      case "lowercase":
        return ".nan";
      case "uppercase":
        return ".NAN";
      case "camelcase":
        return ".NaN";
    }
  } else if (Number.POSITIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return ".inf";
      case "uppercase":
        return ".INF";
      case "camelcase":
        return ".Inf";
    }
  } else if (Number.NEGATIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return "-.inf";
      case "uppercase":
        return "-.INF";
      case "camelcase":
        return "-.Inf";
    }
  } else if (common.isNegativeZero(object)) {
    return "-0.0";
  }
  res = object.toString(10);
  return SCIENTIFIC_WITHOUT_DOT.test(res) ? res.replace("e", ".e") : res;
}
function isFloat(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 !== 0 || common.isNegativeZero(object));
}
var float = new type("tag:yaml.org,2002:float", {
  kind: "scalar",
  resolve: resolveYamlFloat,
  construct: constructYamlFloat,
  predicate: isFloat,
  represent: representYamlFloat,
  defaultStyle: "lowercase"
});
var json = failsafe.extend({
  implicit: [
    _null,
    bool,
    int,
    float
  ]
});
var core = json;
var YAML_DATE_REGEXP = new RegExp(
  "^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])$"
);
var YAML_TIMESTAMP_REGEXP = new RegExp(
  "^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:[Tt]|[ \\t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\\.([0-9]*))?(?:[ \\t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?$"
);
function resolveYamlTimestamp(data) {
  if (data === null)
    return false;
  if (YAML_DATE_REGEXP.exec(data) !== null)
    return true;
  if (YAML_TIMESTAMP_REGEXP.exec(data) !== null)
    return true;
  return false;
}
function constructYamlTimestamp(data) {
  var match, year, month, day, hour, minute, second, fraction = 0, delta = null, tz_hour, tz_minute, date;
  match = YAML_DATE_REGEXP.exec(data);
  if (match === null)
    match = YAML_TIMESTAMP_REGEXP.exec(data);
  if (match === null)
    throw new Error("Date resolve error");
  year = +match[1];
  month = +match[2] - 1;
  day = +match[3];
  if (!match[4]) {
    return new Date(Date.UTC(year, month, day));
  }
  hour = +match[4];
  minute = +match[5];
  second = +match[6];
  if (match[7]) {
    fraction = match[7].slice(0, 3);
    while (fraction.length < 3) {
      fraction += "0";
    }
    fraction = +fraction;
  }
  if (match[9]) {
    tz_hour = +match[10];
    tz_minute = +(match[11] || 0);
    delta = (tz_hour * 60 + tz_minute) * 6e4;
    if (match[9] === "-")
      delta = -delta;
  }
  date = new Date(Date.UTC(year, month, day, hour, minute, second, fraction));
  if (delta)
    date.setTime(date.getTime() - delta);
  return date;
}
function representYamlTimestamp(object) {
  return object.toISOString();
}
var timestamp = new type("tag:yaml.org,2002:timestamp", {
  kind: "scalar",
  resolve: resolveYamlTimestamp,
  construct: constructYamlTimestamp,
  instanceOf: Date,
  represent: representYamlTimestamp
});
function resolveYamlMerge(data) {
  return data === "<<" || data === null;
}
var merge = new type("tag:yaml.org,2002:merge", {
  kind: "scalar",
  resolve: resolveYamlMerge
});
var BASE64_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r";
function resolveYamlBinary(data) {
  if (data === null)
    return false;
  var code, idx, bitlen = 0, max = data.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    code = map2.indexOf(data.charAt(idx));
    if (code > 64)
      continue;
    if (code < 0)
      return false;
    bitlen += 6;
  }
  return bitlen % 8 === 0;
}
function constructYamlBinary(data) {
  var idx, tailbits, input = data.replace(/[\r\n=]/g, ""), max = input.length, map2 = BASE64_MAP, bits = 0, result = [];
  for (idx = 0; idx < max; idx++) {
    if (idx % 4 === 0 && idx) {
      result.push(bits >> 16 & 255);
      result.push(bits >> 8 & 255);
      result.push(bits & 255);
    }
    bits = bits << 6 | map2.indexOf(input.charAt(idx));
  }
  tailbits = max % 4 * 6;
  if (tailbits === 0) {
    result.push(bits >> 16 & 255);
    result.push(bits >> 8 & 255);
    result.push(bits & 255);
  } else if (tailbits === 18) {
    result.push(bits >> 10 & 255);
    result.push(bits >> 2 & 255);
  } else if (tailbits === 12) {
    result.push(bits >> 4 & 255);
  }
  return new Uint8Array(result);
}
function representYamlBinary(object) {
  var result = "", bits = 0, idx, tail, max = object.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    if (idx % 3 === 0 && idx) {
      result += map2[bits >> 18 & 63];
      result += map2[bits >> 12 & 63];
      result += map2[bits >> 6 & 63];
      result += map2[bits & 63];
    }
    bits = (bits << 8) + object[idx];
  }
  tail = max % 3;
  if (tail === 0) {
    result += map2[bits >> 18 & 63];
    result += map2[bits >> 12 & 63];
    result += map2[bits >> 6 & 63];
    result += map2[bits & 63];
  } else if (tail === 2) {
    result += map2[bits >> 10 & 63];
    result += map2[bits >> 4 & 63];
    result += map2[bits << 2 & 63];
    result += map2[64];
  } else if (tail === 1) {
    result += map2[bits >> 2 & 63];
    result += map2[bits << 4 & 63];
    result += map2[64];
    result += map2[64];
  }
  return result;
}
function isBinary(obj) {
  return Object.prototype.toString.call(obj) === "[object Uint8Array]";
}
var binary = new type("tag:yaml.org,2002:binary", {
  kind: "scalar",
  resolve: resolveYamlBinary,
  construct: constructYamlBinary,
  predicate: isBinary,
  represent: representYamlBinary
});
var _hasOwnProperty$3 = Object.prototype.hasOwnProperty;
var _toString$2 = Object.prototype.toString;
function resolveYamlOmap(data) {
  if (data === null)
    return true;
  var objectKeys = [], index, length, pair, pairKey, pairHasKey, object = data;
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    pairHasKey = false;
    if (_toString$2.call(pair) !== "[object Object]")
      return false;
    for (pairKey in pair) {
      if (_hasOwnProperty$3.call(pair, pairKey)) {
        if (!pairHasKey)
          pairHasKey = true;
        else
          return false;
      }
    }
    if (!pairHasKey)
      return false;
    if (objectKeys.indexOf(pairKey) === -1)
      objectKeys.push(pairKey);
    else
      return false;
  }
  return true;
}
function constructYamlOmap(data) {
  return data !== null ? data : [];
}
var omap = new type("tag:yaml.org,2002:omap", {
  kind: "sequence",
  resolve: resolveYamlOmap,
  construct: constructYamlOmap
});
var _toString$1 = Object.prototype.toString;
function resolveYamlPairs(data) {
  if (data === null)
    return true;
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    if (_toString$1.call(pair) !== "[object Object]")
      return false;
    keys = Object.keys(pair);
    if (keys.length !== 1)
      return false;
    result[index] = [keys[0], pair[keys[0]]];
  }
  return true;
}
function constructYamlPairs(data) {
  if (data === null)
    return [];
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    keys = Object.keys(pair);
    result[index] = [keys[0], pair[keys[0]]];
  }
  return result;
}
var pairs = new type("tag:yaml.org,2002:pairs", {
  kind: "sequence",
  resolve: resolveYamlPairs,
  construct: constructYamlPairs
});
var _hasOwnProperty$2 = Object.prototype.hasOwnProperty;
function resolveYamlSet(data) {
  if (data === null)
    return true;
  var key, object = data;
  for (key in object) {
    if (_hasOwnProperty$2.call(object, key)) {
      if (object[key] !== null)
        return false;
    }
  }
  return true;
}
function constructYamlSet(data) {
  return data !== null ? data : {};
}
var set = new type("tag:yaml.org,2002:set", {
  kind: "mapping",
  resolve: resolveYamlSet,
  construct: constructYamlSet
});
var _default = core.extend({
  implicit: [
    timestamp,
    merge
  ],
  explicit: [
    binary,
    omap,
    pairs,
    set
  ]
});
var _hasOwnProperty$1 = Object.prototype.hasOwnProperty;
var CONTEXT_FLOW_IN = 1;
var CONTEXT_FLOW_OUT = 2;
var CONTEXT_BLOCK_IN = 3;
var CONTEXT_BLOCK_OUT = 4;
var CHOMPING_CLIP = 1;
var CHOMPING_STRIP = 2;
var CHOMPING_KEEP = 3;
var PATTERN_NON_PRINTABLE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
var PATTERN_NON_ASCII_LINE_BREAKS = /[\x85\u2028\u2029]/;
var PATTERN_FLOW_INDICATORS = /[,\[\]\{\}]/;
var PATTERN_TAG_HANDLE = /^(?:!|!!|![a-z\-]+!)$/i;
var PATTERN_TAG_URI = /^(?:!|[^,\[\]\{\}])(?:%[0-9a-f]{2}|[0-9a-z\-#;\/\?:@&=\+\$,_\.!~\*'\(\)\[\]])*$/i;
function _class(obj) {
  return Object.prototype.toString.call(obj);
}
function is_EOL(c) {
  return c === 10 || c === 13;
}
function is_WHITE_SPACE(c) {
  return c === 9 || c === 32;
}
function is_WS_OR_EOL(c) {
  return c === 9 || c === 32 || c === 10 || c === 13;
}
function is_FLOW_INDICATOR(c) {
  return c === 44 || c === 91 || c === 93 || c === 123 || c === 125;
}
function fromHexCode(c) {
  var lc;
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  lc = c | 32;
  if (97 <= lc && lc <= 102) {
    return lc - 97 + 10;
  }
  return -1;
}
function escapedHexLen(c) {
  if (c === 120) {
    return 2;
  }
  if (c === 117) {
    return 4;
  }
  if (c === 85) {
    return 8;
  }
  return 0;
}
function fromDecimalCode(c) {
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  return -1;
}
function simpleEscapeSequence(c) {
  return c === 48 ? "\0" : c === 97 ? "\x07" : c === 98 ? "\b" : c === 116 ? "	" : c === 9 ? "	" : c === 110 ? "\n" : c === 118 ? "\v" : c === 102 ? "\f" : c === 114 ? "\r" : c === 101 ? "\x1B" : c === 32 ? " " : c === 34 ? '"' : c === 47 ? "/" : c === 92 ? "\\" : c === 78 ? "\x85" : c === 95 ? "\xA0" : c === 76 ? "\u2028" : c === 80 ? "\u2029" : "";
}
function charFromCodepoint(c) {
  if (c <= 65535) {
    return String.fromCharCode(c);
  }
  return String.fromCharCode(
    (c - 65536 >> 10) + 55296,
    (c - 65536 & 1023) + 56320
  );
}
var simpleEscapeCheck = new Array(256);
var simpleEscapeMap = new Array(256);
for (i = 0; i < 256; i++) {
  simpleEscapeCheck[i] = simpleEscapeSequence(i) ? 1 : 0;
  simpleEscapeMap[i] = simpleEscapeSequence(i);
}
var i;
function State$1(input, options) {
  this.input = input;
  this.filename = options["filename"] || null;
  this.schema = options["schema"] || _default;
  this.onWarning = options["onWarning"] || null;
  this.legacy = options["legacy"] || false;
  this.json = options["json"] || false;
  this.listener = options["listener"] || null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.typeMap = this.schema.compiledTypeMap;
  this.length = input.length;
  this.position = 0;
  this.line = 0;
  this.lineStart = 0;
  this.lineIndent = 0;
  this.firstTabInLine = -1;
  this.documents = [];
}
function generateError(state, message) {
  var mark = {
    name: state.filename,
    buffer: state.input.slice(0, -1),
    // omit trailing \0
    position: state.position,
    line: state.line,
    column: state.position - state.lineStart
  };
  mark.snippet = snippet(mark);
  return new exception(message, mark);
}
function throwError(state, message) {
  throw generateError(state, message);
}
function throwWarning(state, message) {
  if (state.onWarning) {
    state.onWarning.call(null, generateError(state, message));
  }
}
var directiveHandlers = {
  YAML: function handleYamlDirective(state, name, args) {
    var match, major, minor;
    if (state.version !== null) {
      throwError(state, "duplication of %YAML directive");
    }
    if (args.length !== 1) {
      throwError(state, "YAML directive accepts exactly one argument");
    }
    match = /^([0-9]+)\.([0-9]+)$/.exec(args[0]);
    if (match === null) {
      throwError(state, "ill-formed argument of the YAML directive");
    }
    major = parseInt(match[1], 10);
    minor = parseInt(match[2], 10);
    if (major !== 1) {
      throwError(state, "unacceptable YAML version of the document");
    }
    state.version = args[0];
    state.checkLineBreaks = minor < 2;
    if (minor !== 1 && minor !== 2) {
      throwWarning(state, "unsupported YAML version of the document");
    }
  },
  TAG: function handleTagDirective(state, name, args) {
    var handle, prefix;
    if (args.length !== 2) {
      throwError(state, "TAG directive accepts exactly two arguments");
    }
    handle = args[0];
    prefix = args[1];
    if (!PATTERN_TAG_HANDLE.test(handle)) {
      throwError(state, "ill-formed tag handle (first argument) of the TAG directive");
    }
    if (_hasOwnProperty$1.call(state.tagMap, handle)) {
      throwError(state, 'there is a previously declared suffix for "' + handle + '" tag handle');
    }
    if (!PATTERN_TAG_URI.test(prefix)) {
      throwError(state, "ill-formed tag prefix (second argument) of the TAG directive");
    }
    try {
      prefix = decodeURIComponent(prefix);
    } catch (err) {
      throwError(state, "tag prefix is malformed: " + prefix);
    }
    state.tagMap[handle] = prefix;
  }
};
function captureSegment(state, start, end, checkJson) {
  var _position, _length, _character, _result;
  if (start < end) {
    _result = state.input.slice(start, end);
    if (checkJson) {
      for (_position = 0, _length = _result.length; _position < _length; _position += 1) {
        _character = _result.charCodeAt(_position);
        if (!(_character === 9 || 32 <= _character && _character <= 1114111)) {
          throwError(state, "expected valid JSON character");
        }
      }
    } else if (PATTERN_NON_PRINTABLE.test(_result)) {
      throwError(state, "the stream contains non-printable characters");
    }
    state.result += _result;
  }
}
function mergeMappings(state, destination, source, overridableKeys) {
  var sourceKeys, key, index, quantity;
  if (!common.isObject(source)) {
    throwError(state, "cannot merge mappings; the provided source object is unacceptable");
  }
  sourceKeys = Object.keys(source);
  for (index = 0, quantity = sourceKeys.length; index < quantity; index += 1) {
    key = sourceKeys[index];
    if (!_hasOwnProperty$1.call(destination, key)) {
      destination[key] = source[key];
      overridableKeys[key] = true;
    }
  }
}
function storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, startLine, startLineStart, startPos) {
  var index, quantity;
  if (Array.isArray(keyNode)) {
    keyNode = Array.prototype.slice.call(keyNode);
    for (index = 0, quantity = keyNode.length; index < quantity; index += 1) {
      if (Array.isArray(keyNode[index])) {
        throwError(state, "nested arrays are not supported inside keys");
      }
      if (typeof keyNode === "object" && _class(keyNode[index]) === "[object Object]") {
        keyNode[index] = "[object Object]";
      }
    }
  }
  if (typeof keyNode === "object" && _class(keyNode) === "[object Object]") {
    keyNode = "[object Object]";
  }
  keyNode = String(keyNode);
  if (_result === null) {
    _result = {};
  }
  if (keyTag === "tag:yaml.org,2002:merge") {
    if (Array.isArray(valueNode)) {
      for (index = 0, quantity = valueNode.length; index < quantity; index += 1) {
        mergeMappings(state, _result, valueNode[index], overridableKeys);
      }
    } else {
      mergeMappings(state, _result, valueNode, overridableKeys);
    }
  } else {
    if (!state.json && !_hasOwnProperty$1.call(overridableKeys, keyNode) && _hasOwnProperty$1.call(_result, keyNode)) {
      state.line = startLine || state.line;
      state.lineStart = startLineStart || state.lineStart;
      state.position = startPos || state.position;
      throwError(state, "duplicated mapping key");
    }
    if (keyNode === "__proto__") {
      Object.defineProperty(_result, keyNode, {
        configurable: true,
        enumerable: true,
        writable: true,
        value: valueNode
      });
    } else {
      _result[keyNode] = valueNode;
    }
    delete overridableKeys[keyNode];
  }
  return _result;
}
function readLineBreak(state) {
  var ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 10) {
    state.position++;
  } else if (ch === 13) {
    state.position++;
    if (state.input.charCodeAt(state.position) === 10) {
      state.position++;
    }
  } else {
    throwError(state, "a line break is expected");
  }
  state.line += 1;
  state.lineStart = state.position;
  state.firstTabInLine = -1;
}
function skipSeparationSpace(state, allowComments, checkIndent) {
  var lineBreaks = 0, ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    while (is_WHITE_SPACE(ch)) {
      if (ch === 9 && state.firstTabInLine === -1) {
        state.firstTabInLine = state.position;
      }
      ch = state.input.charCodeAt(++state.position);
    }
    if (allowComments && ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (ch !== 10 && ch !== 13 && ch !== 0);
    }
    if (is_EOL(ch)) {
      readLineBreak(state);
      ch = state.input.charCodeAt(state.position);
      lineBreaks++;
      state.lineIndent = 0;
      while (ch === 32) {
        state.lineIndent++;
        ch = state.input.charCodeAt(++state.position);
      }
    } else {
      break;
    }
  }
  if (checkIndent !== -1 && lineBreaks !== 0 && state.lineIndent < checkIndent) {
    throwWarning(state, "deficient indentation");
  }
  return lineBreaks;
}
function testDocumentSeparator(state) {
  var _position = state.position, ch;
  ch = state.input.charCodeAt(_position);
  if ((ch === 45 || ch === 46) && ch === state.input.charCodeAt(_position + 1) && ch === state.input.charCodeAt(_position + 2)) {
    _position += 3;
    ch = state.input.charCodeAt(_position);
    if (ch === 0 || is_WS_OR_EOL(ch)) {
      return true;
    }
  }
  return false;
}
function writeFoldedLines(state, count) {
  if (count === 1) {
    state.result += " ";
  } else if (count > 1) {
    state.result += common.repeat("\n", count - 1);
  }
}
function readPlainScalar(state, nodeIndent, withinFlowCollection) {
  var preceding, following, captureStart, captureEnd, hasPendingContent, _line, _lineStart, _lineIndent, _kind = state.kind, _result = state.result, ch;
  ch = state.input.charCodeAt(state.position);
  if (is_WS_OR_EOL(ch) || is_FLOW_INDICATOR(ch) || ch === 35 || ch === 38 || ch === 42 || ch === 33 || ch === 124 || ch === 62 || ch === 39 || ch === 34 || ch === 37 || ch === 64 || ch === 96) {
    return false;
  }
  if (ch === 63 || ch === 45) {
    following = state.input.charCodeAt(state.position + 1);
    if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
      return false;
    }
  }
  state.kind = "scalar";
  state.result = "";
  captureStart = captureEnd = state.position;
  hasPendingContent = false;
  while (ch !== 0) {
    if (ch === 58) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
        break;
      }
    } else if (ch === 35) {
      preceding = state.input.charCodeAt(state.position - 1);
      if (is_WS_OR_EOL(preceding)) {
        break;
      }
    } else if (state.position === state.lineStart && testDocumentSeparator(state) || withinFlowCollection && is_FLOW_INDICATOR(ch)) {
      break;
    } else if (is_EOL(ch)) {
      _line = state.line;
      _lineStart = state.lineStart;
      _lineIndent = state.lineIndent;
      skipSeparationSpace(state, false, -1);
      if (state.lineIndent >= nodeIndent) {
        hasPendingContent = true;
        ch = state.input.charCodeAt(state.position);
        continue;
      } else {
        state.position = captureEnd;
        state.line = _line;
        state.lineStart = _lineStart;
        state.lineIndent = _lineIndent;
        break;
      }
    }
    if (hasPendingContent) {
      captureSegment(state, captureStart, captureEnd, false);
      writeFoldedLines(state, state.line - _line);
      captureStart = captureEnd = state.position;
      hasPendingContent = false;
    }
    if (!is_WHITE_SPACE(ch)) {
      captureEnd = state.position + 1;
    }
    ch = state.input.charCodeAt(++state.position);
  }
  captureSegment(state, captureStart, captureEnd, false);
  if (state.result) {
    return true;
  }
  state.kind = _kind;
  state.result = _result;
  return false;
}
function readSingleQuotedScalar(state, nodeIndent) {
  var ch, captureStart, captureEnd;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 39) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 39) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (ch === 39) {
        captureStart = state.position;
        state.position++;
        captureEnd = state.position;
      } else {
        return true;
      }
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a single quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a single quoted scalar");
}
function readDoubleQuotedScalar(state, nodeIndent) {
  var captureStart, captureEnd, hexLength, hexResult, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 34) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 34) {
      captureSegment(state, captureStart, state.position, true);
      state.position++;
      return true;
    } else if (ch === 92) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (is_EOL(ch)) {
        skipSeparationSpace(state, false, nodeIndent);
      } else if (ch < 256 && simpleEscapeCheck[ch]) {
        state.result += simpleEscapeMap[ch];
        state.position++;
      } else if ((tmp = escapedHexLen(ch)) > 0) {
        hexLength = tmp;
        hexResult = 0;
        for (; hexLength > 0; hexLength--) {
          ch = state.input.charCodeAt(++state.position);
          if ((tmp = fromHexCode(ch)) >= 0) {
            hexResult = (hexResult << 4) + tmp;
          } else {
            throwError(state, "expected hexadecimal character");
          }
        }
        state.result += charFromCodepoint(hexResult);
        state.position++;
      } else {
        throwError(state, "unknown escape sequence");
      }
      captureStart = captureEnd = state.position;
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a double quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a double quoted scalar");
}
function readFlowCollection(state, nodeIndent) {
  var readNext = true, _line, _lineStart, _pos, _tag = state.tag, _result, _anchor = state.anchor, following, terminator, isPair, isExplicitPair, isMapping, overridableKeys = /* @__PURE__ */ Object.create(null), keyNode, keyTag, valueNode, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 91) {
    terminator = 93;
    isMapping = false;
    _result = [];
  } else if (ch === 123) {
    terminator = 125;
    isMapping = true;
    _result = {};
  } else {
    return false;
  }
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(++state.position);
  while (ch !== 0) {
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === terminator) {
      state.position++;
      state.tag = _tag;
      state.anchor = _anchor;
      state.kind = isMapping ? "mapping" : "sequence";
      state.result = _result;
      return true;
    } else if (!readNext) {
      throwError(state, "missed comma between flow collection entries");
    } else if (ch === 44) {
      throwError(state, "expected the node content, but found ','");
    }
    keyTag = keyNode = valueNode = null;
    isPair = isExplicitPair = false;
    if (ch === 63) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following)) {
        isPair = isExplicitPair = true;
        state.position++;
        skipSeparationSpace(state, true, nodeIndent);
      }
    }
    _line = state.line;
    _lineStart = state.lineStart;
    _pos = state.position;
    composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
    keyTag = state.tag;
    keyNode = state.result;
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if ((isExplicitPair || state.line === _line) && ch === 58) {
      isPair = true;
      ch = state.input.charCodeAt(++state.position);
      skipSeparationSpace(state, true, nodeIndent);
      composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
      valueNode = state.result;
    }
    if (isMapping) {
      storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos);
    } else if (isPair) {
      _result.push(storeMappingPair(state, null, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos));
    } else {
      _result.push(keyNode);
    }
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === 44) {
      readNext = true;
      ch = state.input.charCodeAt(++state.position);
    } else {
      readNext = false;
    }
  }
  throwError(state, "unexpected end of the stream within a flow collection");
}
function readBlockScalar(state, nodeIndent) {
  var captureStart, folding, chomping = CHOMPING_CLIP, didReadContent = false, detectedIndent = false, textIndent = nodeIndent, emptyLines = 0, atMoreIndented = false, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 124) {
    folding = false;
  } else if (ch === 62) {
    folding = true;
  } else {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  while (ch !== 0) {
    ch = state.input.charCodeAt(++state.position);
    if (ch === 43 || ch === 45) {
      if (CHOMPING_CLIP === chomping) {
        chomping = ch === 43 ? CHOMPING_KEEP : CHOMPING_STRIP;
      } else {
        throwError(state, "repeat of a chomping mode identifier");
      }
    } else if ((tmp = fromDecimalCode(ch)) >= 0) {
      if (tmp === 0) {
        throwError(state, "bad explicit indentation width of a block scalar; it cannot be less than one");
      } else if (!detectedIndent) {
        textIndent = nodeIndent + tmp - 1;
        detectedIndent = true;
      } else {
        throwError(state, "repeat of an indentation width identifier");
      }
    } else {
      break;
    }
  }
  if (is_WHITE_SPACE(ch)) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (is_WHITE_SPACE(ch));
    if (ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (!is_EOL(ch) && ch !== 0);
    }
  }
  while (ch !== 0) {
    readLineBreak(state);
    state.lineIndent = 0;
    ch = state.input.charCodeAt(state.position);
    while ((!detectedIndent || state.lineIndent < textIndent) && ch === 32) {
      state.lineIndent++;
      ch = state.input.charCodeAt(++state.position);
    }
    if (!detectedIndent && state.lineIndent > textIndent) {
      textIndent = state.lineIndent;
    }
    if (is_EOL(ch)) {
      emptyLines++;
      continue;
    }
    if (state.lineIndent < textIndent) {
      if (chomping === CHOMPING_KEEP) {
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (chomping === CHOMPING_CLIP) {
        if (didReadContent) {
          state.result += "\n";
        }
      }
      break;
    }
    if (folding) {
      if (is_WHITE_SPACE(ch)) {
        atMoreIndented = true;
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (atMoreIndented) {
        atMoreIndented = false;
        state.result += common.repeat("\n", emptyLines + 1);
      } else if (emptyLines === 0) {
        if (didReadContent) {
          state.result += " ";
        }
      } else {
        state.result += common.repeat("\n", emptyLines);
      }
    } else {
      state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
    }
    didReadContent = true;
    detectedIndent = true;
    emptyLines = 0;
    captureStart = state.position;
    while (!is_EOL(ch) && ch !== 0) {
      ch = state.input.charCodeAt(++state.position);
    }
    captureSegment(state, captureStart, state.position, false);
  }
  return true;
}
function readBlockSequence(state, nodeIndent) {
  var _line, _tag = state.tag, _anchor = state.anchor, _result = [], following, detected = false, ch;
  if (state.firstTabInLine !== -1)
    return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    if (ch !== 45) {
      break;
    }
    following = state.input.charCodeAt(state.position + 1);
    if (!is_WS_OR_EOL(following)) {
      break;
    }
    detected = true;
    state.position++;
    if (skipSeparationSpace(state, true, -1)) {
      if (state.lineIndent <= nodeIndent) {
        _result.push(null);
        ch = state.input.charCodeAt(state.position);
        continue;
      }
    }
    _line = state.line;
    composeNode(state, nodeIndent, CONTEXT_BLOCK_IN, false, true);
    _result.push(state.result);
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a sequence entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "sequence";
    state.result = _result;
    return true;
  }
  return false;
}
function readBlockMapping(state, nodeIndent, flowIndent) {
  var following, allowCompact, _line, _keyLine, _keyLineStart, _keyPos, _tag = state.tag, _anchor = state.anchor, _result = {}, overridableKeys = /* @__PURE__ */ Object.create(null), keyTag = null, keyNode = null, valueNode = null, atExplicitKey = false, detected = false, ch;
  if (state.firstTabInLine !== -1)
    return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (!atExplicitKey && state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    following = state.input.charCodeAt(state.position + 1);
    _line = state.line;
    if ((ch === 63 || ch === 58) && is_WS_OR_EOL(following)) {
      if (ch === 63) {
        if (atExplicitKey) {
          storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
          keyTag = keyNode = valueNode = null;
        }
        detected = true;
        atExplicitKey = true;
        allowCompact = true;
      } else if (atExplicitKey) {
        atExplicitKey = false;
        allowCompact = true;
      } else {
        throwError(state, "incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line");
      }
      state.position += 1;
      ch = following;
    } else {
      _keyLine = state.line;
      _keyLineStart = state.lineStart;
      _keyPos = state.position;
      if (!composeNode(state, flowIndent, CONTEXT_FLOW_OUT, false, true)) {
        break;
      }
      if (state.line === _line) {
        ch = state.input.charCodeAt(state.position);
        while (is_WHITE_SPACE(ch)) {
          ch = state.input.charCodeAt(++state.position);
        }
        if (ch === 58) {
          ch = state.input.charCodeAt(++state.position);
          if (!is_WS_OR_EOL(ch)) {
            throwError(state, "a whitespace character is expected after the key-value separator within a block mapping");
          }
          if (atExplicitKey) {
            storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
            keyTag = keyNode = valueNode = null;
          }
          detected = true;
          atExplicitKey = false;
          allowCompact = false;
          keyTag = state.tag;
          keyNode = state.result;
        } else if (detected) {
          throwError(state, "can not read an implicit mapping pair; a colon is missed");
        } else {
          state.tag = _tag;
          state.anchor = _anchor;
          return true;
        }
      } else if (detected) {
        throwError(state, "can not read a block mapping entry; a multiline key may not be an implicit key");
      } else {
        state.tag = _tag;
        state.anchor = _anchor;
        return true;
      }
    }
    if (state.line === _line || state.lineIndent > nodeIndent) {
      if (atExplicitKey) {
        _keyLine = state.line;
        _keyLineStart = state.lineStart;
        _keyPos = state.position;
      }
      if (composeNode(state, nodeIndent, CONTEXT_BLOCK_OUT, true, allowCompact)) {
        if (atExplicitKey) {
          keyNode = state.result;
        } else {
          valueNode = state.result;
        }
      }
      if (!atExplicitKey) {
        storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _keyLine, _keyLineStart, _keyPos);
        keyTag = keyNode = valueNode = null;
      }
      skipSeparationSpace(state, true, -1);
      ch = state.input.charCodeAt(state.position);
    }
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a mapping entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (atExplicitKey) {
    storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "mapping";
    state.result = _result;
  }
  return detected;
}
function readTagProperty(state) {
  var _position, isVerbatim = false, isNamed = false, tagHandle, tagName, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 33)
    return false;
  if (state.tag !== null) {
    throwError(state, "duplication of a tag property");
  }
  ch = state.input.charCodeAt(++state.position);
  if (ch === 60) {
    isVerbatim = true;
    ch = state.input.charCodeAt(++state.position);
  } else if (ch === 33) {
    isNamed = true;
    tagHandle = "!!";
    ch = state.input.charCodeAt(++state.position);
  } else {
    tagHandle = "!";
  }
  _position = state.position;
  if (isVerbatim) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (ch !== 0 && ch !== 62);
    if (state.position < state.length) {
      tagName = state.input.slice(_position, state.position);
      ch = state.input.charCodeAt(++state.position);
    } else {
      throwError(state, "unexpected end of the stream within a verbatim tag");
    }
  } else {
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      if (ch === 33) {
        if (!isNamed) {
          tagHandle = state.input.slice(_position - 1, state.position + 1);
          if (!PATTERN_TAG_HANDLE.test(tagHandle)) {
            throwError(state, "named tag handle cannot contain such characters");
          }
          isNamed = true;
          _position = state.position + 1;
        } else {
          throwError(state, "tag suffix cannot contain exclamation marks");
        }
      }
      ch = state.input.charCodeAt(++state.position);
    }
    tagName = state.input.slice(_position, state.position);
    if (PATTERN_FLOW_INDICATORS.test(tagName)) {
      throwError(state, "tag suffix cannot contain flow indicator characters");
    }
  }
  if (tagName && !PATTERN_TAG_URI.test(tagName)) {
    throwError(state, "tag name cannot contain such characters: " + tagName);
  }
  try {
    tagName = decodeURIComponent(tagName);
  } catch (err) {
    throwError(state, "tag name is malformed: " + tagName);
  }
  if (isVerbatim) {
    state.tag = tagName;
  } else if (_hasOwnProperty$1.call(state.tagMap, tagHandle)) {
    state.tag = state.tagMap[tagHandle] + tagName;
  } else if (tagHandle === "!") {
    state.tag = "!" + tagName;
  } else if (tagHandle === "!!") {
    state.tag = "tag:yaml.org,2002:" + tagName;
  } else {
    throwError(state, 'undeclared tag handle "' + tagHandle + '"');
  }
  return true;
}
function readAnchorProperty(state) {
  var _position, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 38)
    return false;
  if (state.anchor !== null) {
    throwError(state, "duplication of an anchor property");
  }
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an anchor node must contain at least one character");
  }
  state.anchor = state.input.slice(_position, state.position);
  return true;
}
function readAlias(state) {
  var _position, alias, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 42)
    return false;
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an alias node must contain at least one character");
  }
  alias = state.input.slice(_position, state.position);
  if (!_hasOwnProperty$1.call(state.anchorMap, alias)) {
    throwError(state, 'unidentified alias "' + alias + '"');
  }
  state.result = state.anchorMap[alias];
  skipSeparationSpace(state, true, -1);
  return true;
}
function composeNode(state, parentIndent, nodeContext, allowToSeek, allowCompact) {
  var allowBlockStyles, allowBlockScalars, allowBlockCollections, indentStatus = 1, atNewLine = false, hasContent = false, typeIndex, typeQuantity, typeList, type2, flowIndent, blockIndent;
  if (state.listener !== null) {
    state.listener("open", state);
  }
  state.tag = null;
  state.anchor = null;
  state.kind = null;
  state.result = null;
  allowBlockStyles = allowBlockScalars = allowBlockCollections = CONTEXT_BLOCK_OUT === nodeContext || CONTEXT_BLOCK_IN === nodeContext;
  if (allowToSeek) {
    if (skipSeparationSpace(state, true, -1)) {
      atNewLine = true;
      if (state.lineIndent > parentIndent) {
        indentStatus = 1;
      } else if (state.lineIndent === parentIndent) {
        indentStatus = 0;
      } else if (state.lineIndent < parentIndent) {
        indentStatus = -1;
      }
    }
  }
  if (indentStatus === 1) {
    while (readTagProperty(state) || readAnchorProperty(state)) {
      if (skipSeparationSpace(state, true, -1)) {
        atNewLine = true;
        allowBlockCollections = allowBlockStyles;
        if (state.lineIndent > parentIndent) {
          indentStatus = 1;
        } else if (state.lineIndent === parentIndent) {
          indentStatus = 0;
        } else if (state.lineIndent < parentIndent) {
          indentStatus = -1;
        }
      } else {
        allowBlockCollections = false;
      }
    }
  }
  if (allowBlockCollections) {
    allowBlockCollections = atNewLine || allowCompact;
  }
  if (indentStatus === 1 || CONTEXT_BLOCK_OUT === nodeContext) {
    if (CONTEXT_FLOW_IN === nodeContext || CONTEXT_FLOW_OUT === nodeContext) {
      flowIndent = parentIndent;
    } else {
      flowIndent = parentIndent + 1;
    }
    blockIndent = state.position - state.lineStart;
    if (indentStatus === 1) {
      if (allowBlockCollections && (readBlockSequence(state, blockIndent) || readBlockMapping(state, blockIndent, flowIndent)) || readFlowCollection(state, flowIndent)) {
        hasContent = true;
      } else {
        if (allowBlockScalars && readBlockScalar(state, flowIndent) || readSingleQuotedScalar(state, flowIndent) || readDoubleQuotedScalar(state, flowIndent)) {
          hasContent = true;
        } else if (readAlias(state)) {
          hasContent = true;
          if (state.tag !== null || state.anchor !== null) {
            throwError(state, "alias node should not have any properties");
          }
        } else if (readPlainScalar(state, flowIndent, CONTEXT_FLOW_IN === nodeContext)) {
          hasContent = true;
          if (state.tag === null) {
            state.tag = "?";
          }
        }
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
      }
    } else if (indentStatus === 0) {
      hasContent = allowBlockCollections && readBlockSequence(state, blockIndent);
    }
  }
  if (state.tag === null) {
    if (state.anchor !== null) {
      state.anchorMap[state.anchor] = state.result;
    }
  } else if (state.tag === "?") {
    if (state.result !== null && state.kind !== "scalar") {
      throwError(state, 'unacceptable node kind for !<?> tag; it should be "scalar", not "' + state.kind + '"');
    }
    for (typeIndex = 0, typeQuantity = state.implicitTypes.length; typeIndex < typeQuantity; typeIndex += 1) {
      type2 = state.implicitTypes[typeIndex];
      if (type2.resolve(state.result)) {
        state.result = type2.construct(state.result);
        state.tag = type2.tag;
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
        break;
      }
    }
  } else if (state.tag !== "!") {
    if (_hasOwnProperty$1.call(state.typeMap[state.kind || "fallback"], state.tag)) {
      type2 = state.typeMap[state.kind || "fallback"][state.tag];
    } else {
      type2 = null;
      typeList = state.typeMap.multi[state.kind || "fallback"];
      for (typeIndex = 0, typeQuantity = typeList.length; typeIndex < typeQuantity; typeIndex += 1) {
        if (state.tag.slice(0, typeList[typeIndex].tag.length) === typeList[typeIndex].tag) {
          type2 = typeList[typeIndex];
          break;
        }
      }
    }
    if (!type2) {
      throwError(state, "unknown tag !<" + state.tag + ">");
    }
    if (state.result !== null && type2.kind !== state.kind) {
      throwError(state, "unacceptable node kind for !<" + state.tag + '> tag; it should be "' + type2.kind + '", not "' + state.kind + '"');
    }
    if (!type2.resolve(state.result, state.tag)) {
      throwError(state, "cannot resolve a node with !<" + state.tag + "> explicit tag");
    } else {
      state.result = type2.construct(state.result, state.tag);
      if (state.anchor !== null) {
        state.anchorMap[state.anchor] = state.result;
      }
    }
  }
  if (state.listener !== null) {
    state.listener("close", state);
  }
  return state.tag !== null || state.anchor !== null || hasContent;
}
function readDocument(state) {
  var documentStart = state.position, _position, directiveName, directiveArgs, hasDirectives = false, ch;
  state.version = null;
  state.checkLineBreaks = state.legacy;
  state.tagMap = /* @__PURE__ */ Object.create(null);
  state.anchorMap = /* @__PURE__ */ Object.create(null);
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if (state.lineIndent > 0 || ch !== 37) {
      break;
    }
    hasDirectives = true;
    ch = state.input.charCodeAt(++state.position);
    _position = state.position;
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      ch = state.input.charCodeAt(++state.position);
    }
    directiveName = state.input.slice(_position, state.position);
    directiveArgs = [];
    if (directiveName.length < 1) {
      throwError(state, "directive name must not be less than one character in length");
    }
    while (ch !== 0) {
      while (is_WHITE_SPACE(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      if (ch === 35) {
        do {
          ch = state.input.charCodeAt(++state.position);
        } while (ch !== 0 && !is_EOL(ch));
        break;
      }
      if (is_EOL(ch))
        break;
      _position = state.position;
      while (ch !== 0 && !is_WS_OR_EOL(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      directiveArgs.push(state.input.slice(_position, state.position));
    }
    if (ch !== 0)
      readLineBreak(state);
    if (_hasOwnProperty$1.call(directiveHandlers, directiveName)) {
      directiveHandlers[directiveName](state, directiveName, directiveArgs);
    } else {
      throwWarning(state, 'unknown document directive "' + directiveName + '"');
    }
  }
  skipSeparationSpace(state, true, -1);
  if (state.lineIndent === 0 && state.input.charCodeAt(state.position) === 45 && state.input.charCodeAt(state.position + 1) === 45 && state.input.charCodeAt(state.position + 2) === 45) {
    state.position += 3;
    skipSeparationSpace(state, true, -1);
  } else if (hasDirectives) {
    throwError(state, "directives end mark is expected");
  }
  composeNode(state, state.lineIndent - 1, CONTEXT_BLOCK_OUT, false, true);
  skipSeparationSpace(state, true, -1);
  if (state.checkLineBreaks && PATTERN_NON_ASCII_LINE_BREAKS.test(state.input.slice(documentStart, state.position))) {
    throwWarning(state, "non-ASCII line breaks are interpreted as content");
  }
  state.documents.push(state.result);
  if (state.position === state.lineStart && testDocumentSeparator(state)) {
    if (state.input.charCodeAt(state.position) === 46) {
      state.position += 3;
      skipSeparationSpace(state, true, -1);
    }
    return;
  }
  if (state.position < state.length - 1) {
    throwError(state, "end of the stream or a document separator is expected");
  } else {
    return;
  }
}
function loadDocuments(input, options) {
  input = String(input);
  options = options || {};
  if (input.length !== 0) {
    if (input.charCodeAt(input.length - 1) !== 10 && input.charCodeAt(input.length - 1) !== 13) {
      input += "\n";
    }
    if (input.charCodeAt(0) === 65279) {
      input = input.slice(1);
    }
  }
  var state = new State$1(input, options);
  var nullpos = input.indexOf("\0");
  if (nullpos !== -1) {
    state.position = nullpos;
    throwError(state, "null byte is not allowed in input");
  }
  state.input += "\0";
  while (state.input.charCodeAt(state.position) === 32) {
    state.lineIndent += 1;
    state.position += 1;
  }
  while (state.position < state.length - 1) {
    readDocument(state);
  }
  return state.documents;
}
function loadAll$1(input, iterator, options) {
  if (iterator !== null && typeof iterator === "object" && typeof options === "undefined") {
    options = iterator;
    iterator = null;
  }
  var documents = loadDocuments(input, options);
  if (typeof iterator !== "function") {
    return documents;
  }
  for (var index = 0, length = documents.length; index < length; index += 1) {
    iterator(documents[index]);
  }
}
function load$1(input, options) {
  var documents = loadDocuments(input, options);
  if (documents.length === 0) {
    return void 0;
  } else if (documents.length === 1) {
    return documents[0];
  }
  throw new exception("expected a single document in the stream, but found more");
}
var loadAll_1 = loadAll$1;
var load_1 = load$1;
var loader = {
  loadAll: loadAll_1,
  load: load_1
};
var _toString = Object.prototype.toString;
var _hasOwnProperty = Object.prototype.hasOwnProperty;
var CHAR_BOM = 65279;
var CHAR_TAB = 9;
var CHAR_LINE_FEED = 10;
var CHAR_CARRIAGE_RETURN = 13;
var CHAR_SPACE = 32;
var CHAR_EXCLAMATION = 33;
var CHAR_DOUBLE_QUOTE = 34;
var CHAR_SHARP = 35;
var CHAR_PERCENT = 37;
var CHAR_AMPERSAND = 38;
var CHAR_SINGLE_QUOTE = 39;
var CHAR_ASTERISK = 42;
var CHAR_COMMA = 44;
var CHAR_MINUS = 45;
var CHAR_COLON = 58;
var CHAR_EQUALS = 61;
var CHAR_GREATER_THAN = 62;
var CHAR_QUESTION = 63;
var CHAR_COMMERCIAL_AT = 64;
var CHAR_LEFT_SQUARE_BRACKET = 91;
var CHAR_RIGHT_SQUARE_BRACKET = 93;
var CHAR_GRAVE_ACCENT = 96;
var CHAR_LEFT_CURLY_BRACKET = 123;
var CHAR_VERTICAL_LINE = 124;
var CHAR_RIGHT_CURLY_BRACKET = 125;
var ESCAPE_SEQUENCES = {};
ESCAPE_SEQUENCES[0] = "\\0";
ESCAPE_SEQUENCES[7] = "\\a";
ESCAPE_SEQUENCES[8] = "\\b";
ESCAPE_SEQUENCES[9] = "\\t";
ESCAPE_SEQUENCES[10] = "\\n";
ESCAPE_SEQUENCES[11] = "\\v";
ESCAPE_SEQUENCES[12] = "\\f";
ESCAPE_SEQUENCES[13] = "\\r";
ESCAPE_SEQUENCES[27] = "\\e";
ESCAPE_SEQUENCES[34] = '\\"';
ESCAPE_SEQUENCES[92] = "\\\\";
ESCAPE_SEQUENCES[133] = "\\N";
ESCAPE_SEQUENCES[160] = "\\_";
ESCAPE_SEQUENCES[8232] = "\\L";
ESCAPE_SEQUENCES[8233] = "\\P";
var DEPRECATED_BOOLEANS_SYNTAX = [
  "y",
  "Y",
  "yes",
  "Yes",
  "YES",
  "on",
  "On",
  "ON",
  "n",
  "N",
  "no",
  "No",
  "NO",
  "off",
  "Off",
  "OFF"
];
var DEPRECATED_BASE60_SYNTAX = /^[-+]?[0-9_]+(?::[0-9_]+)+(?:\.[0-9_]*)?$/;
function compileStyleMap(schema2, map2) {
  var result, keys, index, length, tag, style, type2;
  if (map2 === null)
    return {};
  result = {};
  keys = Object.keys(map2);
  for (index = 0, length = keys.length; index < length; index += 1) {
    tag = keys[index];
    style = String(map2[tag]);
    if (tag.slice(0, 2) === "!!") {
      tag = "tag:yaml.org,2002:" + tag.slice(2);
    }
    type2 = schema2.compiledTypeMap["fallback"][tag];
    if (type2 && _hasOwnProperty.call(type2.styleAliases, style)) {
      style = type2.styleAliases[style];
    }
    result[tag] = style;
  }
  return result;
}
function encodeHex(character) {
  var string, handle, length;
  string = character.toString(16).toUpperCase();
  if (character <= 255) {
    handle = "x";
    length = 2;
  } else if (character <= 65535) {
    handle = "u";
    length = 4;
  } else if (character <= 4294967295) {
    handle = "U";
    length = 8;
  } else {
    throw new exception("code point within a string may not be greater than 0xFFFFFFFF");
  }
  return "\\" + handle + common.repeat("0", length - string.length) + string;
}
var QUOTING_TYPE_SINGLE = 1;
var QUOTING_TYPE_DOUBLE = 2;
function State(options) {
  this.schema = options["schema"] || _default;
  this.indent = Math.max(1, options["indent"] || 2);
  this.noArrayIndent = options["noArrayIndent"] || false;
  this.skipInvalid = options["skipInvalid"] || false;
  this.flowLevel = common.isNothing(options["flowLevel"]) ? -1 : options["flowLevel"];
  this.styleMap = compileStyleMap(this.schema, options["styles"] || null);
  this.sortKeys = options["sortKeys"] || false;
  this.lineWidth = options["lineWidth"] || 80;
  this.noRefs = options["noRefs"] || false;
  this.noCompatMode = options["noCompatMode"] || false;
  this.condenseFlow = options["condenseFlow"] || false;
  this.quotingType = options["quotingType"] === '"' ? QUOTING_TYPE_DOUBLE : QUOTING_TYPE_SINGLE;
  this.forceQuotes = options["forceQuotes"] || false;
  this.replacer = typeof options["replacer"] === "function" ? options["replacer"] : null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.explicitTypes = this.schema.compiledExplicit;
  this.tag = null;
  this.result = "";
  this.duplicates = [];
  this.usedDuplicates = null;
}
function indentString(string, spaces) {
  var ind = common.repeat(" ", spaces), position = 0, next = -1, result = "", line, length = string.length;
  while (position < length) {
    next = string.indexOf("\n", position);
    if (next === -1) {
      line = string.slice(position);
      position = length;
    } else {
      line = string.slice(position, next + 1);
      position = next + 1;
    }
    if (line.length && line !== "\n")
      result += ind;
    result += line;
  }
  return result;
}
function generateNextLine(state, level) {
  return "\n" + common.repeat(" ", state.indent * level);
}
function testImplicitResolving(state, str2) {
  var index, length, type2;
  for (index = 0, length = state.implicitTypes.length; index < length; index += 1) {
    type2 = state.implicitTypes[index];
    if (type2.resolve(str2)) {
      return true;
    }
  }
  return false;
}
function isWhitespace(c) {
  return c === CHAR_SPACE || c === CHAR_TAB;
}
function isPrintable(c) {
  return 32 <= c && c <= 126 || 161 <= c && c <= 55295 && c !== 8232 && c !== 8233 || 57344 <= c && c <= 65533 && c !== CHAR_BOM || 65536 <= c && c <= 1114111;
}
function isNsCharOrWhitespace(c) {
  return isPrintable(c) && c !== CHAR_BOM && c !== CHAR_CARRIAGE_RETURN && c !== CHAR_LINE_FEED;
}
function isPlainSafe(c, prev, inblock) {
  var cIsNsCharOrWhitespace = isNsCharOrWhitespace(c);
  var cIsNsChar = cIsNsCharOrWhitespace && !isWhitespace(c);
  return (
    // ns-plain-safe
    (inblock ? (
      // c = flow-in
      cIsNsCharOrWhitespace
    ) : cIsNsCharOrWhitespace && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET) && c !== CHAR_SHARP && !(prev === CHAR_COLON && !cIsNsChar) || isNsCharOrWhitespace(prev) && !isWhitespace(prev) && c === CHAR_SHARP || prev === CHAR_COLON && cIsNsChar
  );
}
function isPlainSafeFirst(c) {
  return isPrintable(c) && c !== CHAR_BOM && !isWhitespace(c) && c !== CHAR_MINUS && c !== CHAR_QUESTION && c !== CHAR_COLON && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET && c !== CHAR_SHARP && c !== CHAR_AMPERSAND && c !== CHAR_ASTERISK && c !== CHAR_EXCLAMATION && c !== CHAR_VERTICAL_LINE && c !== CHAR_EQUALS && c !== CHAR_GREATER_THAN && c !== CHAR_SINGLE_QUOTE && c !== CHAR_DOUBLE_QUOTE && c !== CHAR_PERCENT && c !== CHAR_COMMERCIAL_AT && c !== CHAR_GRAVE_ACCENT;
}
function isPlainSafeLast(c) {
  return !isWhitespace(c) && c !== CHAR_COLON;
}
function codePointAt(string, pos) {
  var first = string.charCodeAt(pos), second;
  if (first >= 55296 && first <= 56319 && pos + 1 < string.length) {
    second = string.charCodeAt(pos + 1);
    if (second >= 56320 && second <= 57343) {
      return (first - 55296) * 1024 + second - 56320 + 65536;
    }
  }
  return first;
}
function needIndentIndicator(string) {
  var leadingSpaceRe = /^\n* /;
  return leadingSpaceRe.test(string);
}
var STYLE_PLAIN = 1;
var STYLE_SINGLE = 2;
var STYLE_LITERAL = 3;
var STYLE_FOLDED = 4;
var STYLE_DOUBLE = 5;
function chooseScalarStyle(string, singleLineOnly, indentPerLevel, lineWidth, testAmbiguousType, quotingType, forceQuotes, inblock) {
  var i;
  var char = 0;
  var prevChar = null;
  var hasLineBreak = false;
  var hasFoldableLine = false;
  var shouldTrackWidth = lineWidth !== -1;
  var previousLineBreak = -1;
  var plain = isPlainSafeFirst(codePointAt(string, 0)) && isPlainSafeLast(codePointAt(string, string.length - 1));
  if (singleLineOnly || forceQuotes) {
    for (i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
  } else {
    for (i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
      char = codePointAt(string, i);
      if (char === CHAR_LINE_FEED) {
        hasLineBreak = true;
        if (shouldTrackWidth) {
          hasFoldableLine = hasFoldableLine || // Foldable line = too long, and not more-indented.
          i - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ";
          previousLineBreak = i;
        }
      } else if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
    hasFoldableLine = hasFoldableLine || shouldTrackWidth && (i - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ");
  }
  if (!hasLineBreak && !hasFoldableLine) {
    if (plain && !forceQuotes && !testAmbiguousType(string)) {
      return STYLE_PLAIN;
    }
    return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
  }
  if (indentPerLevel > 9 && needIndentIndicator(string)) {
    return STYLE_DOUBLE;
  }
  if (!forceQuotes) {
    return hasFoldableLine ? STYLE_FOLDED : STYLE_LITERAL;
  }
  return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
}
function writeScalar(state, string, level, iskey, inblock) {
  state.dump = function() {
    if (string.length === 0) {
      return state.quotingType === QUOTING_TYPE_DOUBLE ? '""' : "''";
    }
    if (!state.noCompatMode) {
      if (DEPRECATED_BOOLEANS_SYNTAX.indexOf(string) !== -1 || DEPRECATED_BASE60_SYNTAX.test(string)) {
        return state.quotingType === QUOTING_TYPE_DOUBLE ? '"' + string + '"' : "'" + string + "'";
      }
    }
    var indent = state.indent * Math.max(1, level);
    var lineWidth = state.lineWidth === -1 ? -1 : Math.max(Math.min(state.lineWidth, 40), state.lineWidth - indent);
    var singleLineOnly = iskey || state.flowLevel > -1 && level >= state.flowLevel;
    function testAmbiguity(string2) {
      return testImplicitResolving(state, string2);
    }
    switch (chooseScalarStyle(
      string,
      singleLineOnly,
      state.indent,
      lineWidth,
      testAmbiguity,
      state.quotingType,
      state.forceQuotes && !iskey,
      inblock
    )) {
      case STYLE_PLAIN:
        return string;
      case STYLE_SINGLE:
        return "'" + string.replace(/'/g, "''") + "'";
      case STYLE_LITERAL:
        return "|" + blockHeader(string, state.indent) + dropEndingNewline(indentString(string, indent));
      case STYLE_FOLDED:
        return ">" + blockHeader(string, state.indent) + dropEndingNewline(indentString(foldString(string, lineWidth), indent));
      case STYLE_DOUBLE:
        return '"' + escapeString(string) + '"';
      default:
        throw new exception("impossible error: invalid scalar style");
    }
  }();
}
function blockHeader(string, indentPerLevel) {
  var indentIndicator = needIndentIndicator(string) ? String(indentPerLevel) : "";
  var clip = string[string.length - 1] === "\n";
  var keep = clip && (string[string.length - 2] === "\n" || string === "\n");
  var chomp = keep ? "+" : clip ? "" : "-";
  return indentIndicator + chomp + "\n";
}
function dropEndingNewline(string) {
  return string[string.length - 1] === "\n" ? string.slice(0, -1) : string;
}
function foldString(string, width) {
  var lineRe = /(\n+)([^\n]*)/g;
  var result = function() {
    var nextLF = string.indexOf("\n");
    nextLF = nextLF !== -1 ? nextLF : string.length;
    lineRe.lastIndex = nextLF;
    return foldLine(string.slice(0, nextLF), width);
  }();
  var prevMoreIndented = string[0] === "\n" || string[0] === " ";
  var moreIndented;
  var match;
  while (match = lineRe.exec(string)) {
    var prefix = match[1], line = match[2];
    moreIndented = line[0] === " ";
    result += prefix + (!prevMoreIndented && !moreIndented && line !== "" ? "\n" : "") + foldLine(line, width);
    prevMoreIndented = moreIndented;
  }
  return result;
}
function foldLine(line, width) {
  if (line === "" || line[0] === " ")
    return line;
  var breakRe = / [^ ]/g;
  var match;
  var start = 0, end, curr = 0, next = 0;
  var result = "";
  while (match = breakRe.exec(line)) {
    next = match.index;
    if (next - start > width) {
      end = curr > start ? curr : next;
      result += "\n" + line.slice(start, end);
      start = end + 1;
    }
    curr = next;
  }
  result += "\n";
  if (line.length - start > width && curr > start) {
    result += line.slice(start, curr) + "\n" + line.slice(curr + 1);
  } else {
    result += line.slice(start);
  }
  return result.slice(1);
}
function escapeString(string) {
  var result = "";
  var char = 0;
  var escapeSeq;
  for (var i = 0; i < string.length; char >= 65536 ? i += 2 : i++) {
    char = codePointAt(string, i);
    escapeSeq = ESCAPE_SEQUENCES[char];
    if (!escapeSeq && isPrintable(char)) {
      result += string[i];
      if (char >= 65536)
        result += string[i + 1];
    } else {
      result += escapeSeq || encodeHex(char);
    }
  }
  return result;
}
function writeFlowSequence(state, level, object) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level, value, false, false) || typeof value === "undefined" && writeNode(state, level, null, false, false)) {
      if (_result !== "")
        _result += "," + (!state.condenseFlow ? " " : "");
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = "[" + _result + "]";
}
function writeBlockSequence(state, level, object, compact) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level + 1, value, true, true, false, true) || typeof value === "undefined" && writeNode(state, level + 1, null, true, true, false, true)) {
      if (!compact || _result !== "") {
        _result += generateNextLine(state, level);
      }
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        _result += "-";
      } else {
        _result += "- ";
      }
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = _result || "[]";
}
function writeFlowMapping(state, level, object) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, pairBuffer;
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (_result !== "")
      pairBuffer += ", ";
    if (state.condenseFlow)
      pairBuffer += '"';
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level, objectKey, false, false)) {
      continue;
    }
    if (state.dump.length > 1024)
      pairBuffer += "? ";
    pairBuffer += state.dump + (state.condenseFlow ? '"' : "") + ":" + (state.condenseFlow ? "" : " ");
    if (!writeNode(state, level, objectValue, false, false)) {
      continue;
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = "{" + _result + "}";
}
function writeBlockMapping(state, level, object, compact) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, explicitPair, pairBuffer;
  if (state.sortKeys === true) {
    objectKeyList.sort();
  } else if (typeof state.sortKeys === "function") {
    objectKeyList.sort(state.sortKeys);
  } else if (state.sortKeys) {
    throw new exception("sortKeys must be a boolean or a function");
  }
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (!compact || _result !== "") {
      pairBuffer += generateNextLine(state, level);
    }
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level + 1, objectKey, true, true, true)) {
      continue;
    }
    explicitPair = state.tag !== null && state.tag !== "?" || state.dump && state.dump.length > 1024;
    if (explicitPair) {
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        pairBuffer += "?";
      } else {
        pairBuffer += "? ";
      }
    }
    pairBuffer += state.dump;
    if (explicitPair) {
      pairBuffer += generateNextLine(state, level);
    }
    if (!writeNode(state, level + 1, objectValue, true, explicitPair)) {
      continue;
    }
    if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
      pairBuffer += ":";
    } else {
      pairBuffer += ": ";
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = _result || "{}";
}
function detectType(state, object, explicit) {
  var _result, typeList, index, length, type2, style;
  typeList = explicit ? state.explicitTypes : state.implicitTypes;
  for (index = 0, length = typeList.length; index < length; index += 1) {
    type2 = typeList[index];
    if ((type2.instanceOf || type2.predicate) && (!type2.instanceOf || typeof object === "object" && object instanceof type2.instanceOf) && (!type2.predicate || type2.predicate(object))) {
      if (explicit) {
        if (type2.multi && type2.representName) {
          state.tag = type2.representName(object);
        } else {
          state.tag = type2.tag;
        }
      } else {
        state.tag = "?";
      }
      if (type2.represent) {
        style = state.styleMap[type2.tag] || type2.defaultStyle;
        if (_toString.call(type2.represent) === "[object Function]") {
          _result = type2.represent(object, style);
        } else if (_hasOwnProperty.call(type2.represent, style)) {
          _result = type2.represent[style](object, style);
        } else {
          throw new exception("!<" + type2.tag + '> tag resolver accepts not "' + style + '" style');
        }
        state.dump = _result;
      }
      return true;
    }
  }
  return false;
}
function writeNode(state, level, object, block, compact, iskey, isblockseq) {
  state.tag = null;
  state.dump = object;
  if (!detectType(state, object, false)) {
    detectType(state, object, true);
  }
  var type2 = _toString.call(state.dump);
  var inblock = block;
  var tagStr;
  if (block) {
    block = state.flowLevel < 0 || state.flowLevel > level;
  }
  var objectOrArray = type2 === "[object Object]" || type2 === "[object Array]", duplicateIndex, duplicate;
  if (objectOrArray) {
    duplicateIndex = state.duplicates.indexOf(object);
    duplicate = duplicateIndex !== -1;
  }
  if (state.tag !== null && state.tag !== "?" || duplicate || state.indent !== 2 && level > 0) {
    compact = false;
  }
  if (duplicate && state.usedDuplicates[duplicateIndex]) {
    state.dump = "*ref_" + duplicateIndex;
  } else {
    if (objectOrArray && duplicate && !state.usedDuplicates[duplicateIndex]) {
      state.usedDuplicates[duplicateIndex] = true;
    }
    if (type2 === "[object Object]") {
      if (block && Object.keys(state.dump).length !== 0) {
        writeBlockMapping(state, level, state.dump, compact);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowMapping(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object Array]") {
      if (block && state.dump.length !== 0) {
        if (state.noArrayIndent && !isblockseq && level > 0) {
          writeBlockSequence(state, level - 1, state.dump, compact);
        } else {
          writeBlockSequence(state, level, state.dump, compact);
        }
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowSequence(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object String]") {
      if (state.tag !== "?") {
        writeScalar(state, state.dump, level, iskey, inblock);
      }
    } else if (type2 === "[object Undefined]") {
      return false;
    } else {
      if (state.skipInvalid)
        return false;
      throw new exception("unacceptable kind of an object to dump " + type2);
    }
    if (state.tag !== null && state.tag !== "?") {
      tagStr = encodeURI(
        state.tag[0] === "!" ? state.tag.slice(1) : state.tag
      ).replace(/!/g, "%21");
      if (state.tag[0] === "!") {
        tagStr = "!" + tagStr;
      } else if (tagStr.slice(0, 18) === "tag:yaml.org,2002:") {
        tagStr = "!!" + tagStr.slice(18);
      } else {
        tagStr = "!<" + tagStr + ">";
      }
      state.dump = tagStr + " " + state.dump;
    }
  }
  return true;
}
function getDuplicateReferences(object, state) {
  var objects = [], duplicatesIndexes = [], index, length;
  inspectNode(object, objects, duplicatesIndexes);
  for (index = 0, length = duplicatesIndexes.length; index < length; index += 1) {
    state.duplicates.push(objects[duplicatesIndexes[index]]);
  }
  state.usedDuplicates = new Array(length);
}
function inspectNode(object, objects, duplicatesIndexes) {
  var objectKeyList, index, length;
  if (object !== null && typeof object === "object") {
    index = objects.indexOf(object);
    if (index !== -1) {
      if (duplicatesIndexes.indexOf(index) === -1) {
        duplicatesIndexes.push(index);
      }
    } else {
      objects.push(object);
      if (Array.isArray(object)) {
        for (index = 0, length = object.length; index < length; index += 1) {
          inspectNode(object[index], objects, duplicatesIndexes);
        }
      } else {
        objectKeyList = Object.keys(object);
        for (index = 0, length = objectKeyList.length; index < length; index += 1) {
          inspectNode(object[objectKeyList[index]], objects, duplicatesIndexes);
        }
      }
    }
  }
}
function dump$1(input, options) {
  options = options || {};
  var state = new State(options);
  if (!state.noRefs)
    getDuplicateReferences(input, state);
  var value = input;
  if (state.replacer) {
    value = state.replacer.call({ "": value }, "", value);
  }
  if (writeNode(state, 0, value, true, true))
    return state.dump + "\n";
  return "";
}
var dump_1 = dump$1;
var dumper = {
  dump: dump_1
};
function renamed(from, to) {
  return function() {
    throw new Error("Function yaml." + from + " is removed in js-yaml 4. Use yaml." + to + " instead, which is now safe by default.");
  };
}
var load = loader.load;
var loadAll = loader.loadAll;
var dump = dumper.dump;
var safeLoad = renamed("safeLoad", "load");
var safeLoadAll = renamed("safeLoadAll", "loadAll");
var safeDump = renamed("safeDump", "dump");

// src/config.ts
var CONFIG_ENV_PREFIX = "config.";
function getConfigValues() {
  const values = {};
  for (const name in import_node_process.env) {
    if (name.startsWith(CONFIG_ENV_PREFIX)) {
      values[name.slice(CONFIG_ENV_PREFIX.length)] = import_node_process.env[name];
    }
  }
  return values;
}
function replaceAll(str2, search, value) {
  while (true) {
    const nextStr = str2.replace(search, value);
    if (nextStr === str2)
      return str2;
    str2 = nextStr;
  }
}
function setConfigValuesRecursively(config2, values) {
  for (const i in config2) {
    if (typeof config2[i] === "string") {
      for (const name in values) {
        config2[i] = replaceAll(config2[i], `\${${name}}`, values[name]);
      }
    } else if (typeof config2[i] === "object" && config2[i]) {
      setConfigValuesRecursively(config2[i], values);
    }
  }
}
var config_default = () => {
  const config2 = load((0, import_core.getInput)("config"));
  if (!config2 || typeof config2 !== "object" || Array.isArray(config2)) {
    (0, import_core.error)("Unknown config object. Should be YAML or JSON -serialized object");
  }
  (0, import_core.info)(`Loaded config:
${dump(config2)}`);
  const configValues = getConfigValues();
  (0, import_core.info)(`Loaded config values:
${dump(configValues)}`);
  setConfigValuesRecursively(config2, configValues);
  (0, import_core.info)(`Config with values:
${dump(config2)}`);
  return config2;
};

// src/index.ts
var config = config_default();
/*! Bundled license information:

js-yaml/dist/js-yaml.mjs:
  (*! js-yaml 4.1.0 https://github.com/nodeca/js-yaml @license MIT *)
*/
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vbm9kZV9tb2R1bGVzL0BhY3Rpb25zL2NvcmUvc3JjL3V0aWxzLnRzIiwgIi4uL25vZGVfbW9kdWxlcy9AYWN0aW9ucy9jb3JlL3NyYy9jb21tYW5kLnRzIiwgIi4uL25vZGVfbW9kdWxlcy91dWlkL2Rpc3QvZXNtLW5vZGUvcm5nLmpzIiwgIi4uL25vZGVfbW9kdWxlcy91dWlkL2Rpc3QvZXNtLW5vZGUvcmVnZXguanMiLCAiLi4vbm9kZV9tb2R1bGVzL3V1aWQvZGlzdC9lc20tbm9kZS92YWxpZGF0ZS5qcyIsICIuLi9ub2RlX21vZHVsZXMvdXVpZC9kaXN0L2VzbS1ub2RlL3N0cmluZ2lmeS5qcyIsICIuLi9ub2RlX21vZHVsZXMvdXVpZC9kaXN0L2VzbS1ub2RlL3YxLmpzIiwgIi4uL25vZGVfbW9kdWxlcy91dWlkL2Rpc3QvZXNtLW5vZGUvcGFyc2UuanMiLCAiLi4vbm9kZV9tb2R1bGVzL3V1aWQvZGlzdC9lc20tbm9kZS92MzUuanMiLCAiLi4vbm9kZV9tb2R1bGVzL3V1aWQvZGlzdC9lc20tbm9kZS9tZDUuanMiLCAiLi4vbm9kZV9tb2R1bGVzL3V1aWQvZGlzdC9lc20tbm9kZS92My5qcyIsICIuLi9ub2RlX21vZHVsZXMvdXVpZC9kaXN0L2VzbS1ub2RlL3Y0LmpzIiwgIi4uL25vZGVfbW9kdWxlcy91dWlkL2Rpc3QvZXNtLW5vZGUvc2hhMS5qcyIsICIuLi9ub2RlX21vZHVsZXMvdXVpZC9kaXN0L2VzbS1ub2RlL3Y1LmpzIiwgIi4uL25vZGVfbW9kdWxlcy91dWlkL2Rpc3QvZXNtLW5vZGUvbmlsLmpzIiwgIi4uL25vZGVfbW9kdWxlcy91dWlkL2Rpc3QvZXNtLW5vZGUvdmVyc2lvbi5qcyIsICIuLi9ub2RlX21vZHVsZXMvdXVpZC9kaXN0L2VzbS1ub2RlL2luZGV4LmpzIiwgIi4uL25vZGVfbW9kdWxlcy9AYWN0aW9ucy9jb3JlL3NyYy9maWxlLWNvbW1hbmQudHMiLCAiLi4vbm9kZV9tb2R1bGVzL0BhY3Rpb25zL2h0dHAtY2xpZW50L3NyYy9wcm94eS50cyIsICIuLi9ub2RlX21vZHVsZXMvdHVubmVsL2xpYi90dW5uZWwuanMiLCAiLi4vbm9kZV9tb2R1bGVzL3R1bm5lbC9pbmRleC5qcyIsICIuLi9ub2RlX21vZHVsZXMvQGFjdGlvbnMvaHR0cC1jbGllbnQvc3JjL2luZGV4LnRzIiwgIi4uL25vZGVfbW9kdWxlcy9AYWN0aW9ucy9odHRwLWNsaWVudC9zcmMvYXV0aC50cyIsICIuLi9ub2RlX21vZHVsZXMvQGFjdGlvbnMvY29yZS9zcmMvb2lkYy11dGlscy50cyIsICIuLi9ub2RlX21vZHVsZXMvQGFjdGlvbnMvY29yZS9zcmMvc3VtbWFyeS50cyIsICIuLi9ub2RlX21vZHVsZXMvQGFjdGlvbnMvY29yZS9zcmMvcGF0aC11dGlscy50cyIsICIuLi9ub2RlX21vZHVsZXMvQGFjdGlvbnMvY29yZS9zcmMvY29yZS50cyIsICIuLi9zcmMvY29uZmlnLnRzIiwgIi4uL25vZGVfbW9kdWxlcy9qcy15YW1sL2Rpc3QvanMteWFtbC5tanMiLCAiLi4vc3JjL2luZGV4LnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogW251bGwsIG51bGwsICJpbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5jb25zdCBybmRzOFBvb2wgPSBuZXcgVWludDhBcnJheSgyNTYpOyAvLyAjIG9mIHJhbmRvbSB2YWx1ZXMgdG8gcHJlLWFsbG9jYXRlXG5cbmxldCBwb29sUHRyID0gcm5kczhQb29sLmxlbmd0aDtcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHJuZygpIHtcbiAgaWYgKHBvb2xQdHIgPiBybmRzOFBvb2wubGVuZ3RoIC0gMTYpIHtcbiAgICBjcnlwdG8ucmFuZG9tRmlsbFN5bmMocm5kczhQb29sKTtcbiAgICBwb29sUHRyID0gMDtcbiAgfVxuXG4gIHJldHVybiBybmRzOFBvb2wuc2xpY2UocG9vbFB0ciwgcG9vbFB0ciArPSAxNik7XG59IiwgImV4cG9ydCBkZWZhdWx0IC9eKD86WzAtOWEtZl17OH0tWzAtOWEtZl17NH0tWzEtNV1bMC05YS1mXXszfS1bODlhYl1bMC05YS1mXXszfS1bMC05YS1mXXsxMn18MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwKSQvaTsiLCAiaW1wb3J0IFJFR0VYIGZyb20gJy4vcmVnZXguanMnO1xuXG5mdW5jdGlvbiB2YWxpZGF0ZSh1dWlkKSB7XG4gIHJldHVybiB0eXBlb2YgdXVpZCA9PT0gJ3N0cmluZycgJiYgUkVHRVgudGVzdCh1dWlkKTtcbn1cblxuZXhwb3J0IGRlZmF1bHQgdmFsaWRhdGU7IiwgImltcG9ydCB2YWxpZGF0ZSBmcm9tICcuL3ZhbGlkYXRlLmpzJztcbi8qKlxuICogQ29udmVydCBhcnJheSBvZiAxNiBieXRlIHZhbHVlcyB0byBVVUlEIHN0cmluZyBmb3JtYXQgb2YgdGhlIGZvcm06XG4gKiBYWFhYWFhYWC1YWFhYLVhYWFgtWFhYWC1YWFhYWFhYWFhYWFhcbiAqL1xuXG5jb25zdCBieXRlVG9IZXggPSBbXTtcblxuZm9yIChsZXQgaSA9IDA7IGkgPCAyNTY7ICsraSkge1xuICBieXRlVG9IZXgucHVzaCgoaSArIDB4MTAwKS50b1N0cmluZygxNikuc3Vic3RyKDEpKTtcbn1cblxuZnVuY3Rpb24gc3RyaW5naWZ5KGFyciwgb2Zmc2V0ID0gMCkge1xuICAvLyBOb3RlOiBCZSBjYXJlZnVsIGVkaXRpbmcgdGhpcyBjb2RlISAgSXQncyBiZWVuIHR1bmVkIGZvciBwZXJmb3JtYW5jZVxuICAvLyBhbmQgd29ya3MgaW4gd2F5cyB5b3UgbWF5IG5vdCBleHBlY3QuIFNlZSBodHRwczovL2dpdGh1Yi5jb20vdXVpZGpzL3V1aWQvcHVsbC80MzRcbiAgY29uc3QgdXVpZCA9IChieXRlVG9IZXhbYXJyW29mZnNldCArIDBdXSArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgMV1dICsgYnl0ZVRvSGV4W2FycltvZmZzZXQgKyAyXV0gKyBieXRlVG9IZXhbYXJyW29mZnNldCArIDNdXSArICctJyArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgNF1dICsgYnl0ZVRvSGV4W2FycltvZmZzZXQgKyA1XV0gKyAnLScgKyBieXRlVG9IZXhbYXJyW29mZnNldCArIDZdXSArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgN11dICsgJy0nICsgYnl0ZVRvSGV4W2FycltvZmZzZXQgKyA4XV0gKyBieXRlVG9IZXhbYXJyW29mZnNldCArIDldXSArICctJyArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgMTBdXSArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgMTFdXSArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgMTJdXSArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgMTNdXSArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgMTRdXSArIGJ5dGVUb0hleFthcnJbb2Zmc2V0ICsgMTVdXSkudG9Mb3dlckNhc2UoKTsgLy8gQ29uc2lzdGVuY3kgY2hlY2sgZm9yIHZhbGlkIFVVSUQuICBJZiB0aGlzIHRocm93cywgaXQncyBsaWtlbHkgZHVlIHRvIG9uZVxuICAvLyBvZiB0aGUgZm9sbG93aW5nOlxuICAvLyAtIE9uZSBvciBtb3JlIGlucHV0IGFycmF5IHZhbHVlcyBkb24ndCBtYXAgdG8gYSBoZXggb2N0ZXQgKGxlYWRpbmcgdG9cbiAgLy8gXCJ1bmRlZmluZWRcIiBpbiB0aGUgdXVpZClcbiAgLy8gLSBJbnZhbGlkIGlucHV0IHZhbHVlcyBmb3IgdGhlIFJGQyBgdmVyc2lvbmAgb3IgYHZhcmlhbnRgIGZpZWxkc1xuXG4gIGlmICghdmFsaWRhdGUodXVpZCkpIHtcbiAgICB0aHJvdyBUeXBlRXJyb3IoJ1N0cmluZ2lmaWVkIFVVSUQgaXMgaW52YWxpZCcpO1xuICB9XG5cbiAgcmV0dXJuIHV1aWQ7XG59XG5cbmV4cG9ydCBkZWZhdWx0IHN0cmluZ2lmeTsiLCAiaW1wb3J0IHJuZyBmcm9tICcuL3JuZy5qcyc7XG5pbXBvcnQgc3RyaW5naWZ5IGZyb20gJy4vc3RyaW5naWZ5LmpzJzsgLy8gKipgdjEoKWAgLSBHZW5lcmF0ZSB0aW1lLWJhc2VkIFVVSUQqKlxuLy9cbi8vIEluc3BpcmVkIGJ5IGh0dHBzOi8vZ2l0aHViLmNvbS9MaW9zSy9VVUlELmpzXG4vLyBhbmQgaHR0cDovL2RvY3MucHl0aG9uLm9yZy9saWJyYXJ5L3V1aWQuaHRtbFxuXG5sZXQgX25vZGVJZDtcblxubGV0IF9jbG9ja3NlcTsgLy8gUHJldmlvdXMgdXVpZCBjcmVhdGlvbiB0aW1lXG5cblxubGV0IF9sYXN0TVNlY3MgPSAwO1xubGV0IF9sYXN0TlNlY3MgPSAwOyAvLyBTZWUgaHR0cHM6Ly9naXRodWIuY29tL3V1aWRqcy91dWlkIGZvciBBUEkgZGV0YWlsc1xuXG5mdW5jdGlvbiB2MShvcHRpb25zLCBidWYsIG9mZnNldCkge1xuICBsZXQgaSA9IGJ1ZiAmJiBvZmZzZXQgfHwgMDtcbiAgY29uc3QgYiA9IGJ1ZiB8fCBuZXcgQXJyYXkoMTYpO1xuICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcbiAgbGV0IG5vZGUgPSBvcHRpb25zLm5vZGUgfHwgX25vZGVJZDtcbiAgbGV0IGNsb2Nrc2VxID0gb3B0aW9ucy5jbG9ja3NlcSAhPT0gdW5kZWZpbmVkID8gb3B0aW9ucy5jbG9ja3NlcSA6IF9jbG9ja3NlcTsgLy8gbm9kZSBhbmQgY2xvY2tzZXEgbmVlZCB0byBiZSBpbml0aWFsaXplZCB0byByYW5kb20gdmFsdWVzIGlmIHRoZXkncmUgbm90XG4gIC8vIHNwZWNpZmllZC4gIFdlIGRvIHRoaXMgbGF6aWx5IHRvIG1pbmltaXplIGlzc3VlcyByZWxhdGVkIHRvIGluc3VmZmljaWVudFxuICAvLyBzeXN0ZW0gZW50cm9weS4gIFNlZSAjMTg5XG5cbiAgaWYgKG5vZGUgPT0gbnVsbCB8fCBjbG9ja3NlcSA9PSBudWxsKSB7XG4gICAgY29uc3Qgc2VlZEJ5dGVzID0gb3B0aW9ucy5yYW5kb20gfHwgKG9wdGlvbnMucm5nIHx8IHJuZykoKTtcblxuICAgIGlmIChub2RlID09IG51bGwpIHtcbiAgICAgIC8vIFBlciA0LjUsIGNyZWF0ZSBhbmQgNDgtYml0IG5vZGUgaWQsICg0NyByYW5kb20gYml0cyArIG11bHRpY2FzdCBiaXQgPSAxKVxuICAgICAgbm9kZSA9IF9ub2RlSWQgPSBbc2VlZEJ5dGVzWzBdIHwgMHgwMSwgc2VlZEJ5dGVzWzFdLCBzZWVkQnl0ZXNbMl0sIHNlZWRCeXRlc1szXSwgc2VlZEJ5dGVzWzRdLCBzZWVkQnl0ZXNbNV1dO1xuICAgIH1cblxuICAgIGlmIChjbG9ja3NlcSA9PSBudWxsKSB7XG4gICAgICAvLyBQZXIgNC4yLjIsIHJhbmRvbWl6ZSAoMTQgYml0KSBjbG9ja3NlcVxuICAgICAgY2xvY2tzZXEgPSBfY2xvY2tzZXEgPSAoc2VlZEJ5dGVzWzZdIDw8IDggfCBzZWVkQnl0ZXNbN10pICYgMHgzZmZmO1xuICAgIH1cbiAgfSAvLyBVVUlEIHRpbWVzdGFtcHMgYXJlIDEwMCBuYW5vLXNlY29uZCB1bml0cyBzaW5jZSB0aGUgR3JlZ29yaWFuIGVwb2NoLFxuICAvLyAoMTU4Mi0xMC0xNSAwMDowMCkuICBKU051bWJlcnMgYXJlbid0IHByZWNpc2UgZW5vdWdoIGZvciB0aGlzLCBzb1xuICAvLyB0aW1lIGlzIGhhbmRsZWQgaW50ZXJuYWxseSBhcyAnbXNlY3MnIChpbnRlZ2VyIG1pbGxpc2Vjb25kcykgYW5kICduc2VjcydcbiAgLy8gKDEwMC1uYW5vc2Vjb25kcyBvZmZzZXQgZnJvbSBtc2Vjcykgc2luY2UgdW5peCBlcG9jaCwgMTk3MC0wMS0wMSAwMDowMC5cblxuXG4gIGxldCBtc2VjcyA9IG9wdGlvbnMubXNlY3MgIT09IHVuZGVmaW5lZCA/IG9wdGlvbnMubXNlY3MgOiBEYXRlLm5vdygpOyAvLyBQZXIgNC4yLjEuMiwgdXNlIGNvdW50IG9mIHV1aWQncyBnZW5lcmF0ZWQgZHVyaW5nIHRoZSBjdXJyZW50IGNsb2NrXG4gIC8vIGN5Y2xlIHRvIHNpbXVsYXRlIGhpZ2hlciByZXNvbHV0aW9uIGNsb2NrXG5cbiAgbGV0IG5zZWNzID0gb3B0aW9ucy5uc2VjcyAhPT0gdW5kZWZpbmVkID8gb3B0aW9ucy5uc2VjcyA6IF9sYXN0TlNlY3MgKyAxOyAvLyBUaW1lIHNpbmNlIGxhc3QgdXVpZCBjcmVhdGlvbiAoaW4gbXNlY3MpXG5cbiAgY29uc3QgZHQgPSBtc2VjcyAtIF9sYXN0TVNlY3MgKyAobnNlY3MgLSBfbGFzdE5TZWNzKSAvIDEwMDAwOyAvLyBQZXIgNC4yLjEuMiwgQnVtcCBjbG9ja3NlcSBvbiBjbG9jayByZWdyZXNzaW9uXG5cbiAgaWYgKGR0IDwgMCAmJiBvcHRpb25zLmNsb2Nrc2VxID09PSB1bmRlZmluZWQpIHtcbiAgICBjbG9ja3NlcSA9IGNsb2Nrc2VxICsgMSAmIDB4M2ZmZjtcbiAgfSAvLyBSZXNldCBuc2VjcyBpZiBjbG9jayByZWdyZXNzZXMgKG5ldyBjbG9ja3NlcSkgb3Igd2UndmUgbW92ZWQgb250byBhIG5ld1xuICAvLyB0aW1lIGludGVydmFsXG5cblxuICBpZiAoKGR0IDwgMCB8fCBtc2VjcyA+IF9sYXN0TVNlY3MpICYmIG9wdGlvbnMubnNlY3MgPT09IHVuZGVmaW5lZCkge1xuICAgIG5zZWNzID0gMDtcbiAgfSAvLyBQZXIgNC4yLjEuMiBUaHJvdyBlcnJvciBpZiB0b28gbWFueSB1dWlkcyBhcmUgcmVxdWVzdGVkXG5cblxuICBpZiAobnNlY3MgPj0gMTAwMDApIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoXCJ1dWlkLnYxKCk6IENhbid0IGNyZWF0ZSBtb3JlIHRoYW4gMTBNIHV1aWRzL3NlY1wiKTtcbiAgfVxuXG4gIF9sYXN0TVNlY3MgPSBtc2VjcztcbiAgX2xhc3ROU2VjcyA9IG5zZWNzO1xuICBfY2xvY2tzZXEgPSBjbG9ja3NlcTsgLy8gUGVyIDQuMS40IC0gQ29udmVydCBmcm9tIHVuaXggZXBvY2ggdG8gR3JlZ29yaWFuIGVwb2NoXG5cbiAgbXNlY3MgKz0gMTIyMTkyOTI4MDAwMDA7IC8vIGB0aW1lX2xvd2BcblxuICBjb25zdCB0bCA9ICgobXNlY3MgJiAweGZmZmZmZmYpICogMTAwMDAgKyBuc2VjcykgJSAweDEwMDAwMDAwMDtcbiAgYltpKytdID0gdGwgPj4+IDI0ICYgMHhmZjtcbiAgYltpKytdID0gdGwgPj4+IDE2ICYgMHhmZjtcbiAgYltpKytdID0gdGwgPj4+IDggJiAweGZmO1xuICBiW2krK10gPSB0bCAmIDB4ZmY7IC8vIGB0aW1lX21pZGBcblxuICBjb25zdCB0bWggPSBtc2VjcyAvIDB4MTAwMDAwMDAwICogMTAwMDAgJiAweGZmZmZmZmY7XG4gIGJbaSsrXSA9IHRtaCA+Pj4gOCAmIDB4ZmY7XG4gIGJbaSsrXSA9IHRtaCAmIDB4ZmY7IC8vIGB0aW1lX2hpZ2hfYW5kX3ZlcnNpb25gXG5cbiAgYltpKytdID0gdG1oID4+PiAyNCAmIDB4ZiB8IDB4MTA7IC8vIGluY2x1ZGUgdmVyc2lvblxuXG4gIGJbaSsrXSA9IHRtaCA+Pj4gMTYgJiAweGZmOyAvLyBgY2xvY2tfc2VxX2hpX2FuZF9yZXNlcnZlZGAgKFBlciA0LjIuMiAtIGluY2x1ZGUgdmFyaWFudClcblxuICBiW2krK10gPSBjbG9ja3NlcSA+Pj4gOCB8IDB4ODA7IC8vIGBjbG9ja19zZXFfbG93YFxuXG4gIGJbaSsrXSA9IGNsb2Nrc2VxICYgMHhmZjsgLy8gYG5vZGVgXG5cbiAgZm9yIChsZXQgbiA9IDA7IG4gPCA2OyArK24pIHtcbiAgICBiW2kgKyBuXSA9IG5vZGVbbl07XG4gIH1cblxuICByZXR1cm4gYnVmIHx8IHN0cmluZ2lmeShiKTtcbn1cblxuZXhwb3J0IGRlZmF1bHQgdjE7IiwgImltcG9ydCB2YWxpZGF0ZSBmcm9tICcuL3ZhbGlkYXRlLmpzJztcblxuZnVuY3Rpb24gcGFyc2UodXVpZCkge1xuICBpZiAoIXZhbGlkYXRlKHV1aWQpKSB7XG4gICAgdGhyb3cgVHlwZUVycm9yKCdJbnZhbGlkIFVVSUQnKTtcbiAgfVxuXG4gIGxldCB2O1xuICBjb25zdCBhcnIgPSBuZXcgVWludDhBcnJheSgxNik7IC8vIFBhcnNlICMjIyMjIyMjLS4uLi4tLi4uLi0uLi4uLS4uLi4uLi4uLi4uLlxuXG4gIGFyclswXSA9ICh2ID0gcGFyc2VJbnQodXVpZC5zbGljZSgwLCA4KSwgMTYpKSA+Pj4gMjQ7XG4gIGFyclsxXSA9IHYgPj4+IDE2ICYgMHhmZjtcbiAgYXJyWzJdID0gdiA+Pj4gOCAmIDB4ZmY7XG4gIGFyclszXSA9IHYgJiAweGZmOyAvLyBQYXJzZSAuLi4uLi4uLi0jIyMjLS4uLi4tLi4uLi0uLi4uLi4uLi4uLi5cblxuICBhcnJbNF0gPSAodiA9IHBhcnNlSW50KHV1aWQuc2xpY2UoOSwgMTMpLCAxNikpID4+PiA4O1xuICBhcnJbNV0gPSB2ICYgMHhmZjsgLy8gUGFyc2UgLi4uLi4uLi4tLi4uLi0jIyMjLS4uLi4tLi4uLi4uLi4uLi4uXG5cbiAgYXJyWzZdID0gKHYgPSBwYXJzZUludCh1dWlkLnNsaWNlKDE0LCAxOCksIDE2KSkgPj4+IDg7XG4gIGFycls3XSA9IHYgJiAweGZmOyAvLyBQYXJzZSAuLi4uLi4uLi0uLi4uLS4uLi4tIyMjIy0uLi4uLi4uLi4uLi5cblxuICBhcnJbOF0gPSAodiA9IHBhcnNlSW50KHV1aWQuc2xpY2UoMTksIDIzKSwgMTYpKSA+Pj4gODtcbiAgYXJyWzldID0gdiAmIDB4ZmY7IC8vIFBhcnNlIC4uLi4uLi4uLS4uLi4tLi4uLi0uLi4uLSMjIyMjIyMjIyMjI1xuICAvLyAoVXNlIFwiL1wiIHRvIGF2b2lkIDMyLWJpdCB0cnVuY2F0aW9uIHdoZW4gYml0LXNoaWZ0aW5nIGhpZ2gtb3JkZXIgYnl0ZXMpXG5cbiAgYXJyWzEwXSA9ICh2ID0gcGFyc2VJbnQodXVpZC5zbGljZSgyNCwgMzYpLCAxNikpIC8gMHgxMDAwMDAwMDAwMCAmIDB4ZmY7XG4gIGFyclsxMV0gPSB2IC8gMHgxMDAwMDAwMDAgJiAweGZmO1xuICBhcnJbMTJdID0gdiA+Pj4gMjQgJiAweGZmO1xuICBhcnJbMTNdID0gdiA+Pj4gMTYgJiAweGZmO1xuICBhcnJbMTRdID0gdiA+Pj4gOCAmIDB4ZmY7XG4gIGFyclsxNV0gPSB2ICYgMHhmZjtcbiAgcmV0dXJuIGFycjtcbn1cblxuZXhwb3J0IGRlZmF1bHQgcGFyc2U7IiwgImltcG9ydCBzdHJpbmdpZnkgZnJvbSAnLi9zdHJpbmdpZnkuanMnO1xuaW1wb3J0IHBhcnNlIGZyb20gJy4vcGFyc2UuanMnO1xuXG5mdW5jdGlvbiBzdHJpbmdUb0J5dGVzKHN0cikge1xuICBzdHIgPSB1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQoc3RyKSk7IC8vIFVURjggZXNjYXBlXG5cbiAgY29uc3QgYnl0ZXMgPSBbXTtcblxuICBmb3IgKGxldCBpID0gMDsgaSA8IHN0ci5sZW5ndGg7ICsraSkge1xuICAgIGJ5dGVzLnB1c2goc3RyLmNoYXJDb2RlQXQoaSkpO1xuICB9XG5cbiAgcmV0dXJuIGJ5dGVzO1xufVxuXG5leHBvcnQgY29uc3QgRE5TID0gJzZiYTdiODEwLTlkYWQtMTFkMS04MGI0LTAwYzA0ZmQ0MzBjOCc7XG5leHBvcnQgY29uc3QgVVJMID0gJzZiYTdiODExLTlkYWQtMTFkMS04MGI0LTAwYzA0ZmQ0MzBjOCc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiAobmFtZSwgdmVyc2lvbiwgaGFzaGZ1bmMpIHtcbiAgZnVuY3Rpb24gZ2VuZXJhdGVVVUlEKHZhbHVlLCBuYW1lc3BhY2UsIGJ1Ziwgb2Zmc2V0KSB7XG4gICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIHZhbHVlID0gc3RyaW5nVG9CeXRlcyh2YWx1ZSk7XG4gICAgfVxuXG4gICAgaWYgKHR5cGVvZiBuYW1lc3BhY2UgPT09ICdzdHJpbmcnKSB7XG4gICAgICBuYW1lc3BhY2UgPSBwYXJzZShuYW1lc3BhY2UpO1xuICAgIH1cblxuICAgIGlmIChuYW1lc3BhY2UubGVuZ3RoICE9PSAxNikge1xuICAgICAgdGhyb3cgVHlwZUVycm9yKCdOYW1lc3BhY2UgbXVzdCBiZSBhcnJheS1saWtlICgxNiBpdGVyYWJsZSBpbnRlZ2VyIHZhbHVlcywgMC0yNTUpJyk7XG4gICAgfSAvLyBDb21wdXRlIGhhc2ggb2YgbmFtZXNwYWNlIGFuZCB2YWx1ZSwgUGVyIDQuM1xuICAgIC8vIEZ1dHVyZTogVXNlIHNwcmVhZCBzeW50YXggd2hlbiBzdXBwb3J0ZWQgb24gYWxsIHBsYXRmb3JtcywgZS5nLiBgYnl0ZXMgPVxuICAgIC8vIGhhc2hmdW5jKFsuLi5uYW1lc3BhY2UsIC4uLiB2YWx1ZV0pYFxuXG5cbiAgICBsZXQgYnl0ZXMgPSBuZXcgVWludDhBcnJheSgxNiArIHZhbHVlLmxlbmd0aCk7XG4gICAgYnl0ZXMuc2V0KG5hbWVzcGFjZSk7XG4gICAgYnl0ZXMuc2V0KHZhbHVlLCBuYW1lc3BhY2UubGVuZ3RoKTtcbiAgICBieXRlcyA9IGhhc2hmdW5jKGJ5dGVzKTtcbiAgICBieXRlc1s2XSA9IGJ5dGVzWzZdICYgMHgwZiB8IHZlcnNpb247XG4gICAgYnl0ZXNbOF0gPSBieXRlc1s4XSAmIDB4M2YgfCAweDgwO1xuXG4gICAgaWYgKGJ1Zikge1xuICAgICAgb2Zmc2V0ID0gb2Zmc2V0IHx8IDA7XG5cbiAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgMTY7ICsraSkge1xuICAgICAgICBidWZbb2Zmc2V0ICsgaV0gPSBieXRlc1tpXTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIGJ1ZjtcbiAgICB9XG5cbiAgICByZXR1cm4gc3RyaW5naWZ5KGJ5dGVzKTtcbiAgfSAvLyBGdW5jdGlvbiNuYW1lIGlzIG5vdCBzZXR0YWJsZSBvbiBzb21lIHBsYXRmb3JtcyAoIzI3MClcblxuXG4gIHRyeSB7XG4gICAgZ2VuZXJhdGVVVUlELm5hbWUgPSBuYW1lOyAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tZW1wdHlcbiAgfSBjYXRjaCAoZXJyKSB7fSAvLyBGb3IgQ29tbW9uSlMgZGVmYXVsdCBleHBvcnQgc3VwcG9ydFxuXG5cbiAgZ2VuZXJhdGVVVUlELkROUyA9IEROUztcbiAgZ2VuZXJhdGVVVUlELlVSTCA9IFVSTDtcbiAgcmV0dXJuIGdlbmVyYXRlVVVJRDtcbn0iLCAiaW1wb3J0IGNyeXB0byBmcm9tICdjcnlwdG8nO1xuXG5mdW5jdGlvbiBtZDUoYnl0ZXMpIHtcbiAgaWYgKEFycmF5LmlzQXJyYXkoYnl0ZXMpKSB7XG4gICAgYnl0ZXMgPSBCdWZmZXIuZnJvbShieXRlcyk7XG4gIH0gZWxzZSBpZiAodHlwZW9mIGJ5dGVzID09PSAnc3RyaW5nJykge1xuICAgIGJ5dGVzID0gQnVmZmVyLmZyb20oYnl0ZXMsICd1dGY4Jyk7XG4gIH1cblxuICByZXR1cm4gY3J5cHRvLmNyZWF0ZUhhc2goJ21kNScpLnVwZGF0ZShieXRlcykuZGlnZXN0KCk7XG59XG5cbmV4cG9ydCBkZWZhdWx0IG1kNTsiLCAiaW1wb3J0IHYzNSBmcm9tICcuL3YzNS5qcyc7XG5pbXBvcnQgbWQ1IGZyb20gJy4vbWQ1LmpzJztcbmNvbnN0IHYzID0gdjM1KCd2MycsIDB4MzAsIG1kNSk7XG5leHBvcnQgZGVmYXVsdCB2MzsiLCAiaW1wb3J0IHJuZyBmcm9tICcuL3JuZy5qcyc7XG5pbXBvcnQgc3RyaW5naWZ5IGZyb20gJy4vc3RyaW5naWZ5LmpzJztcblxuZnVuY3Rpb24gdjQob3B0aW9ucywgYnVmLCBvZmZzZXQpIHtcbiAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG4gIGNvbnN0IHJuZHMgPSBvcHRpb25zLnJhbmRvbSB8fCAob3B0aW9ucy5ybmcgfHwgcm5nKSgpOyAvLyBQZXIgNC40LCBzZXQgYml0cyBmb3IgdmVyc2lvbiBhbmQgYGNsb2NrX3NlcV9oaV9hbmRfcmVzZXJ2ZWRgXG5cbiAgcm5kc1s2XSA9IHJuZHNbNl0gJiAweDBmIHwgMHg0MDtcbiAgcm5kc1s4XSA9IHJuZHNbOF0gJiAweDNmIHwgMHg4MDsgLy8gQ29weSBieXRlcyB0byBidWZmZXIsIGlmIHByb3ZpZGVkXG5cbiAgaWYgKGJ1Zikge1xuICAgIG9mZnNldCA9IG9mZnNldCB8fCAwO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCAxNjsgKytpKSB7XG4gICAgICBidWZbb2Zmc2V0ICsgaV0gPSBybmRzW2ldO1xuICAgIH1cblxuICAgIHJldHVybiBidWY7XG4gIH1cblxuICByZXR1cm4gc3RyaW5naWZ5KHJuZHMpO1xufVxuXG5leHBvcnQgZGVmYXVsdCB2NDsiLCAiaW1wb3J0IGNyeXB0byBmcm9tICdjcnlwdG8nO1xuXG5mdW5jdGlvbiBzaGExKGJ5dGVzKSB7XG4gIGlmIChBcnJheS5pc0FycmF5KGJ5dGVzKSkge1xuICAgIGJ5dGVzID0gQnVmZmVyLmZyb20oYnl0ZXMpO1xuICB9IGVsc2UgaWYgKHR5cGVvZiBieXRlcyA9PT0gJ3N0cmluZycpIHtcbiAgICBieXRlcyA9IEJ1ZmZlci5mcm9tKGJ5dGVzLCAndXRmOCcpO1xuICB9XG5cbiAgcmV0dXJuIGNyeXB0by5jcmVhdGVIYXNoKCdzaGExJykudXBkYXRlKGJ5dGVzKS5kaWdlc3QoKTtcbn1cblxuZXhwb3J0IGRlZmF1bHQgc2hhMTsiLCAiaW1wb3J0IHYzNSBmcm9tICcuL3YzNS5qcyc7XG5pbXBvcnQgc2hhMSBmcm9tICcuL3NoYTEuanMnO1xuY29uc3QgdjUgPSB2MzUoJ3Y1JywgMHg1MCwgc2hhMSk7XG5leHBvcnQgZGVmYXVsdCB2NTsiLCAiZXhwb3J0IGRlZmF1bHQgJzAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCc7IiwgImltcG9ydCB2YWxpZGF0ZSBmcm9tICcuL3ZhbGlkYXRlLmpzJztcblxuZnVuY3Rpb24gdmVyc2lvbih1dWlkKSB7XG4gIGlmICghdmFsaWRhdGUodXVpZCkpIHtcbiAgICB0aHJvdyBUeXBlRXJyb3IoJ0ludmFsaWQgVVVJRCcpO1xuICB9XG5cbiAgcmV0dXJuIHBhcnNlSW50KHV1aWQuc3Vic3RyKDE0LCAxKSwgMTYpO1xufVxuXG5leHBvcnQgZGVmYXVsdCB2ZXJzaW9uOyIsICJleHBvcnQgeyBkZWZhdWx0IGFzIHYxIH0gZnJvbSAnLi92MS5qcyc7XG5leHBvcnQgeyBkZWZhdWx0IGFzIHYzIH0gZnJvbSAnLi92My5qcyc7XG5leHBvcnQgeyBkZWZhdWx0IGFzIHY0IH0gZnJvbSAnLi92NC5qcyc7XG5leHBvcnQgeyBkZWZhdWx0IGFzIHY1IH0gZnJvbSAnLi92NS5qcyc7XG5leHBvcnQgeyBkZWZhdWx0IGFzIE5JTCB9IGZyb20gJy4vbmlsLmpzJztcbmV4cG9ydCB7IGRlZmF1bHQgYXMgdmVyc2lvbiB9IGZyb20gJy4vdmVyc2lvbi5qcyc7XG5leHBvcnQgeyBkZWZhdWx0IGFzIHZhbGlkYXRlIH0gZnJvbSAnLi92YWxpZGF0ZS5qcyc7XG5leHBvcnQgeyBkZWZhdWx0IGFzIHN0cmluZ2lmeSB9IGZyb20gJy4vc3RyaW5naWZ5LmpzJztcbmV4cG9ydCB7IGRlZmF1bHQgYXMgcGFyc2UgfSBmcm9tICcuL3BhcnNlLmpzJzsiLCBudWxsLCBudWxsLCAiJ3VzZSBzdHJpY3QnO1xuXG52YXIgbmV0ID0gcmVxdWlyZSgnbmV0Jyk7XG52YXIgdGxzID0gcmVxdWlyZSgndGxzJyk7XG52YXIgaHR0cCA9IHJlcXVpcmUoJ2h0dHAnKTtcbnZhciBodHRwcyA9IHJlcXVpcmUoJ2h0dHBzJyk7XG52YXIgZXZlbnRzID0gcmVxdWlyZSgnZXZlbnRzJyk7XG52YXIgYXNzZXJ0ID0gcmVxdWlyZSgnYXNzZXJ0Jyk7XG52YXIgdXRpbCA9IHJlcXVpcmUoJ3V0aWwnKTtcblxuXG5leHBvcnRzLmh0dHBPdmVySHR0cCA9IGh0dHBPdmVySHR0cDtcbmV4cG9ydHMuaHR0cHNPdmVySHR0cCA9IGh0dHBzT3Zlckh0dHA7XG5leHBvcnRzLmh0dHBPdmVySHR0cHMgPSBodHRwT3Zlckh0dHBzO1xuZXhwb3J0cy5odHRwc092ZXJIdHRwcyA9IGh0dHBzT3Zlckh0dHBzO1xuXG5cbmZ1bmN0aW9uIGh0dHBPdmVySHR0cChvcHRpb25zKSB7XG4gIHZhciBhZ2VudCA9IG5ldyBUdW5uZWxpbmdBZ2VudChvcHRpb25zKTtcbiAgYWdlbnQucmVxdWVzdCA9IGh0dHAucmVxdWVzdDtcbiAgcmV0dXJuIGFnZW50O1xufVxuXG5mdW5jdGlvbiBodHRwc092ZXJIdHRwKG9wdGlvbnMpIHtcbiAgdmFyIGFnZW50ID0gbmV3IFR1bm5lbGluZ0FnZW50KG9wdGlvbnMpO1xuICBhZ2VudC5yZXF1ZXN0ID0gaHR0cC5yZXF1ZXN0O1xuICBhZ2VudC5jcmVhdGVTb2NrZXQgPSBjcmVhdGVTZWN1cmVTb2NrZXQ7XG4gIGFnZW50LmRlZmF1bHRQb3J0ID0gNDQzO1xuICByZXR1cm4gYWdlbnQ7XG59XG5cbmZ1bmN0aW9uIGh0dHBPdmVySHR0cHMob3B0aW9ucykge1xuICB2YXIgYWdlbnQgPSBuZXcgVHVubmVsaW5nQWdlbnQob3B0aW9ucyk7XG4gIGFnZW50LnJlcXVlc3QgPSBodHRwcy5yZXF1ZXN0O1xuICByZXR1cm4gYWdlbnQ7XG59XG5cbmZ1bmN0aW9uIGh0dHBzT3Zlckh0dHBzKG9wdGlvbnMpIHtcbiAgdmFyIGFnZW50ID0gbmV3IFR1bm5lbGluZ0FnZW50KG9wdGlvbnMpO1xuICBhZ2VudC5yZXF1ZXN0ID0gaHR0cHMucmVxdWVzdDtcbiAgYWdlbnQuY3JlYXRlU29ja2V0ID0gY3JlYXRlU2VjdXJlU29ja2V0O1xuICBhZ2VudC5kZWZhdWx0UG9ydCA9IDQ0MztcbiAgcmV0dXJuIGFnZW50O1xufVxuXG5cbmZ1bmN0aW9uIFR1bm5lbGluZ0FnZW50KG9wdGlvbnMpIHtcbiAgdmFyIHNlbGYgPSB0aGlzO1xuICBzZWxmLm9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuICBzZWxmLnByb3h5T3B0aW9ucyA9IHNlbGYub3B0aW9ucy5wcm94eSB8fCB7fTtcbiAgc2VsZi5tYXhTb2NrZXRzID0gc2VsZi5vcHRpb25zLm1heFNvY2tldHMgfHwgaHR0cC5BZ2VudC5kZWZhdWx0TWF4U29ja2V0cztcbiAgc2VsZi5yZXF1ZXN0cyA9IFtdO1xuICBzZWxmLnNvY2tldHMgPSBbXTtcblxuICBzZWxmLm9uKCdmcmVlJywgZnVuY3Rpb24gb25GcmVlKHNvY2tldCwgaG9zdCwgcG9ydCwgbG9jYWxBZGRyZXNzKSB7XG4gICAgdmFyIG9wdGlvbnMgPSB0b09wdGlvbnMoaG9zdCwgcG9ydCwgbG9jYWxBZGRyZXNzKTtcbiAgICBmb3IgKHZhciBpID0gMCwgbGVuID0gc2VsZi5yZXF1ZXN0cy5sZW5ndGg7IGkgPCBsZW47ICsraSkge1xuICAgICAgdmFyIHBlbmRpbmcgPSBzZWxmLnJlcXVlc3RzW2ldO1xuICAgICAgaWYgKHBlbmRpbmcuaG9zdCA9PT0gb3B0aW9ucy5ob3N0ICYmIHBlbmRpbmcucG9ydCA9PT0gb3B0aW9ucy5wb3J0KSB7XG4gICAgICAgIC8vIERldGVjdCB0aGUgcmVxdWVzdCB0byBjb25uZWN0IHNhbWUgb3JpZ2luIHNlcnZlcixcbiAgICAgICAgLy8gcmV1c2UgdGhlIGNvbm5lY3Rpb24uXG4gICAgICAgIHNlbGYucmVxdWVzdHMuc3BsaWNlKGksIDEpO1xuICAgICAgICBwZW5kaW5nLnJlcXVlc3Qub25Tb2NrZXQoc29ja2V0KTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH1cbiAgICBzb2NrZXQuZGVzdHJveSgpO1xuICAgIHNlbGYucmVtb3ZlU29ja2V0KHNvY2tldCk7XG4gIH0pO1xufVxudXRpbC5pbmhlcml0cyhUdW5uZWxpbmdBZ2VudCwgZXZlbnRzLkV2ZW50RW1pdHRlcik7XG5cblR1bm5lbGluZ0FnZW50LnByb3RvdHlwZS5hZGRSZXF1ZXN0ID0gZnVuY3Rpb24gYWRkUmVxdWVzdChyZXEsIGhvc3QsIHBvcnQsIGxvY2FsQWRkcmVzcykge1xuICB2YXIgc2VsZiA9IHRoaXM7XG4gIHZhciBvcHRpb25zID0gbWVyZ2VPcHRpb25zKHtyZXF1ZXN0OiByZXF9LCBzZWxmLm9wdGlvbnMsIHRvT3B0aW9ucyhob3N0LCBwb3J0LCBsb2NhbEFkZHJlc3MpKTtcblxuICBpZiAoc2VsZi5zb2NrZXRzLmxlbmd0aCA+PSB0aGlzLm1heFNvY2tldHMpIHtcbiAgICAvLyBXZSBhcmUgb3ZlciBsaW1pdCBzbyB3ZSdsbCBhZGQgaXQgdG8gdGhlIHF1ZXVlLlxuICAgIHNlbGYucmVxdWVzdHMucHVzaChvcHRpb25zKTtcbiAgICByZXR1cm47XG4gIH1cblxuICAvLyBJZiB3ZSBhcmUgdW5kZXIgbWF4U29ja2V0cyBjcmVhdGUgYSBuZXcgb25lLlxuICBzZWxmLmNyZWF0ZVNvY2tldChvcHRpb25zLCBmdW5jdGlvbihzb2NrZXQpIHtcbiAgICBzb2NrZXQub24oJ2ZyZWUnLCBvbkZyZWUpO1xuICAgIHNvY2tldC5vbignY2xvc2UnLCBvbkNsb3NlT3JSZW1vdmUpO1xuICAgIHNvY2tldC5vbignYWdlbnRSZW1vdmUnLCBvbkNsb3NlT3JSZW1vdmUpO1xuICAgIHJlcS5vblNvY2tldChzb2NrZXQpO1xuXG4gICAgZnVuY3Rpb24gb25GcmVlKCkge1xuICAgICAgc2VsZi5lbWl0KCdmcmVlJywgc29ja2V0LCBvcHRpb25zKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBvbkNsb3NlT3JSZW1vdmUoZXJyKSB7XG4gICAgICBzZWxmLnJlbW92ZVNvY2tldChzb2NrZXQpO1xuICAgICAgc29ja2V0LnJlbW92ZUxpc3RlbmVyKCdmcmVlJywgb25GcmVlKTtcbiAgICAgIHNvY2tldC5yZW1vdmVMaXN0ZW5lcignY2xvc2UnLCBvbkNsb3NlT3JSZW1vdmUpO1xuICAgICAgc29ja2V0LnJlbW92ZUxpc3RlbmVyKCdhZ2VudFJlbW92ZScsIG9uQ2xvc2VPclJlbW92ZSk7XG4gICAgfVxuICB9KTtcbn07XG5cblR1bm5lbGluZ0FnZW50LnByb3RvdHlwZS5jcmVhdGVTb2NrZXQgPSBmdW5jdGlvbiBjcmVhdGVTb2NrZXQob3B0aW9ucywgY2IpIHtcbiAgdmFyIHNlbGYgPSB0aGlzO1xuICB2YXIgcGxhY2Vob2xkZXIgPSB7fTtcbiAgc2VsZi5zb2NrZXRzLnB1c2gocGxhY2Vob2xkZXIpO1xuXG4gIHZhciBjb25uZWN0T3B0aW9ucyA9IG1lcmdlT3B0aW9ucyh7fSwgc2VsZi5wcm94eU9wdGlvbnMsIHtcbiAgICBtZXRob2Q6ICdDT05ORUNUJyxcbiAgICBwYXRoOiBvcHRpb25zLmhvc3QgKyAnOicgKyBvcHRpb25zLnBvcnQsXG4gICAgYWdlbnQ6IGZhbHNlLFxuICAgIGhlYWRlcnM6IHtcbiAgICAgIGhvc3Q6IG9wdGlvbnMuaG9zdCArICc6JyArIG9wdGlvbnMucG9ydFxuICAgIH1cbiAgfSk7XG4gIGlmIChvcHRpb25zLmxvY2FsQWRkcmVzcykge1xuICAgIGNvbm5lY3RPcHRpb25zLmxvY2FsQWRkcmVzcyA9IG9wdGlvbnMubG9jYWxBZGRyZXNzO1xuICB9XG4gIGlmIChjb25uZWN0T3B0aW9ucy5wcm94eUF1dGgpIHtcbiAgICBjb25uZWN0T3B0aW9ucy5oZWFkZXJzID0gY29ubmVjdE9wdGlvbnMuaGVhZGVycyB8fCB7fTtcbiAgICBjb25uZWN0T3B0aW9ucy5oZWFkZXJzWydQcm94eS1BdXRob3JpemF0aW9uJ10gPSAnQmFzaWMgJyArXG4gICAgICAgIG5ldyBCdWZmZXIoY29ubmVjdE9wdGlvbnMucHJveHlBdXRoKS50b1N0cmluZygnYmFzZTY0Jyk7XG4gIH1cblxuICBkZWJ1ZygnbWFraW5nIENPTk5FQ1QgcmVxdWVzdCcpO1xuICB2YXIgY29ubmVjdFJlcSA9IHNlbGYucmVxdWVzdChjb25uZWN0T3B0aW9ucyk7XG4gIGNvbm5lY3RSZXEudXNlQ2h1bmtlZEVuY29kaW5nQnlEZWZhdWx0ID0gZmFsc2U7IC8vIGZvciB2MC42XG4gIGNvbm5lY3RSZXEub25jZSgncmVzcG9uc2UnLCBvblJlc3BvbnNlKTsgLy8gZm9yIHYwLjZcbiAgY29ubmVjdFJlcS5vbmNlKCd1cGdyYWRlJywgb25VcGdyYWRlKTsgICAvLyBmb3IgdjAuNlxuICBjb25uZWN0UmVxLm9uY2UoJ2Nvbm5lY3QnLCBvbkNvbm5lY3QpOyAgIC8vIGZvciB2MC43IG9yIGxhdGVyXG4gIGNvbm5lY3RSZXEub25jZSgnZXJyb3InLCBvbkVycm9yKTtcbiAgY29ubmVjdFJlcS5lbmQoKTtcblxuICBmdW5jdGlvbiBvblJlc3BvbnNlKHJlcykge1xuICAgIC8vIFZlcnkgaGFja3kuIFRoaXMgaXMgbmVjZXNzYXJ5IHRvIGF2b2lkIGh0dHAtcGFyc2VyIGxlYWtzLlxuICAgIHJlcy51cGdyYWRlID0gdHJ1ZTtcbiAgfVxuXG4gIGZ1bmN0aW9uIG9uVXBncmFkZShyZXMsIHNvY2tldCwgaGVhZCkge1xuICAgIC8vIEhhY2t5LlxuICAgIHByb2Nlc3MubmV4dFRpY2soZnVuY3Rpb24oKSB7XG4gICAgICBvbkNvbm5lY3QocmVzLCBzb2NrZXQsIGhlYWQpO1xuICAgIH0pO1xuICB9XG5cbiAgZnVuY3Rpb24gb25Db25uZWN0KHJlcywgc29ja2V0LCBoZWFkKSB7XG4gICAgY29ubmVjdFJlcS5yZW1vdmVBbGxMaXN0ZW5lcnMoKTtcbiAgICBzb2NrZXQucmVtb3ZlQWxsTGlzdGVuZXJzKCk7XG5cbiAgICBpZiAocmVzLnN0YXR1c0NvZGUgIT09IDIwMCkge1xuICAgICAgZGVidWcoJ3R1bm5lbGluZyBzb2NrZXQgY291bGQgbm90IGJlIGVzdGFibGlzaGVkLCBzdGF0dXNDb2RlPSVkJyxcbiAgICAgICAgcmVzLnN0YXR1c0NvZGUpO1xuICAgICAgc29ja2V0LmRlc3Ryb3koKTtcbiAgICAgIHZhciBlcnJvciA9IG5ldyBFcnJvcigndHVubmVsaW5nIHNvY2tldCBjb3VsZCBub3QgYmUgZXN0YWJsaXNoZWQsICcgK1xuICAgICAgICAnc3RhdHVzQ29kZT0nICsgcmVzLnN0YXR1c0NvZGUpO1xuICAgICAgZXJyb3IuY29kZSA9ICdFQ09OTlJFU0VUJztcbiAgICAgIG9wdGlvbnMucmVxdWVzdC5lbWl0KCdlcnJvcicsIGVycm9yKTtcbiAgICAgIHNlbGYucmVtb3ZlU29ja2V0KHBsYWNlaG9sZGVyKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKGhlYWQubGVuZ3RoID4gMCkge1xuICAgICAgZGVidWcoJ2dvdCBpbGxlZ2FsIHJlc3BvbnNlIGJvZHkgZnJvbSBwcm94eScpO1xuICAgICAgc29ja2V0LmRlc3Ryb3koKTtcbiAgICAgIHZhciBlcnJvciA9IG5ldyBFcnJvcignZ290IGlsbGVnYWwgcmVzcG9uc2UgYm9keSBmcm9tIHByb3h5Jyk7XG4gICAgICBlcnJvci5jb2RlID0gJ0VDT05OUkVTRVQnO1xuICAgICAgb3B0aW9ucy5yZXF1ZXN0LmVtaXQoJ2Vycm9yJywgZXJyb3IpO1xuICAgICAgc2VsZi5yZW1vdmVTb2NrZXQocGxhY2Vob2xkZXIpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBkZWJ1ZygndHVubmVsaW5nIGNvbm5lY3Rpb24gaGFzIGVzdGFibGlzaGVkJyk7XG4gICAgc2VsZi5zb2NrZXRzW3NlbGYuc29ja2V0cy5pbmRleE9mKHBsYWNlaG9sZGVyKV0gPSBzb2NrZXQ7XG4gICAgcmV0dXJuIGNiKHNvY2tldCk7XG4gIH1cblxuICBmdW5jdGlvbiBvbkVycm9yKGNhdXNlKSB7XG4gICAgY29ubmVjdFJlcS5yZW1vdmVBbGxMaXN0ZW5lcnMoKTtcblxuICAgIGRlYnVnKCd0dW5uZWxpbmcgc29ja2V0IGNvdWxkIG5vdCBiZSBlc3RhYmxpc2hlZCwgY2F1c2U9JXNcXG4nLFxuICAgICAgICAgIGNhdXNlLm1lc3NhZ2UsIGNhdXNlLnN0YWNrKTtcbiAgICB2YXIgZXJyb3IgPSBuZXcgRXJyb3IoJ3R1bm5lbGluZyBzb2NrZXQgY291bGQgbm90IGJlIGVzdGFibGlzaGVkLCAnICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgJ2NhdXNlPScgKyBjYXVzZS5tZXNzYWdlKTtcbiAgICBlcnJvci5jb2RlID0gJ0VDT05OUkVTRVQnO1xuICAgIG9wdGlvbnMucmVxdWVzdC5lbWl0KCdlcnJvcicsIGVycm9yKTtcbiAgICBzZWxmLnJlbW92ZVNvY2tldChwbGFjZWhvbGRlcik7XG4gIH1cbn07XG5cblR1bm5lbGluZ0FnZW50LnByb3RvdHlwZS5yZW1vdmVTb2NrZXQgPSBmdW5jdGlvbiByZW1vdmVTb2NrZXQoc29ja2V0KSB7XG4gIHZhciBwb3MgPSB0aGlzLnNvY2tldHMuaW5kZXhPZihzb2NrZXQpXG4gIGlmIChwb3MgPT09IC0xKSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIHRoaXMuc29ja2V0cy5zcGxpY2UocG9zLCAxKTtcblxuICB2YXIgcGVuZGluZyA9IHRoaXMucmVxdWVzdHMuc2hpZnQoKTtcbiAgaWYgKHBlbmRpbmcpIHtcbiAgICAvLyBJZiB3ZSBoYXZlIHBlbmRpbmcgcmVxdWVzdHMgYW5kIGEgc29ja2V0IGdldHMgY2xvc2VkIGEgbmV3IG9uZVxuICAgIC8vIG5lZWRzIHRvIGJlIGNyZWF0ZWQgdG8gdGFrZSBvdmVyIGluIHRoZSBwb29sIGZvciB0aGUgb25lIHRoYXQgY2xvc2VkLlxuICAgIHRoaXMuY3JlYXRlU29ja2V0KHBlbmRpbmcsIGZ1bmN0aW9uKHNvY2tldCkge1xuICAgICAgcGVuZGluZy5yZXF1ZXN0Lm9uU29ja2V0KHNvY2tldCk7XG4gICAgfSk7XG4gIH1cbn07XG5cbmZ1bmN0aW9uIGNyZWF0ZVNlY3VyZVNvY2tldChvcHRpb25zLCBjYikge1xuICB2YXIgc2VsZiA9IHRoaXM7XG4gIFR1bm5lbGluZ0FnZW50LnByb3RvdHlwZS5jcmVhdGVTb2NrZXQuY2FsbChzZWxmLCBvcHRpb25zLCBmdW5jdGlvbihzb2NrZXQpIHtcbiAgICB2YXIgaG9zdEhlYWRlciA9IG9wdGlvbnMucmVxdWVzdC5nZXRIZWFkZXIoJ2hvc3QnKTtcbiAgICB2YXIgdGxzT3B0aW9ucyA9IG1lcmdlT3B0aW9ucyh7fSwgc2VsZi5vcHRpb25zLCB7XG4gICAgICBzb2NrZXQ6IHNvY2tldCxcbiAgICAgIHNlcnZlcm5hbWU6IGhvc3RIZWFkZXIgPyBob3N0SGVhZGVyLnJlcGxhY2UoLzouKiQvLCAnJykgOiBvcHRpb25zLmhvc3RcbiAgICB9KTtcblxuICAgIC8vIDAgaXMgZHVtbXkgcG9ydCBmb3IgdjAuNlxuICAgIHZhciBzZWN1cmVTb2NrZXQgPSB0bHMuY29ubmVjdCgwLCB0bHNPcHRpb25zKTtcbiAgICBzZWxmLnNvY2tldHNbc2VsZi5zb2NrZXRzLmluZGV4T2Yoc29ja2V0KV0gPSBzZWN1cmVTb2NrZXQ7XG4gICAgY2Ioc2VjdXJlU29ja2V0KTtcbiAgfSk7XG59XG5cblxuZnVuY3Rpb24gdG9PcHRpb25zKGhvc3QsIHBvcnQsIGxvY2FsQWRkcmVzcykge1xuICBpZiAodHlwZW9mIGhvc3QgPT09ICdzdHJpbmcnKSB7IC8vIHNpbmNlIHYwLjEwXG4gICAgcmV0dXJuIHtcbiAgICAgIGhvc3Q6IGhvc3QsXG4gICAgICBwb3J0OiBwb3J0LFxuICAgICAgbG9jYWxBZGRyZXNzOiBsb2NhbEFkZHJlc3NcbiAgICB9O1xuICB9XG4gIHJldHVybiBob3N0OyAvLyBmb3IgdjAuMTEgb3IgbGF0ZXJcbn1cblxuZnVuY3Rpb24gbWVyZ2VPcHRpb25zKHRhcmdldCkge1xuICBmb3IgKHZhciBpID0gMSwgbGVuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGxlbjsgKytpKSB7XG4gICAgdmFyIG92ZXJyaWRlcyA9IGFyZ3VtZW50c1tpXTtcbiAgICBpZiAodHlwZW9mIG92ZXJyaWRlcyA9PT0gJ29iamVjdCcpIHtcbiAgICAgIHZhciBrZXlzID0gT2JqZWN0LmtleXMob3ZlcnJpZGVzKTtcbiAgICAgIGZvciAodmFyIGogPSAwLCBrZXlMZW4gPSBrZXlzLmxlbmd0aDsgaiA8IGtleUxlbjsgKytqKSB7XG4gICAgICAgIHZhciBrID0ga2V5c1tqXTtcbiAgICAgICAgaWYgKG92ZXJyaWRlc1trXSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgdGFyZ2V0W2tdID0gb3ZlcnJpZGVzW2tdO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG4gIHJldHVybiB0YXJnZXQ7XG59XG5cblxudmFyIGRlYnVnO1xuaWYgKHByb2Nlc3MuZW52Lk5PREVfREVCVUcgJiYgL1xcYnR1bm5lbFxcYi8udGVzdChwcm9jZXNzLmVudi5OT0RFX0RFQlVHKSkge1xuICBkZWJ1ZyA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBhcmdzID0gQXJyYXkucHJvdG90eXBlLnNsaWNlLmNhbGwoYXJndW1lbnRzKTtcbiAgICBpZiAodHlwZW9mIGFyZ3NbMF0gPT09ICdzdHJpbmcnKSB7XG4gICAgICBhcmdzWzBdID0gJ1RVTk5FTDogJyArIGFyZ3NbMF07XG4gICAgfSBlbHNlIHtcbiAgICAgIGFyZ3MudW5zaGlmdCgnVFVOTkVMOicpO1xuICAgIH1cbiAgICBjb25zb2xlLmVycm9yLmFwcGx5KGNvbnNvbGUsIGFyZ3MpO1xuICB9XG59IGVsc2Uge1xuICBkZWJ1ZyA9IGZ1bmN0aW9uKCkge307XG59XG5leHBvcnRzLmRlYnVnID0gZGVidWc7IC8vIGZvciB0ZXN0XG4iLCAibW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2xpYi90dW5uZWwnKTtcbiIsIG51bGwsIG51bGwsIG51bGwsIG51bGwsIG51bGwsIG51bGwsICJpbXBvcnQgeyBlbnYgfSBmcm9tICdub2RlOnByb2Nlc3MnO1xuaW1wb3J0IHsgZXJyb3IsIGdldElucHV0LCBpbmZvIH0gZnJvbSAnQGFjdGlvbnMvY29yZSc7XG5pbXBvcnQgeyBsb2FkLCBkdW1wIH0gZnJvbSAnanMteWFtbCc7XG5cbmNvbnN0IENPTkZJR19FTlZfUFJFRklYID0gJ2NvbmZpZy4nO1xuXG5mdW5jdGlvbiBnZXRDb25maWdWYWx1ZXMoKSB7XG4gICAgY29uc3QgdmFsdWVzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+ID0ge307XG4gICAgZm9yIChjb25zdCBuYW1lIGluIGVudikge1xuICAgICAgICBpZiAobmFtZS5zdGFydHNXaXRoKENPTkZJR19FTlZfUFJFRklYKSkge1xuICAgICAgICAgICAgdmFsdWVzW25hbWUuc2xpY2UoQ09ORklHX0VOVl9QUkVGSVgubGVuZ3RoKV0gPSBlbnZbbmFtZV0hO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiB2YWx1ZXM7XG59XG5cbmZ1bmN0aW9uIHJlcGxhY2VBbGwoc3RyOiBzdHJpbmcsIHNlYXJjaDogc3RyaW5nLCB2YWx1ZTogc3RyaW5nKSB7XG4gICAgd2hpbGUodHJ1ZSkge1xuICAgICAgICBjb25zdCBuZXh0U3RyID0gc3RyLnJlcGxhY2Uoc2VhcmNoLCB2YWx1ZSk7XG4gICAgICAgIGlmIChuZXh0U3RyID09PSBzdHIpIHJldHVybiBzdHI7XG4gICAgICAgIHN0ciA9IG5leHRTdHI7XG4gICAgfVxufVxuXG5mdW5jdGlvbiBzZXRDb25maWdWYWx1ZXNSZWN1cnNpdmVseShjb25maWc6IFJlY29yZDxzdHJpbmcsIGFueT4sIHZhbHVlczogUmVjb3JkPHN0cmluZywgc3RyaW5nPikge1xuICAgIGZvciAoY29uc3QgaSBpbiBjb25maWcpIHtcbiAgICAgICAgaWYgKHR5cGVvZiBjb25maWdbaV0gPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICBmb3IgKGNvbnN0IG5hbWUgaW4gdmFsdWVzKSB7XG4gICAgICAgICAgICAgICAgY29uZmlnW2ldID0gcmVwbGFjZUFsbChjb25maWdbaV0sIGBcXCR7JHtuYW1lfX1gLCB2YWx1ZXNbbmFtZV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2UgaWYgKHR5cGVvZiBjb25maWdbaV0gPT09ICdvYmplY3QnICYmIGNvbmZpZ1tpXSkge1xuICAgICAgICAgICAgc2V0Q29uZmlnVmFsdWVzUmVjdXJzaXZlbHkoY29uZmlnW2ldLCB2YWx1ZXMpO1xuICAgICAgICB9XG4gICAgfVxufVxuXG5leHBvcnQgZGVmYXVsdCAoKSA9PiB7XG4gICAgY29uc3QgY29uZmlnID0gbG9hZChnZXRJbnB1dCgnY29uZmlnJykpO1xuICAgIGlmICghY29uZmlnIHx8IHR5cGVvZiBjb25maWcgIT09ICdvYmplY3QnIHx8IEFycmF5LmlzQXJyYXkoY29uZmlnKSkge1xuICAgICAgICBlcnJvcignVW5rbm93biBjb25maWcgb2JqZWN0LiBTaG91bGQgYmUgWUFNTCBvciBKU09OIC1zZXJpYWxpemVkIG9iamVjdCcpO1xuICAgIH1cbiAgICBpbmZvKGBMb2FkZWQgY29uZmlnOlxcbiR7ZHVtcChjb25maWcpfWApO1xuICAgIGNvbnN0IGNvbmZpZ1ZhbHVlcyA9IGdldENvbmZpZ1ZhbHVlcygpO1xuICAgIGluZm8oYExvYWRlZCBjb25maWcgdmFsdWVzOlxcbiR7ZHVtcChjb25maWdWYWx1ZXMpfWApO1xuICAgIHNldENvbmZpZ1ZhbHVlc1JlY3Vyc2l2ZWx5KGNvbmZpZyBhcyBSZWNvcmQ8c3RyaW5nLCBhbnk+LCBjb25maWdWYWx1ZXMpO1xuICAgIGluZm8oYENvbmZpZyB3aXRoIHZhbHVlczpcXG4ke2R1bXAoY29uZmlnKX1gKTtcbiAgICByZXR1cm4gY29uZmlnIGFzIFJlY29yZDxzdHJpbmcsIGFueT47XG59XG4iLCAiXG4vKiEganMteWFtbCA0LjEuMCBodHRwczovL2dpdGh1Yi5jb20vbm9kZWNhL2pzLXlhbWwgQGxpY2Vuc2UgTUlUICovXG5mdW5jdGlvbiBpc05vdGhpbmcoc3ViamVjdCkge1xuICByZXR1cm4gKHR5cGVvZiBzdWJqZWN0ID09PSAndW5kZWZpbmVkJykgfHwgKHN1YmplY3QgPT09IG51bGwpO1xufVxuXG5cbmZ1bmN0aW9uIGlzT2JqZWN0KHN1YmplY3QpIHtcbiAgcmV0dXJuICh0eXBlb2Ygc3ViamVjdCA9PT0gJ29iamVjdCcpICYmIChzdWJqZWN0ICE9PSBudWxsKTtcbn1cblxuXG5mdW5jdGlvbiB0b0FycmF5KHNlcXVlbmNlKSB7XG4gIGlmIChBcnJheS5pc0FycmF5KHNlcXVlbmNlKSkgcmV0dXJuIHNlcXVlbmNlO1xuICBlbHNlIGlmIChpc05vdGhpbmcoc2VxdWVuY2UpKSByZXR1cm4gW107XG5cbiAgcmV0dXJuIFsgc2VxdWVuY2UgXTtcbn1cblxuXG5mdW5jdGlvbiBleHRlbmQodGFyZ2V0LCBzb3VyY2UpIHtcbiAgdmFyIGluZGV4LCBsZW5ndGgsIGtleSwgc291cmNlS2V5cztcblxuICBpZiAoc291cmNlKSB7XG4gICAgc291cmNlS2V5cyA9IE9iamVjdC5rZXlzKHNvdXJjZSk7XG5cbiAgICBmb3IgKGluZGV4ID0gMCwgbGVuZ3RoID0gc291cmNlS2V5cy5sZW5ndGg7IGluZGV4IDwgbGVuZ3RoOyBpbmRleCArPSAxKSB7XG4gICAgICBrZXkgPSBzb3VyY2VLZXlzW2luZGV4XTtcbiAgICAgIHRhcmdldFtrZXldID0gc291cmNlW2tleV07XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHRhcmdldDtcbn1cblxuXG5mdW5jdGlvbiByZXBlYXQoc3RyaW5nLCBjb3VudCkge1xuICB2YXIgcmVzdWx0ID0gJycsIGN5Y2xlO1xuXG4gIGZvciAoY3ljbGUgPSAwOyBjeWNsZSA8IGNvdW50OyBjeWNsZSArPSAxKSB7XG4gICAgcmVzdWx0ICs9IHN0cmluZztcbiAgfVxuXG4gIHJldHVybiByZXN1bHQ7XG59XG5cblxuZnVuY3Rpb24gaXNOZWdhdGl2ZVplcm8obnVtYmVyKSB7XG4gIHJldHVybiAobnVtYmVyID09PSAwKSAmJiAoTnVtYmVyLk5FR0FUSVZFX0lORklOSVRZID09PSAxIC8gbnVtYmVyKTtcbn1cblxuXG52YXIgaXNOb3RoaW5nXzEgICAgICA9IGlzTm90aGluZztcbnZhciBpc09iamVjdF8xICAgICAgID0gaXNPYmplY3Q7XG52YXIgdG9BcnJheV8xICAgICAgICA9IHRvQXJyYXk7XG52YXIgcmVwZWF0XzEgICAgICAgICA9IHJlcGVhdDtcbnZhciBpc05lZ2F0aXZlWmVyb18xID0gaXNOZWdhdGl2ZVplcm87XG52YXIgZXh0ZW5kXzEgICAgICAgICA9IGV4dGVuZDtcblxudmFyIGNvbW1vbiA9IHtcblx0aXNOb3RoaW5nOiBpc05vdGhpbmdfMSxcblx0aXNPYmplY3Q6IGlzT2JqZWN0XzEsXG5cdHRvQXJyYXk6IHRvQXJyYXlfMSxcblx0cmVwZWF0OiByZXBlYXRfMSxcblx0aXNOZWdhdGl2ZVplcm86IGlzTmVnYXRpdmVaZXJvXzEsXG5cdGV4dGVuZDogZXh0ZW5kXzFcbn07XG5cbi8vIFlBTUwgZXJyb3IgY2xhc3MuIGh0dHA6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvODQ1ODk4NFxuXG5cbmZ1bmN0aW9uIGZvcm1hdEVycm9yKGV4Y2VwdGlvbiwgY29tcGFjdCkge1xuICB2YXIgd2hlcmUgPSAnJywgbWVzc2FnZSA9IGV4Y2VwdGlvbi5yZWFzb24gfHwgJyh1bmtub3duIHJlYXNvbiknO1xuXG4gIGlmICghZXhjZXB0aW9uLm1hcmspIHJldHVybiBtZXNzYWdlO1xuXG4gIGlmIChleGNlcHRpb24ubWFyay5uYW1lKSB7XG4gICAgd2hlcmUgKz0gJ2luIFwiJyArIGV4Y2VwdGlvbi5tYXJrLm5hbWUgKyAnXCIgJztcbiAgfVxuXG4gIHdoZXJlICs9ICcoJyArIChleGNlcHRpb24ubWFyay5saW5lICsgMSkgKyAnOicgKyAoZXhjZXB0aW9uLm1hcmsuY29sdW1uICsgMSkgKyAnKSc7XG5cbiAgaWYgKCFjb21wYWN0ICYmIGV4Y2VwdGlvbi5tYXJrLnNuaXBwZXQpIHtcbiAgICB3aGVyZSArPSAnXFxuXFxuJyArIGV4Y2VwdGlvbi5tYXJrLnNuaXBwZXQ7XG4gIH1cblxuICByZXR1cm4gbWVzc2FnZSArICcgJyArIHdoZXJlO1xufVxuXG5cbmZ1bmN0aW9uIFlBTUxFeGNlcHRpb24kMShyZWFzb24sIG1hcmspIHtcbiAgLy8gU3VwZXIgY29uc3RydWN0b3JcbiAgRXJyb3IuY2FsbCh0aGlzKTtcblxuICB0aGlzLm5hbWUgPSAnWUFNTEV4Y2VwdGlvbic7XG4gIHRoaXMucmVhc29uID0gcmVhc29uO1xuICB0aGlzLm1hcmsgPSBtYXJrO1xuICB0aGlzLm1lc3NhZ2UgPSBmb3JtYXRFcnJvcih0aGlzLCBmYWxzZSk7XG5cbiAgLy8gSW5jbHVkZSBzdGFjayB0cmFjZSBpbiBlcnJvciBvYmplY3RcbiAgaWYgKEVycm9yLmNhcHR1cmVTdGFja1RyYWNlKSB7XG4gICAgLy8gQ2hyb21lIGFuZCBOb2RlSlNcbiAgICBFcnJvci5jYXB0dXJlU3RhY2tUcmFjZSh0aGlzLCB0aGlzLmNvbnN0cnVjdG9yKTtcbiAgfSBlbHNlIHtcbiAgICAvLyBGRiwgSUUgMTArIGFuZCBTYWZhcmkgNisuIEZhbGxiYWNrIGZvciBvdGhlcnNcbiAgICB0aGlzLnN0YWNrID0gKG5ldyBFcnJvcigpKS5zdGFjayB8fCAnJztcbiAgfVxufVxuXG5cbi8vIEluaGVyaXQgZnJvbSBFcnJvclxuWUFNTEV4Y2VwdGlvbiQxLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUoRXJyb3IucHJvdG90eXBlKTtcbllBTUxFeGNlcHRpb24kMS5wcm90b3R5cGUuY29uc3RydWN0b3IgPSBZQU1MRXhjZXB0aW9uJDE7XG5cblxuWUFNTEV4Y2VwdGlvbiQxLnByb3RvdHlwZS50b1N0cmluZyA9IGZ1bmN0aW9uIHRvU3RyaW5nKGNvbXBhY3QpIHtcbiAgcmV0dXJuIHRoaXMubmFtZSArICc6ICcgKyBmb3JtYXRFcnJvcih0aGlzLCBjb21wYWN0KTtcbn07XG5cblxudmFyIGV4Y2VwdGlvbiA9IFlBTUxFeGNlcHRpb24kMTtcblxuLy8gZ2V0IHNuaXBwZXQgZm9yIGEgc2luZ2xlIGxpbmUsIHJlc3BlY3RpbmcgbWF4TGVuZ3RoXG5mdW5jdGlvbiBnZXRMaW5lKGJ1ZmZlciwgbGluZVN0YXJ0LCBsaW5lRW5kLCBwb3NpdGlvbiwgbWF4TGluZUxlbmd0aCkge1xuICB2YXIgaGVhZCA9ICcnO1xuICB2YXIgdGFpbCA9ICcnO1xuICB2YXIgbWF4SGFsZkxlbmd0aCA9IE1hdGguZmxvb3IobWF4TGluZUxlbmd0aCAvIDIpIC0gMTtcblxuICBpZiAocG9zaXRpb24gLSBsaW5lU3RhcnQgPiBtYXhIYWxmTGVuZ3RoKSB7XG4gICAgaGVhZCA9ICcgLi4uICc7XG4gICAgbGluZVN0YXJ0ID0gcG9zaXRpb24gLSBtYXhIYWxmTGVuZ3RoICsgaGVhZC5sZW5ndGg7XG4gIH1cblxuICBpZiAobGluZUVuZCAtIHBvc2l0aW9uID4gbWF4SGFsZkxlbmd0aCkge1xuICAgIHRhaWwgPSAnIC4uLic7XG4gICAgbGluZUVuZCA9IHBvc2l0aW9uICsgbWF4SGFsZkxlbmd0aCAtIHRhaWwubGVuZ3RoO1xuICB9XG5cbiAgcmV0dXJuIHtcbiAgICBzdHI6IGhlYWQgKyBidWZmZXIuc2xpY2UobGluZVN0YXJ0LCBsaW5lRW5kKS5yZXBsYWNlKC9cXHQvZywgJ1x1MjE5MicpICsgdGFpbCxcbiAgICBwb3M6IHBvc2l0aW9uIC0gbGluZVN0YXJ0ICsgaGVhZC5sZW5ndGggLy8gcmVsYXRpdmUgcG9zaXRpb25cbiAgfTtcbn1cblxuXG5mdW5jdGlvbiBwYWRTdGFydChzdHJpbmcsIG1heCkge1xuICByZXR1cm4gY29tbW9uLnJlcGVhdCgnICcsIG1heCAtIHN0cmluZy5sZW5ndGgpICsgc3RyaW5nO1xufVxuXG5cbmZ1bmN0aW9uIG1ha2VTbmlwcGV0KG1hcmssIG9wdGlvbnMpIHtcbiAgb3B0aW9ucyA9IE9iamVjdC5jcmVhdGUob3B0aW9ucyB8fCBudWxsKTtcblxuICBpZiAoIW1hcmsuYnVmZmVyKSByZXR1cm4gbnVsbDtcblxuICBpZiAoIW9wdGlvbnMubWF4TGVuZ3RoKSBvcHRpb25zLm1heExlbmd0aCA9IDc5O1xuICBpZiAodHlwZW9mIG9wdGlvbnMuaW5kZW50ICAgICAgIT09ICdudW1iZXInKSBvcHRpb25zLmluZGVudCAgICAgID0gMTtcbiAgaWYgKHR5cGVvZiBvcHRpb25zLmxpbmVzQmVmb3JlICE9PSAnbnVtYmVyJykgb3B0aW9ucy5saW5lc0JlZm9yZSA9IDM7XG4gIGlmICh0eXBlb2Ygb3B0aW9ucy5saW5lc0FmdGVyICAhPT0gJ251bWJlcicpIG9wdGlvbnMubGluZXNBZnRlciAgPSAyO1xuXG4gIHZhciByZSA9IC9cXHI/XFxufFxccnxcXDAvZztcbiAgdmFyIGxpbmVTdGFydHMgPSBbIDAgXTtcbiAgdmFyIGxpbmVFbmRzID0gW107XG4gIHZhciBtYXRjaDtcbiAgdmFyIGZvdW5kTGluZU5vID0gLTE7XG5cbiAgd2hpbGUgKChtYXRjaCA9IHJlLmV4ZWMobWFyay5idWZmZXIpKSkge1xuICAgIGxpbmVFbmRzLnB1c2gobWF0Y2guaW5kZXgpO1xuICAgIGxpbmVTdGFydHMucHVzaChtYXRjaC5pbmRleCArIG1hdGNoWzBdLmxlbmd0aCk7XG5cbiAgICBpZiAobWFyay5wb3NpdGlvbiA8PSBtYXRjaC5pbmRleCAmJiBmb3VuZExpbmVObyA8IDApIHtcbiAgICAgIGZvdW5kTGluZU5vID0gbGluZVN0YXJ0cy5sZW5ndGggLSAyO1xuICAgIH1cbiAgfVxuXG4gIGlmIChmb3VuZExpbmVObyA8IDApIGZvdW5kTGluZU5vID0gbGluZVN0YXJ0cy5sZW5ndGggLSAxO1xuXG4gIHZhciByZXN1bHQgPSAnJywgaSwgbGluZTtcbiAgdmFyIGxpbmVOb0xlbmd0aCA9IE1hdGgubWluKG1hcmsubGluZSArIG9wdGlvbnMubGluZXNBZnRlciwgbGluZUVuZHMubGVuZ3RoKS50b1N0cmluZygpLmxlbmd0aDtcbiAgdmFyIG1heExpbmVMZW5ndGggPSBvcHRpb25zLm1heExlbmd0aCAtIChvcHRpb25zLmluZGVudCArIGxpbmVOb0xlbmd0aCArIDMpO1xuXG4gIGZvciAoaSA9IDE7IGkgPD0gb3B0aW9ucy5saW5lc0JlZm9yZTsgaSsrKSB7XG4gICAgaWYgKGZvdW5kTGluZU5vIC0gaSA8IDApIGJyZWFrO1xuICAgIGxpbmUgPSBnZXRMaW5lKFxuICAgICAgbWFyay5idWZmZXIsXG4gICAgICBsaW5lU3RhcnRzW2ZvdW5kTGluZU5vIC0gaV0sXG4gICAgICBsaW5lRW5kc1tmb3VuZExpbmVObyAtIGldLFxuICAgICAgbWFyay5wb3NpdGlvbiAtIChsaW5lU3RhcnRzW2ZvdW5kTGluZU5vXSAtIGxpbmVTdGFydHNbZm91bmRMaW5lTm8gLSBpXSksXG4gICAgICBtYXhMaW5lTGVuZ3RoXG4gICAgKTtcbiAgICByZXN1bHQgPSBjb21tb24ucmVwZWF0KCcgJywgb3B0aW9ucy5pbmRlbnQpICsgcGFkU3RhcnQoKG1hcmsubGluZSAtIGkgKyAxKS50b1N0cmluZygpLCBsaW5lTm9MZW5ndGgpICtcbiAgICAgICcgfCAnICsgbGluZS5zdHIgKyAnXFxuJyArIHJlc3VsdDtcbiAgfVxuXG4gIGxpbmUgPSBnZXRMaW5lKG1hcmsuYnVmZmVyLCBsaW5lU3RhcnRzW2ZvdW5kTGluZU5vXSwgbGluZUVuZHNbZm91bmRMaW5lTm9dLCBtYXJrLnBvc2l0aW9uLCBtYXhMaW5lTGVuZ3RoKTtcbiAgcmVzdWx0ICs9IGNvbW1vbi5yZXBlYXQoJyAnLCBvcHRpb25zLmluZGVudCkgKyBwYWRTdGFydCgobWFyay5saW5lICsgMSkudG9TdHJpbmcoKSwgbGluZU5vTGVuZ3RoKSArXG4gICAgJyB8ICcgKyBsaW5lLnN0ciArICdcXG4nO1xuICByZXN1bHQgKz0gY29tbW9uLnJlcGVhdCgnLScsIG9wdGlvbnMuaW5kZW50ICsgbGluZU5vTGVuZ3RoICsgMyArIGxpbmUucG9zKSArICdeJyArICdcXG4nO1xuXG4gIGZvciAoaSA9IDE7IGkgPD0gb3B0aW9ucy5saW5lc0FmdGVyOyBpKyspIHtcbiAgICBpZiAoZm91bmRMaW5lTm8gKyBpID49IGxpbmVFbmRzLmxlbmd0aCkgYnJlYWs7XG4gICAgbGluZSA9IGdldExpbmUoXG4gICAgICBtYXJrLmJ1ZmZlcixcbiAgICAgIGxpbmVTdGFydHNbZm91bmRMaW5lTm8gKyBpXSxcbiAgICAgIGxpbmVFbmRzW2ZvdW5kTGluZU5vICsgaV0sXG4gICAgICBtYXJrLnBvc2l0aW9uIC0gKGxpbmVTdGFydHNbZm91bmRMaW5lTm9dIC0gbGluZVN0YXJ0c1tmb3VuZExpbmVObyArIGldKSxcbiAgICAgIG1heExpbmVMZW5ndGhcbiAgICApO1xuICAgIHJlc3VsdCArPSBjb21tb24ucmVwZWF0KCcgJywgb3B0aW9ucy5pbmRlbnQpICsgcGFkU3RhcnQoKG1hcmsubGluZSArIGkgKyAxKS50b1N0cmluZygpLCBsaW5lTm9MZW5ndGgpICtcbiAgICAgICcgfCAnICsgbGluZS5zdHIgKyAnXFxuJztcbiAgfVxuXG4gIHJldHVybiByZXN1bHQucmVwbGFjZSgvXFxuJC8sICcnKTtcbn1cblxuXG52YXIgc25pcHBldCA9IG1ha2VTbmlwcGV0O1xuXG52YXIgVFlQRV9DT05TVFJVQ1RPUl9PUFRJT05TID0gW1xuICAna2luZCcsXG4gICdtdWx0aScsXG4gICdyZXNvbHZlJyxcbiAgJ2NvbnN0cnVjdCcsXG4gICdpbnN0YW5jZU9mJyxcbiAgJ3ByZWRpY2F0ZScsXG4gICdyZXByZXNlbnQnLFxuICAncmVwcmVzZW50TmFtZScsXG4gICdkZWZhdWx0U3R5bGUnLFxuICAnc3R5bGVBbGlhc2VzJ1xuXTtcblxudmFyIFlBTUxfTk9ERV9LSU5EUyA9IFtcbiAgJ3NjYWxhcicsXG4gICdzZXF1ZW5jZScsXG4gICdtYXBwaW5nJ1xuXTtcblxuZnVuY3Rpb24gY29tcGlsZVN0eWxlQWxpYXNlcyhtYXApIHtcbiAgdmFyIHJlc3VsdCA9IHt9O1xuXG4gIGlmIChtYXAgIT09IG51bGwpIHtcbiAgICBPYmplY3Qua2V5cyhtYXApLmZvckVhY2goZnVuY3Rpb24gKHN0eWxlKSB7XG4gICAgICBtYXBbc3R5bGVdLmZvckVhY2goZnVuY3Rpb24gKGFsaWFzKSB7XG4gICAgICAgIHJlc3VsdFtTdHJpbmcoYWxpYXMpXSA9IHN0eWxlO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICByZXR1cm4gcmVzdWx0O1xufVxuXG5mdW5jdGlvbiBUeXBlJDEodGFnLCBvcHRpb25zKSB7XG4gIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gIE9iamVjdC5rZXlzKG9wdGlvbnMpLmZvckVhY2goZnVuY3Rpb24gKG5hbWUpIHtcbiAgICBpZiAoVFlQRV9DT05TVFJVQ1RPUl9PUFRJT05TLmluZGV4T2YobmFtZSkgPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgZXhjZXB0aW9uKCdVbmtub3duIG9wdGlvbiBcIicgKyBuYW1lICsgJ1wiIGlzIG1ldCBpbiBkZWZpbml0aW9uIG9mIFwiJyArIHRhZyArICdcIiBZQU1MIHR5cGUuJyk7XG4gICAgfVxuICB9KTtcblxuICAvLyBUT0RPOiBBZGQgdGFnIGZvcm1hdCBjaGVjay5cbiAgdGhpcy5vcHRpb25zICAgICAgID0gb3B0aW9uczsgLy8ga2VlcCBvcmlnaW5hbCBvcHRpb25zIGluIGNhc2UgdXNlciB3YW50cyB0byBleHRlbmQgdGhpcyB0eXBlIGxhdGVyXG4gIHRoaXMudGFnICAgICAgICAgICA9IHRhZztcbiAgdGhpcy5raW5kICAgICAgICAgID0gb3B0aW9uc1sna2luZCddICAgICAgICAgIHx8IG51bGw7XG4gIHRoaXMucmVzb2x2ZSAgICAgICA9IG9wdGlvbnNbJ3Jlc29sdmUnXSAgICAgICB8fCBmdW5jdGlvbiAoKSB7IHJldHVybiB0cnVlOyB9O1xuICB0aGlzLmNvbnN0cnVjdCAgICAgPSBvcHRpb25zWydjb25zdHJ1Y3QnXSAgICAgfHwgZnVuY3Rpb24gKGRhdGEpIHsgcmV0dXJuIGRhdGE7IH07XG4gIHRoaXMuaW5zdGFuY2VPZiAgICA9IG9wdGlvbnNbJ2luc3RhbmNlT2YnXSAgICB8fCBudWxsO1xuICB0aGlzLnByZWRpY2F0ZSAgICAgPSBvcHRpb25zWydwcmVkaWNhdGUnXSAgICAgfHwgbnVsbDtcbiAgdGhpcy5yZXByZXNlbnQgICAgID0gb3B0aW9uc1sncmVwcmVzZW50J10gICAgIHx8IG51bGw7XG4gIHRoaXMucmVwcmVzZW50TmFtZSA9IG9wdGlvbnNbJ3JlcHJlc2VudE5hbWUnXSB8fCBudWxsO1xuICB0aGlzLmRlZmF1bHRTdHlsZSAgPSBvcHRpb25zWydkZWZhdWx0U3R5bGUnXSAgfHwgbnVsbDtcbiAgdGhpcy5tdWx0aSAgICAgICAgID0gb3B0aW9uc1snbXVsdGknXSAgICAgICAgIHx8IGZhbHNlO1xuICB0aGlzLnN0eWxlQWxpYXNlcyAgPSBjb21waWxlU3R5bGVBbGlhc2VzKG9wdGlvbnNbJ3N0eWxlQWxpYXNlcyddIHx8IG51bGwpO1xuXG4gIGlmIChZQU1MX05PREVfS0lORFMuaW5kZXhPZih0aGlzLmtpbmQpID09PSAtMSkge1xuICAgIHRocm93IG5ldyBleGNlcHRpb24oJ1Vua25vd24ga2luZCBcIicgKyB0aGlzLmtpbmQgKyAnXCIgaXMgc3BlY2lmaWVkIGZvciBcIicgKyB0YWcgKyAnXCIgWUFNTCB0eXBlLicpO1xuICB9XG59XG5cbnZhciB0eXBlID0gVHlwZSQxO1xuXG4vKmVzbGludC1kaXNhYmxlIG1heC1sZW4qL1xuXG5cblxuXG5cbmZ1bmN0aW9uIGNvbXBpbGVMaXN0KHNjaGVtYSwgbmFtZSkge1xuICB2YXIgcmVzdWx0ID0gW107XG5cbiAgc2NoZW1hW25hbWVdLmZvckVhY2goZnVuY3Rpb24gKGN1cnJlbnRUeXBlKSB7XG4gICAgdmFyIG5ld0luZGV4ID0gcmVzdWx0Lmxlbmd0aDtcblxuICAgIHJlc3VsdC5mb3JFYWNoKGZ1bmN0aW9uIChwcmV2aW91c1R5cGUsIHByZXZpb3VzSW5kZXgpIHtcbiAgICAgIGlmIChwcmV2aW91c1R5cGUudGFnID09PSBjdXJyZW50VHlwZS50YWcgJiZcbiAgICAgICAgICBwcmV2aW91c1R5cGUua2luZCA9PT0gY3VycmVudFR5cGUua2luZCAmJlxuICAgICAgICAgIHByZXZpb3VzVHlwZS5tdWx0aSA9PT0gY3VycmVudFR5cGUubXVsdGkpIHtcblxuICAgICAgICBuZXdJbmRleCA9IHByZXZpb3VzSW5kZXg7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICByZXN1bHRbbmV3SW5kZXhdID0gY3VycmVudFR5cGU7XG4gIH0pO1xuXG4gIHJldHVybiByZXN1bHQ7XG59XG5cblxuZnVuY3Rpb24gY29tcGlsZU1hcCgvKiBsaXN0cy4uLiAqLykge1xuICB2YXIgcmVzdWx0ID0ge1xuICAgICAgICBzY2FsYXI6IHt9LFxuICAgICAgICBzZXF1ZW5jZToge30sXG4gICAgICAgIG1hcHBpbmc6IHt9LFxuICAgICAgICBmYWxsYmFjazoge30sXG4gICAgICAgIG11bHRpOiB7XG4gICAgICAgICAgc2NhbGFyOiBbXSxcbiAgICAgICAgICBzZXF1ZW5jZTogW10sXG4gICAgICAgICAgbWFwcGluZzogW10sXG4gICAgICAgICAgZmFsbGJhY2s6IFtdXG4gICAgICAgIH1cbiAgICAgIH0sIGluZGV4LCBsZW5ndGg7XG5cbiAgZnVuY3Rpb24gY29sbGVjdFR5cGUodHlwZSkge1xuICAgIGlmICh0eXBlLm11bHRpKSB7XG4gICAgICByZXN1bHQubXVsdGlbdHlwZS5raW5kXS5wdXNoKHR5cGUpO1xuICAgICAgcmVzdWx0Lm11bHRpWydmYWxsYmFjayddLnB1c2godHlwZSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlc3VsdFt0eXBlLmtpbmRdW3R5cGUudGFnXSA9IHJlc3VsdFsnZmFsbGJhY2snXVt0eXBlLnRhZ10gPSB0eXBlO1xuICAgIH1cbiAgfVxuXG4gIGZvciAoaW5kZXggPSAwLCBsZW5ndGggPSBhcmd1bWVudHMubGVuZ3RoOyBpbmRleCA8IGxlbmd0aDsgaW5kZXggKz0gMSkge1xuICAgIGFyZ3VtZW50c1tpbmRleF0uZm9yRWFjaChjb2xsZWN0VHlwZSk7XG4gIH1cbiAgcmV0dXJuIHJlc3VsdDtcbn1cblxuXG5mdW5jdGlvbiBTY2hlbWEkMShkZWZpbml0aW9uKSB7XG4gIHJldHVybiB0aGlzLmV4dGVuZChkZWZpbml0aW9uKTtcbn1cblxuXG5TY2hlbWEkMS5wcm90b3R5cGUuZXh0ZW5kID0gZnVuY3Rpb24gZXh0ZW5kKGRlZmluaXRpb24pIHtcbiAgdmFyIGltcGxpY2l0ID0gW107XG4gIHZhciBleHBsaWNpdCA9IFtdO1xuXG4gIGlmIChkZWZpbml0aW9uIGluc3RhbmNlb2YgdHlwZSkge1xuICAgIC8vIFNjaGVtYS5leHRlbmQodHlwZSlcbiAgICBleHBsaWNpdC5wdXNoKGRlZmluaXRpb24pO1xuXG4gIH0gZWxzZSBpZiAoQXJyYXkuaXNBcnJheShkZWZpbml0aW9uKSkge1xuICAgIC8vIFNjaGVtYS5leHRlbmQoWyB0eXBlMSwgdHlwZTIsIC4uLiBdKVxuICAgIGV4cGxpY2l0ID0gZXhwbGljaXQuY29uY2F0KGRlZmluaXRpb24pO1xuXG4gIH0gZWxzZSBpZiAoZGVmaW5pdGlvbiAmJiAoQXJyYXkuaXNBcnJheShkZWZpbml0aW9uLmltcGxpY2l0KSB8fCBBcnJheS5pc0FycmF5KGRlZmluaXRpb24uZXhwbGljaXQpKSkge1xuICAgIC8vIFNjaGVtYS5leHRlbmQoeyBleHBsaWNpdDogWyB0eXBlMSwgdHlwZTIsIC4uLiBdLCBpbXBsaWNpdDogWyB0eXBlMSwgdHlwZTIsIC4uLiBdIH0pXG4gICAgaWYgKGRlZmluaXRpb24uaW1wbGljaXQpIGltcGxpY2l0ID0gaW1wbGljaXQuY29uY2F0KGRlZmluaXRpb24uaW1wbGljaXQpO1xuICAgIGlmIChkZWZpbml0aW9uLmV4cGxpY2l0KSBleHBsaWNpdCA9IGV4cGxpY2l0LmNvbmNhdChkZWZpbml0aW9uLmV4cGxpY2l0KTtcblxuICB9IGVsc2Uge1xuICAgIHRocm93IG5ldyBleGNlcHRpb24oJ1NjaGVtYS5leHRlbmQgYXJndW1lbnQgc2hvdWxkIGJlIGEgVHlwZSwgWyBUeXBlIF0sICcgK1xuICAgICAgJ29yIGEgc2NoZW1hIGRlZmluaXRpb24gKHsgaW1wbGljaXQ6IFsuLi5dLCBleHBsaWNpdDogWy4uLl0gfSknKTtcbiAgfVxuXG4gIGltcGxpY2l0LmZvckVhY2goZnVuY3Rpb24gKHR5cGUkMSkge1xuICAgIGlmICghKHR5cGUkMSBpbnN0YW5jZW9mIHR5cGUpKSB7XG4gICAgICB0aHJvdyBuZXcgZXhjZXB0aW9uKCdTcGVjaWZpZWQgbGlzdCBvZiBZQU1MIHR5cGVzIChvciBhIHNpbmdsZSBUeXBlIG9iamVjdCkgY29udGFpbnMgYSBub24tVHlwZSBvYmplY3QuJyk7XG4gICAgfVxuXG4gICAgaWYgKHR5cGUkMS5sb2FkS2luZCAmJiB0eXBlJDEubG9hZEtpbmQgIT09ICdzY2FsYXInKSB7XG4gICAgICB0aHJvdyBuZXcgZXhjZXB0aW9uKCdUaGVyZSBpcyBhIG5vbi1zY2FsYXIgdHlwZSBpbiB0aGUgaW1wbGljaXQgbGlzdCBvZiBhIHNjaGVtYS4gSW1wbGljaXQgcmVzb2x2aW5nIG9mIHN1Y2ggdHlwZXMgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICB9XG5cbiAgICBpZiAodHlwZSQxLm11bHRpKSB7XG4gICAgICB0aHJvdyBuZXcgZXhjZXB0aW9uKCdUaGVyZSBpcyBhIG11bHRpIHR5cGUgaW4gdGhlIGltcGxpY2l0IGxpc3Qgb2YgYSBzY2hlbWEuIE11bHRpIHRhZ3MgY2FuIG9ubHkgYmUgbGlzdGVkIGFzIGV4cGxpY2l0LicpO1xuICAgIH1cbiAgfSk7XG5cbiAgZXhwbGljaXQuZm9yRWFjaChmdW5jdGlvbiAodHlwZSQxKSB7XG4gICAgaWYgKCEodHlwZSQxIGluc3RhbmNlb2YgdHlwZSkpIHtcbiAgICAgIHRocm93IG5ldyBleGNlcHRpb24oJ1NwZWNpZmllZCBsaXN0IG9mIFlBTUwgdHlwZXMgKG9yIGEgc2luZ2xlIFR5cGUgb2JqZWN0KSBjb250YWlucyBhIG5vbi1UeXBlIG9iamVjdC4nKTtcbiAgICB9XG4gIH0pO1xuXG4gIHZhciByZXN1bHQgPSBPYmplY3QuY3JlYXRlKFNjaGVtYSQxLnByb3RvdHlwZSk7XG5cbiAgcmVzdWx0LmltcGxpY2l0ID0gKHRoaXMuaW1wbGljaXQgfHwgW10pLmNvbmNhdChpbXBsaWNpdCk7XG4gIHJlc3VsdC5leHBsaWNpdCA9ICh0aGlzLmV4cGxpY2l0IHx8IFtdKS5jb25jYXQoZXhwbGljaXQpO1xuXG4gIHJlc3VsdC5jb21waWxlZEltcGxpY2l0ID0gY29tcGlsZUxpc3QocmVzdWx0LCAnaW1wbGljaXQnKTtcbiAgcmVzdWx0LmNvbXBpbGVkRXhwbGljaXQgPSBjb21waWxlTGlzdChyZXN1bHQsICdleHBsaWNpdCcpO1xuICByZXN1bHQuY29tcGlsZWRUeXBlTWFwICA9IGNvbXBpbGVNYXAocmVzdWx0LmNvbXBpbGVkSW1wbGljaXQsIHJlc3VsdC5jb21waWxlZEV4cGxpY2l0KTtcblxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuXG52YXIgc2NoZW1hID0gU2NoZW1hJDE7XG5cbnZhciBzdHIgPSBuZXcgdHlwZSgndGFnOnlhbWwub3JnLDIwMDI6c3RyJywge1xuICBraW5kOiAnc2NhbGFyJyxcbiAgY29uc3RydWN0OiBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gZGF0YSAhPT0gbnVsbCA/IGRhdGEgOiAnJzsgfVxufSk7XG5cbnZhciBzZXEgPSBuZXcgdHlwZSgndGFnOnlhbWwub3JnLDIwMDI6c2VxJywge1xuICBraW5kOiAnc2VxdWVuY2UnLFxuICBjb25zdHJ1Y3Q6IGZ1bmN0aW9uIChkYXRhKSB7IHJldHVybiBkYXRhICE9PSBudWxsID8gZGF0YSA6IFtdOyB9XG59KTtcblxudmFyIG1hcCA9IG5ldyB0eXBlKCd0YWc6eWFtbC5vcmcsMjAwMjptYXAnLCB7XG4gIGtpbmQ6ICdtYXBwaW5nJyxcbiAgY29uc3RydWN0OiBmdW5jdGlvbiAoZGF0YSkgeyByZXR1cm4gZGF0YSAhPT0gbnVsbCA/IGRhdGEgOiB7fTsgfVxufSk7XG5cbnZhciBmYWlsc2FmZSA9IG5ldyBzY2hlbWEoe1xuICBleHBsaWNpdDogW1xuICAgIHN0cixcbiAgICBzZXEsXG4gICAgbWFwXG4gIF1cbn0pO1xuXG5mdW5jdGlvbiByZXNvbHZlWWFtbE51bGwoZGF0YSkge1xuICBpZiAoZGF0YSA9PT0gbnVsbCkgcmV0dXJuIHRydWU7XG5cbiAgdmFyIG1heCA9IGRhdGEubGVuZ3RoO1xuXG4gIHJldHVybiAobWF4ID09PSAxICYmIGRhdGEgPT09ICd+JykgfHxcbiAgICAgICAgIChtYXggPT09IDQgJiYgKGRhdGEgPT09ICdudWxsJyB8fCBkYXRhID09PSAnTnVsbCcgfHwgZGF0YSA9PT0gJ05VTEwnKSk7XG59XG5cbmZ1bmN0aW9uIGNvbnN0cnVjdFlhbWxOdWxsKCkge1xuICByZXR1cm4gbnVsbDtcbn1cblxuZnVuY3Rpb24gaXNOdWxsKG9iamVjdCkge1xuICByZXR1cm4gb2JqZWN0ID09PSBudWxsO1xufVxuXG52YXIgX251bGwgPSBuZXcgdHlwZSgndGFnOnlhbWwub3JnLDIwMDI6bnVsbCcsIHtcbiAga2luZDogJ3NjYWxhcicsXG4gIHJlc29sdmU6IHJlc29sdmVZYW1sTnVsbCxcbiAgY29uc3RydWN0OiBjb25zdHJ1Y3RZYW1sTnVsbCxcbiAgcHJlZGljYXRlOiBpc051bGwsXG4gIHJlcHJlc2VudDoge1xuICAgIGNhbm9uaWNhbDogZnVuY3Rpb24gKCkgeyByZXR1cm4gJ34nOyAgICB9LFxuICAgIGxvd2VyY2FzZTogZnVuY3Rpb24gKCkgeyByZXR1cm4gJ251bGwnOyB9LFxuICAgIHVwcGVyY2FzZTogZnVuY3Rpb24gKCkgeyByZXR1cm4gJ05VTEwnOyB9LFxuICAgIGNhbWVsY2FzZTogZnVuY3Rpb24gKCkgeyByZXR1cm4gJ051bGwnOyB9LFxuICAgIGVtcHR5OiAgICAgZnVuY3Rpb24gKCkgeyByZXR1cm4gJyc7ICAgICB9XG4gIH0sXG4gIGRlZmF1bHRTdHlsZTogJ2xvd2VyY2FzZSdcbn0pO1xuXG5mdW5jdGlvbiByZXNvbHZlWWFtbEJvb2xlYW4oZGF0YSkge1xuICBpZiAoZGF0YSA9PT0gbnVsbCkgcmV0dXJuIGZhbHNlO1xuXG4gIHZhciBtYXggPSBkYXRhLmxlbmd0aDtcblxuICByZXR1cm4gKG1heCA9PT0gNCAmJiAoZGF0YSA9PT0gJ3RydWUnIHx8IGRhdGEgPT09ICdUcnVlJyB8fCBkYXRhID09PSAnVFJVRScpKSB8fFxuICAgICAgICAgKG1heCA9PT0gNSAmJiAoZGF0YSA9PT0gJ2ZhbHNlJyB8fCBkYXRhID09PSAnRmFsc2UnIHx8IGRhdGEgPT09ICdGQUxTRScpKTtcbn1cblxuZnVuY3Rpb24gY29uc3RydWN0WWFtbEJvb2xlYW4oZGF0YSkge1xuICByZXR1cm4gZGF0YSA9PT0gJ3RydWUnIHx8XG4gICAgICAgICBkYXRhID09PSAnVHJ1ZScgfHxcbiAgICAgICAgIGRhdGEgPT09ICdUUlVFJztcbn1cblxuZnVuY3Rpb24gaXNCb29sZWFuKG9iamVjdCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKG9iamVjdCkgPT09ICdbb2JqZWN0IEJvb2xlYW5dJztcbn1cblxudmFyIGJvb2wgPSBuZXcgdHlwZSgndGFnOnlhbWwub3JnLDIwMDI6Ym9vbCcsIHtcbiAga2luZDogJ3NjYWxhcicsXG4gIHJlc29sdmU6IHJlc29sdmVZYW1sQm9vbGVhbixcbiAgY29uc3RydWN0OiBjb25zdHJ1Y3RZYW1sQm9vbGVhbixcbiAgcHJlZGljYXRlOiBpc0Jvb2xlYW4sXG4gIHJlcHJlc2VudDoge1xuICAgIGxvd2VyY2FzZTogZnVuY3Rpb24gKG9iamVjdCkgeyByZXR1cm4gb2JqZWN0ID8gJ3RydWUnIDogJ2ZhbHNlJzsgfSxcbiAgICB1cHBlcmNhc2U6IGZ1bmN0aW9uIChvYmplY3QpIHsgcmV0dXJuIG9iamVjdCA/ICdUUlVFJyA6ICdGQUxTRSc7IH0sXG4gICAgY2FtZWxjYXNlOiBmdW5jdGlvbiAob2JqZWN0KSB7IHJldHVybiBvYmplY3QgPyAnVHJ1ZScgOiAnRmFsc2UnOyB9XG4gIH0sXG4gIGRlZmF1bHRTdHlsZTogJ2xvd2VyY2FzZSdcbn0pO1xuXG5mdW5jdGlvbiBpc0hleENvZGUoYykge1xuICByZXR1cm4gKCgweDMwLyogMCAqLyA8PSBjKSAmJiAoYyA8PSAweDM5LyogOSAqLykpIHx8XG4gICAgICAgICAoKDB4NDEvKiBBICovIDw9IGMpICYmIChjIDw9IDB4NDYvKiBGICovKSkgfHxcbiAgICAgICAgICgoMHg2MS8qIGEgKi8gPD0gYykgJiYgKGMgPD0gMHg2Ni8qIGYgKi8pKTtcbn1cblxuZnVuY3Rpb24gaXNPY3RDb2RlKGMpIHtcbiAgcmV0dXJuICgoMHgzMC8qIDAgKi8gPD0gYykgJiYgKGMgPD0gMHgzNy8qIDcgKi8pKTtcbn1cblxuZnVuY3Rpb24gaXNEZWNDb2RlKGMpIHtcbiAgcmV0dXJuICgoMHgzMC8qIDAgKi8gPD0gYykgJiYgKGMgPD0gMHgzOS8qIDkgKi8pKTtcbn1cblxuZnVuY3Rpb24gcmVzb2x2ZVlhbWxJbnRlZ2VyKGRhdGEpIHtcbiAgaWYgKGRhdGEgPT09IG51bGwpIHJldHVybiBmYWxzZTtcblxuICB2YXIgbWF4ID0gZGF0YS5sZW5ndGgsXG4gICAgICBpbmRleCA9IDAsXG4gICAgICBoYXNEaWdpdHMgPSBmYWxzZSxcbiAgICAgIGNoO1xuXG4gIGlmICghbWF4KSByZXR1cm4gZmFsc2U7XG5cbiAgY2ggPSBkYXRhW2luZGV4XTtcblxuICAvLyBzaWduXG4gIGlmIChjaCA9PT0gJy0nIHx8IGNoID09PSAnKycpIHtcbiAgICBjaCA9IGRhdGFbKytpbmRleF07XG4gIH1cblxuICBpZiAoY2ggPT09ICcwJykge1xuICAgIC8vIDBcbiAgICBpZiAoaW5kZXggKyAxID09PSBtYXgpIHJldHVybiB0cnVlO1xuICAgIGNoID0gZGF0YVsrK2luZGV4XTtcblxuICAgIC8vIGJhc2UgMiwgYmFzZSA4LCBiYXNlIDE2XG5cbiAgICBpZiAoY2ggPT09ICdiJykge1xuICAgICAgLy8gYmFzZSAyXG4gICAgICBpbmRleCsrO1xuXG4gICAgICBmb3IgKDsgaW5kZXggPCBtYXg7IGluZGV4KyspIHtcbiAgICAgICAgY2ggPSBkYXRhW2luZGV4XTtcbiAgICAgICAgaWYgKGNoID09PSAnXycpIGNvbnRpbnVlO1xuICAgICAgICBpZiAoY2ggIT09ICcwJyAmJiBjaCAhPT0gJzEnKSByZXR1cm4gZmFsc2U7XG4gICAgICAgIGhhc0RpZ2l0cyA9IHRydWU7XG4gICAgICB9XG4gICAgICByZXR1cm4gaGFzRGlnaXRzICYmIGNoICE9PSAnXyc7XG4gICAgfVxuXG5cbiAgICBpZiAoY2ggPT09ICd4Jykge1xuICAgICAgLy8gYmFzZSAxNlxuICAgICAgaW5kZXgrKztcblxuICAgICAgZm9yICg7IGluZGV4IDwgbWF4OyBpbmRleCsrKSB7XG4gICAgICAgIGNoID0gZGF0YVtpbmRleF07XG4gICAgICAgIGlmIChjaCA9PT0gJ18nKSBjb250aW51ZTtcbiAgICAgICAgaWYgKCFpc0hleENvZGUoZGF0YS5jaGFyQ29kZUF0KGluZGV4KSkpIHJldHVybiBmYWxzZTtcbiAgICAgICAgaGFzRGlnaXRzID0gdHJ1ZTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBoYXNEaWdpdHMgJiYgY2ggIT09ICdfJztcbiAgICB9XG5cblxuICAgIGlmIChjaCA9PT0gJ28nKSB7XG4gICAgICAvLyBiYXNlIDhcbiAgICAgIGluZGV4Kys7XG5cbiAgICAgIGZvciAoOyBpbmRleCA8IG1heDsgaW5kZXgrKykge1xuICAgICAgICBjaCA9IGRhdGFbaW5kZXhdO1xuICAgICAgICBpZiAoY2ggPT09ICdfJykgY29udGludWU7XG4gICAgICAgIGlmICghaXNPY3RDb2RlKGRhdGEuY2hhckNvZGVBdChpbmRleCkpKSByZXR1cm4gZmFsc2U7XG4gICAgICAgIGhhc0RpZ2l0cyA9IHRydWU7XG4gICAgICB9XG4gICAgICByZXR1cm4gaGFzRGlnaXRzICYmIGNoICE9PSAnXyc7XG4gICAgfVxuICB9XG5cbiAgLy8gYmFzZSAxMCAoZXhjZXB0IDApXG5cbiAgLy8gdmFsdWUgc2hvdWxkIG5vdCBzdGFydCB3aXRoIGBfYDtcbiAgaWYgKGNoID09PSAnXycpIHJldHVybiBmYWxzZTtcblxuICBmb3IgKDsgaW5kZXggPCBtYXg7IGluZGV4KyspIHtcbiAgICBjaCA9IGRhdGFbaW5kZXhdO1xuICAgIGlmIChjaCA9PT0gJ18nKSBjb250aW51ZTtcbiAgICBpZiAoIWlzRGVjQ29kZShkYXRhLmNoYXJDb2RlQXQoaW5kZXgpKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICBoYXNEaWdpdHMgPSB0cnVlO1xuICB9XG5cbiAgLy8gU2hvdWxkIGhhdmUgZGlnaXRzIGFuZCBzaG91bGQgbm90IGVuZCB3aXRoIGBfYFxuICBpZiAoIWhhc0RpZ2l0cyB8fCBjaCA9PT0gJ18nKSByZXR1cm4gZmFsc2U7XG5cbiAgcmV0dXJuIHRydWU7XG59XG5cbmZ1bmN0aW9uIGNvbnN0cnVjdFlhbWxJbnRlZ2VyKGRhdGEpIHtcbiAgdmFyIHZhbHVlID0gZGF0YSwgc2lnbiA9IDEsIGNoO1xuXG4gIGlmICh2YWx1ZS5pbmRleE9mKCdfJykgIT09IC0xKSB7XG4gICAgdmFsdWUgPSB2YWx1ZS5yZXBsYWNlKC9fL2csICcnKTtcbiAgfVxuXG4gIGNoID0gdmFsdWVbMF07XG5cbiAgaWYgKGNoID09PSAnLScgfHwgY2ggPT09ICcrJykge1xuICAgIGlmIChjaCA9PT0gJy0nKSBzaWduID0gLTE7XG4gICAgdmFsdWUgPSB2YWx1ZS5zbGljZSgxKTtcbiAgICBjaCA9IHZhbHVlWzBdO1xuICB9XG5cbiAgaWYgKHZhbHVlID09PSAnMCcpIHJldHVybiAwO1xuXG4gIGlmIChjaCA9PT0gJzAnKSB7XG4gICAgaWYgKHZhbHVlWzFdID09PSAnYicpIHJldHVybiBzaWduICogcGFyc2VJbnQodmFsdWUuc2xpY2UoMiksIDIpO1xuICAgIGlmICh2YWx1ZVsxXSA9PT0gJ3gnKSByZXR1cm4gc2lnbiAqIHBhcnNlSW50KHZhbHVlLnNsaWNlKDIpLCAxNik7XG4gICAgaWYgKHZhbHVlWzFdID09PSAnbycpIHJldHVybiBzaWduICogcGFyc2VJbnQodmFsdWUuc2xpY2UoMiksIDgpO1xuICB9XG5cbiAgcmV0dXJuIHNpZ24gKiBwYXJzZUludCh2YWx1ZSwgMTApO1xufVxuXG5mdW5jdGlvbiBpc0ludGVnZXIob2JqZWN0KSB7XG4gIHJldHVybiAoT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKG9iamVjdCkpID09PSAnW29iamVjdCBOdW1iZXJdJyAmJlxuICAgICAgICAgKG9iamVjdCAlIDEgPT09IDAgJiYgIWNvbW1vbi5pc05lZ2F0aXZlWmVybyhvYmplY3QpKTtcbn1cblxudmFyIGludCA9IG5ldyB0eXBlKCd0YWc6eWFtbC5vcmcsMjAwMjppbnQnLCB7XG4gIGtpbmQ6ICdzY2FsYXInLFxuICByZXNvbHZlOiByZXNvbHZlWWFtbEludGVnZXIsXG4gIGNvbnN0cnVjdDogY29uc3RydWN0WWFtbEludGVnZXIsXG4gIHByZWRpY2F0ZTogaXNJbnRlZ2VyLFxuICByZXByZXNlbnQ6IHtcbiAgICBiaW5hcnk6ICAgICAgZnVuY3Rpb24gKG9iaikgeyByZXR1cm4gb2JqID49IDAgPyAnMGInICsgb2JqLnRvU3RyaW5nKDIpIDogJy0wYicgKyBvYmoudG9TdHJpbmcoMikuc2xpY2UoMSk7IH0sXG4gICAgb2N0YWw6ICAgICAgIGZ1bmN0aW9uIChvYmopIHsgcmV0dXJuIG9iaiA+PSAwID8gJzBvJyAgKyBvYmoudG9TdHJpbmcoOCkgOiAnLTBvJyAgKyBvYmoudG9TdHJpbmcoOCkuc2xpY2UoMSk7IH0sXG4gICAgZGVjaW1hbDogICAgIGZ1bmN0aW9uIChvYmopIHsgcmV0dXJuIG9iai50b1N0cmluZygxMCk7IH0sXG4gICAgLyogZXNsaW50LWRpc2FibGUgbWF4LWxlbiAqL1xuICAgIGhleGFkZWNpbWFsOiBmdW5jdGlvbiAob2JqKSB7IHJldHVybiBvYmogPj0gMCA/ICcweCcgKyBvYmoudG9TdHJpbmcoMTYpLnRvVXBwZXJDYXNlKCkgOiAgJy0weCcgKyBvYmoudG9TdHJpbmcoMTYpLnRvVXBwZXJDYXNlKCkuc2xpY2UoMSk7IH1cbiAgfSxcbiAgZGVmYXVsdFN0eWxlOiAnZGVjaW1hbCcsXG4gIHN0eWxlQWxpYXNlczoge1xuICAgIGJpbmFyeTogICAgICBbIDIsICAnYmluJyBdLFxuICAgIG9jdGFsOiAgICAgICBbIDgsICAnb2N0JyBdLFxuICAgIGRlY2ltYWw6ICAgICBbIDEwLCAnZGVjJyBdLFxuICAgIGhleGFkZWNpbWFsOiBbIDE2LCAnaGV4JyBdXG4gIH1cbn0pO1xuXG52YXIgWUFNTF9GTE9BVF9QQVRURVJOID0gbmV3IFJlZ0V4cChcbiAgLy8gMi41ZTQsIDIuNSBhbmQgaW50ZWdlcnNcbiAgJ14oPzpbLStdPyg/OlswLTldWzAtOV9dKikoPzpcXFxcLlswLTlfXSopPyg/OltlRV1bLStdP1swLTldKyk/JyArXG4gIC8vIC4yZTQsIC4yXG4gIC8vIHNwZWNpYWwgY2FzZSwgc2VlbXMgbm90IGZyb20gc3BlY1xuICAnfFxcXFwuWzAtOV9dKyg/OltlRV1bLStdP1swLTldKyk/JyArXG4gIC8vIC5pbmZcbiAgJ3xbLStdP1xcXFwuKD86aW5mfEluZnxJTkYpJyArXG4gIC8vIC5uYW5cbiAgJ3xcXFxcLig/Om5hbnxOYU58TkFOKSkkJyk7XG5cbmZ1bmN0aW9uIHJlc29sdmVZYW1sRmxvYXQoZGF0YSkge1xuICBpZiAoZGF0YSA9PT0gbnVsbCkgcmV0dXJuIGZhbHNlO1xuXG4gIGlmICghWUFNTF9GTE9BVF9QQVRURVJOLnRlc3QoZGF0YSkgfHxcbiAgICAgIC8vIFF1aWNrIGhhY2sgdG8gbm90IGFsbG93IGludGVnZXJzIGVuZCB3aXRoIGBfYFxuICAgICAgLy8gUHJvYmFibHkgc2hvdWxkIHVwZGF0ZSByZWdleHAgJiBjaGVjayBzcGVlZFxuICAgICAgZGF0YVtkYXRhLmxlbmd0aCAtIDFdID09PSAnXycpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICByZXR1cm4gdHJ1ZTtcbn1cblxuZnVuY3Rpb24gY29uc3RydWN0WWFtbEZsb2F0KGRhdGEpIHtcbiAgdmFyIHZhbHVlLCBzaWduO1xuXG4gIHZhbHVlICA9IGRhdGEucmVwbGFjZSgvXy9nLCAnJykudG9Mb3dlckNhc2UoKTtcbiAgc2lnbiAgID0gdmFsdWVbMF0gPT09ICctJyA/IC0xIDogMTtcblxuICBpZiAoJystJy5pbmRleE9mKHZhbHVlWzBdKSA+PSAwKSB7XG4gICAgdmFsdWUgPSB2YWx1ZS5zbGljZSgxKTtcbiAgfVxuXG4gIGlmICh2YWx1ZSA9PT0gJy5pbmYnKSB7XG4gICAgcmV0dXJuIChzaWduID09PSAxKSA/IE51bWJlci5QT1NJVElWRV9JTkZJTklUWSA6IE51bWJlci5ORUdBVElWRV9JTkZJTklUWTtcblxuICB9IGVsc2UgaWYgKHZhbHVlID09PSAnLm5hbicpIHtcbiAgICByZXR1cm4gTmFOO1xuICB9XG4gIHJldHVybiBzaWduICogcGFyc2VGbG9hdCh2YWx1ZSwgMTApO1xufVxuXG5cbnZhciBTQ0lFTlRJRklDX1dJVEhPVVRfRE9UID0gL15bLStdP1swLTldK2UvO1xuXG5mdW5jdGlvbiByZXByZXNlbnRZYW1sRmxvYXQob2JqZWN0LCBzdHlsZSkge1xuICB2YXIgcmVzO1xuXG4gIGlmIChpc05hTihvYmplY3QpKSB7XG4gICAgc3dpdGNoIChzdHlsZSkge1xuICAgICAgY2FzZSAnbG93ZXJjYXNlJzogcmV0dXJuICcubmFuJztcbiAgICAgIGNhc2UgJ3VwcGVyY2FzZSc6IHJldHVybiAnLk5BTic7XG4gICAgICBjYXNlICdjYW1lbGNhc2UnOiByZXR1cm4gJy5OYU4nO1xuICAgIH1cbiAgfSBlbHNlIGlmIChOdW1iZXIuUE9TSVRJVkVfSU5GSU5JVFkgPT09IG9iamVjdCkge1xuICAgIHN3aXRjaCAoc3R5bGUpIHtcbiAgICAgIGNhc2UgJ2xvd2VyY2FzZSc6IHJldHVybiAnLmluZic7XG4gICAgICBjYXNlICd1cHBlcmNhc2UnOiByZXR1cm4gJy5JTkYnO1xuICAgICAgY2FzZSAnY2FtZWxjYXNlJzogcmV0dXJuICcuSW5mJztcbiAgICB9XG4gIH0gZWxzZSBpZiAoTnVtYmVyLk5FR0FUSVZFX0lORklOSVRZID09PSBvYmplY3QpIHtcbiAgICBzd2l0Y2ggKHN0eWxlKSB7XG4gICAgICBjYXNlICdsb3dlcmNhc2UnOiByZXR1cm4gJy0uaW5mJztcbiAgICAgIGNhc2UgJ3VwcGVyY2FzZSc6IHJldHVybiAnLS5JTkYnO1xuICAgICAgY2FzZSAnY2FtZWxjYXNlJzogcmV0dXJuICctLkluZic7XG4gICAgfVxuICB9IGVsc2UgaWYgKGNvbW1vbi5pc05lZ2F0aXZlWmVybyhvYmplY3QpKSB7XG4gICAgcmV0dXJuICctMC4wJztcbiAgfVxuXG4gIHJlcyA9IG9iamVjdC50b1N0cmluZygxMCk7XG5cbiAgLy8gSlMgc3RyaW5naWZpZXIgY2FuIGJ1aWxkIHNjaWVudGlmaWMgZm9ybWF0IHdpdGhvdXQgZG90czogNWUtMTAwLFxuICAvLyB3aGlsZSBZQU1MIHJlcXVyZXMgZG90OiA1LmUtMTAwLiBGaXggaXQgd2l0aCBzaW1wbGUgaGFja1xuXG4gIHJldHVybiBTQ0lFTlRJRklDX1dJVEhPVVRfRE9ULnRlc3QocmVzKSA/IHJlcy5yZXBsYWNlKCdlJywgJy5lJykgOiByZXM7XG59XG5cbmZ1bmN0aW9uIGlzRmxvYXQob2JqZWN0KSB7XG4gIHJldHVybiAoT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKG9iamVjdCkgPT09ICdbb2JqZWN0IE51bWJlcl0nKSAmJlxuICAgICAgICAgKG9iamVjdCAlIDEgIT09IDAgfHwgY29tbW9uLmlzTmVnYXRpdmVaZXJvKG9iamVjdCkpO1xufVxuXG52YXIgZmxvYXQgPSBuZXcgdHlwZSgndGFnOnlhbWwub3JnLDIwMDI6ZmxvYXQnLCB7XG4gIGtpbmQ6ICdzY2FsYXInLFxuICByZXNvbHZlOiByZXNvbHZlWWFtbEZsb2F0LFxuICBjb25zdHJ1Y3Q6IGNvbnN0cnVjdFlhbWxGbG9hdCxcbiAgcHJlZGljYXRlOiBpc0Zsb2F0LFxuICByZXByZXNlbnQ6IHJlcHJlc2VudFlhbWxGbG9hdCxcbiAgZGVmYXVsdFN0eWxlOiAnbG93ZXJjYXNlJ1xufSk7XG5cbnZhciBqc29uID0gZmFpbHNhZmUuZXh0ZW5kKHtcbiAgaW1wbGljaXQ6IFtcbiAgICBfbnVsbCxcbiAgICBib29sLFxuICAgIGludCxcbiAgICBmbG9hdFxuICBdXG59KTtcblxudmFyIGNvcmUgPSBqc29uO1xuXG52YXIgWUFNTF9EQVRFX1JFR0VYUCA9IG5ldyBSZWdFeHAoXG4gICdeKFswLTldWzAtOV1bMC05XVswLTldKScgICAgICAgICAgKyAvLyBbMV0geWVhclxuICAnLShbMC05XVswLTldKScgICAgICAgICAgICAgICAgICAgICsgLy8gWzJdIG1vbnRoXG4gICctKFswLTldWzAtOV0pJCcpOyAgICAgICAgICAgICAgICAgICAvLyBbM10gZGF5XG5cbnZhciBZQU1MX1RJTUVTVEFNUF9SRUdFWFAgPSBuZXcgUmVnRXhwKFxuICAnXihbMC05XVswLTldWzAtOV1bMC05XSknICAgICAgICAgICsgLy8gWzFdIHllYXJcbiAgJy0oWzAtOV1bMC05XT8pJyAgICAgICAgICAgICAgICAgICArIC8vIFsyXSBtb250aFxuICAnLShbMC05XVswLTldPyknICAgICAgICAgICAgICAgICAgICsgLy8gWzNdIGRheVxuICAnKD86W1R0XXxbIFxcXFx0XSspJyAgICAgICAgICAgICAgICAgKyAvLyAuLi5cbiAgJyhbMC05XVswLTldPyknICAgICAgICAgICAgICAgICAgICArIC8vIFs0XSBob3VyXG4gICc6KFswLTldWzAtOV0pJyAgICAgICAgICAgICAgICAgICAgKyAvLyBbNV0gbWludXRlXG4gICc6KFswLTldWzAtOV0pJyAgICAgICAgICAgICAgICAgICAgKyAvLyBbNl0gc2Vjb25kXG4gICcoPzpcXFxcLihbMC05XSopKT8nICAgICAgICAgICAgICAgICArIC8vIFs3XSBmcmFjdGlvblxuICAnKD86WyBcXFxcdF0qKFp8KFstK10pKFswLTldWzAtOV0/KScgKyAvLyBbOF0gdHogWzldIHR6X3NpZ24gWzEwXSB0el9ob3VyXG4gICcoPzo6KFswLTldWzAtOV0pKT8pKT8kJyk7ICAgICAgICAgICAvLyBbMTFdIHR6X21pbnV0ZVxuXG5mdW5jdGlvbiByZXNvbHZlWWFtbFRpbWVzdGFtcChkYXRhKSB7XG4gIGlmIChkYXRhID09PSBudWxsKSByZXR1cm4gZmFsc2U7XG4gIGlmIChZQU1MX0RBVEVfUkVHRVhQLmV4ZWMoZGF0YSkgIT09IG51bGwpIHJldHVybiB0cnVlO1xuICBpZiAoWUFNTF9USU1FU1RBTVBfUkVHRVhQLmV4ZWMoZGF0YSkgIT09IG51bGwpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59XG5cbmZ1bmN0aW9uIGNvbnN0cnVjdFlhbWxUaW1lc3RhbXAoZGF0YSkge1xuICB2YXIgbWF0Y2gsIHllYXIsIG1vbnRoLCBkYXksIGhvdXIsIG1pbnV0ZSwgc2Vjb25kLCBmcmFjdGlvbiA9IDAsXG4gICAgICBkZWx0YSA9IG51bGwsIHR6X2hvdXIsIHR6X21pbnV0ZSwgZGF0ZTtcblxuICBtYXRjaCA9IFlBTUxfREFURV9SRUdFWFAuZXhlYyhkYXRhKTtcbiAgaWYgKG1hdGNoID09PSBudWxsKSBtYXRjaCA9IFlBTUxfVElNRVNUQU1QX1JFR0VYUC5leGVjKGRhdGEpO1xuXG4gIGlmIChtYXRjaCA9PT0gbnVsbCkgdGhyb3cgbmV3IEVycm9yKCdEYXRlIHJlc29sdmUgZXJyb3InKTtcblxuICAvLyBtYXRjaDogWzFdIHllYXIgWzJdIG1vbnRoIFszXSBkYXlcblxuICB5ZWFyID0gKyhtYXRjaFsxXSk7XG4gIG1vbnRoID0gKyhtYXRjaFsyXSkgLSAxOyAvLyBKUyBtb250aCBzdGFydHMgd2l0aCAwXG4gIGRheSA9ICsobWF0Y2hbM10pO1xuXG4gIGlmICghbWF0Y2hbNF0pIHsgLy8gbm8gaG91clxuICAgIHJldHVybiBuZXcgRGF0ZShEYXRlLlVUQyh5ZWFyLCBtb250aCwgZGF5KSk7XG4gIH1cblxuICAvLyBtYXRjaDogWzRdIGhvdXIgWzVdIG1pbnV0ZSBbNl0gc2Vjb25kIFs3XSBmcmFjdGlvblxuXG4gIGhvdXIgPSArKG1hdGNoWzRdKTtcbiAgbWludXRlID0gKyhtYXRjaFs1XSk7XG4gIHNlY29uZCA9ICsobWF0Y2hbNl0pO1xuXG4gIGlmIChtYXRjaFs3XSkge1xuICAgIGZyYWN0aW9uID0gbWF0Y2hbN10uc2xpY2UoMCwgMyk7XG4gICAgd2hpbGUgKGZyYWN0aW9uLmxlbmd0aCA8IDMpIHsgLy8gbWlsbGktc2Vjb25kc1xuICAgICAgZnJhY3Rpb24gKz0gJzAnO1xuICAgIH1cbiAgICBmcmFjdGlvbiA9ICtmcmFjdGlvbjtcbiAgfVxuXG4gIC8vIG1hdGNoOiBbOF0gdHogWzldIHR6X3NpZ24gWzEwXSB0el9ob3VyIFsxMV0gdHpfbWludXRlXG5cbiAgaWYgKG1hdGNoWzldKSB7XG4gICAgdHpfaG91ciA9ICsobWF0Y2hbMTBdKTtcbiAgICB0el9taW51dGUgPSArKG1hdGNoWzExXSB8fCAwKTtcbiAgICBkZWx0YSA9ICh0el9ob3VyICogNjAgKyB0el9taW51dGUpICogNjAwMDA7IC8vIGRlbHRhIGluIG1pbGktc2Vjb25kc1xuICAgIGlmIChtYXRjaFs5XSA9PT0gJy0nKSBkZWx0YSA9IC1kZWx0YTtcbiAgfVxuXG4gIGRhdGUgPSBuZXcgRGF0ZShEYXRlLlVUQyh5ZWFyLCBtb250aCwgZGF5LCBob3VyLCBtaW51dGUsIHNlY29uZCwgZnJhY3Rpb24pKTtcblxuICBpZiAoZGVsdGEpIGRhdGUuc2V0VGltZShkYXRlLmdldFRpbWUoKSAtIGRlbHRhKTtcblxuICByZXR1cm4gZGF0ZTtcbn1cblxuZnVuY3Rpb24gcmVwcmVzZW50WWFtbFRpbWVzdGFtcChvYmplY3QgLyosIHN0eWxlKi8pIHtcbiAgcmV0dXJuIG9iamVjdC50b0lTT1N0cmluZygpO1xufVxuXG52YXIgdGltZXN0YW1wID0gbmV3IHR5cGUoJ3RhZzp5YW1sLm9yZywyMDAyOnRpbWVzdGFtcCcsIHtcbiAga2luZDogJ3NjYWxhcicsXG4gIHJlc29sdmU6IHJlc29sdmVZYW1sVGltZXN0YW1wLFxuICBjb25zdHJ1Y3Q6IGNvbnN0cnVjdFlhbWxUaW1lc3RhbXAsXG4gIGluc3RhbmNlT2Y6IERhdGUsXG4gIHJlcHJlc2VudDogcmVwcmVzZW50WWFtbFRpbWVzdGFtcFxufSk7XG5cbmZ1bmN0aW9uIHJlc29sdmVZYW1sTWVyZ2UoZGF0YSkge1xuICByZXR1cm4gZGF0YSA9PT0gJzw8JyB8fCBkYXRhID09PSBudWxsO1xufVxuXG52YXIgbWVyZ2UgPSBuZXcgdHlwZSgndGFnOnlhbWwub3JnLDIwMDI6bWVyZ2UnLCB7XG4gIGtpbmQ6ICdzY2FsYXInLFxuICByZXNvbHZlOiByZXNvbHZlWWFtbE1lcmdlXG59KTtcblxuLyplc2xpbnQtZGlzYWJsZSBuby1iaXR3aXNlKi9cblxuXG5cblxuXG4vLyBbIDY0LCA2NSwgNjYgXSAtPiBbIHBhZGRpbmcsIENSLCBMRiBdXG52YXIgQkFTRTY0X01BUCA9ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPVxcblxccic7XG5cblxuZnVuY3Rpb24gcmVzb2x2ZVlhbWxCaW5hcnkoZGF0YSkge1xuICBpZiAoZGF0YSA9PT0gbnVsbCkgcmV0dXJuIGZhbHNlO1xuXG4gIHZhciBjb2RlLCBpZHgsIGJpdGxlbiA9IDAsIG1heCA9IGRhdGEubGVuZ3RoLCBtYXAgPSBCQVNFNjRfTUFQO1xuXG4gIC8vIENvbnZlcnQgb25lIGJ5IG9uZS5cbiAgZm9yIChpZHggPSAwOyBpZHggPCBtYXg7IGlkeCsrKSB7XG4gICAgY29kZSA9IG1hcC5pbmRleE9mKGRhdGEuY2hhckF0KGlkeCkpO1xuXG4gICAgLy8gU2tpcCBDUi9MRlxuICAgIGlmIChjb2RlID4gNjQpIGNvbnRpbnVlO1xuXG4gICAgLy8gRmFpbCBvbiBpbGxlZ2FsIGNoYXJhY3RlcnNcbiAgICBpZiAoY29kZSA8IDApIHJldHVybiBmYWxzZTtcblxuICAgIGJpdGxlbiArPSA2O1xuICB9XG5cbiAgLy8gSWYgdGhlcmUgYXJlIGFueSBiaXRzIGxlZnQsIHNvdXJjZSB3YXMgY29ycnVwdGVkXG4gIHJldHVybiAoYml0bGVuICUgOCkgPT09IDA7XG59XG5cbmZ1bmN0aW9uIGNvbnN0cnVjdFlhbWxCaW5hcnkoZGF0YSkge1xuICB2YXIgaWR4LCB0YWlsYml0cyxcbiAgICAgIGlucHV0ID0gZGF0YS5yZXBsYWNlKC9bXFxyXFxuPV0vZywgJycpLCAvLyByZW1vdmUgQ1IvTEYgJiBwYWRkaW5nIHRvIHNpbXBsaWZ5IHNjYW5cbiAgICAgIG1heCA9IGlucHV0Lmxlbmd0aCxcbiAgICAgIG1hcCA9IEJBU0U2NF9NQVAsXG4gICAgICBiaXRzID0gMCxcbiAgICAgIHJlc3VsdCA9IFtdO1xuXG4gIC8vIENvbGxlY3QgYnkgNio0IGJpdHMgKDMgYnl0ZXMpXG5cbiAgZm9yIChpZHggPSAwOyBpZHggPCBtYXg7IGlkeCsrKSB7XG4gICAgaWYgKChpZHggJSA0ID09PSAwKSAmJiBpZHgpIHtcbiAgICAgIHJlc3VsdC5wdXNoKChiaXRzID4+IDE2KSAmIDB4RkYpO1xuICAgICAgcmVzdWx0LnB1c2goKGJpdHMgPj4gOCkgJiAweEZGKTtcbiAgICAgIHJlc3VsdC5wdXNoKGJpdHMgJiAweEZGKTtcbiAgICB9XG5cbiAgICBiaXRzID0gKGJpdHMgPDwgNikgfCBtYXAuaW5kZXhPZihpbnB1dC5jaGFyQXQoaWR4KSk7XG4gIH1cblxuICAvLyBEdW1wIHRhaWxcblxuICB0YWlsYml0cyA9IChtYXggJSA0KSAqIDY7XG5cbiAgaWYgKHRhaWxiaXRzID09PSAwKSB7XG4gICAgcmVzdWx0LnB1c2goKGJpdHMgPj4gMTYpICYgMHhGRik7XG4gICAgcmVzdWx0LnB1c2goKGJpdHMgPj4gOCkgJiAweEZGKTtcbiAgICByZXN1bHQucHVzaChiaXRzICYgMHhGRik7XG4gIH0gZWxzZSBpZiAodGFpbGJpdHMgPT09IDE4KSB7XG4gICAgcmVzdWx0LnB1c2goKGJpdHMgPj4gMTApICYgMHhGRik7XG4gICAgcmVzdWx0LnB1c2goKGJpdHMgPj4gMikgJiAweEZGKTtcbiAgfSBlbHNlIGlmICh0YWlsYml0cyA9PT0gMTIpIHtcbiAgICByZXN1bHQucHVzaCgoYml0cyA+PiA0KSAmIDB4RkYpO1xuICB9XG5cbiAgcmV0dXJuIG5ldyBVaW50OEFycmF5KHJlc3VsdCk7XG59XG5cbmZ1bmN0aW9uIHJlcHJlc2VudFlhbWxCaW5hcnkob2JqZWN0IC8qLCBzdHlsZSovKSB7XG4gIHZhciByZXN1bHQgPSAnJywgYml0cyA9IDAsIGlkeCwgdGFpbCxcbiAgICAgIG1heCA9IG9iamVjdC5sZW5ndGgsXG4gICAgICBtYXAgPSBCQVNFNjRfTUFQO1xuXG4gIC8vIENvbnZlcnQgZXZlcnkgdGhyZWUgYnl0ZXMgdG8gNCBBU0NJSSBjaGFyYWN0ZXJzLlxuXG4gIGZvciAoaWR4ID0gMDsgaWR4IDwgbWF4OyBpZHgrKykge1xuICAgIGlmICgoaWR4ICUgMyA9PT0gMCkgJiYgaWR4KSB7XG4gICAgICByZXN1bHQgKz0gbWFwWyhiaXRzID4+IDE4KSAmIDB4M0ZdO1xuICAgICAgcmVzdWx0ICs9IG1hcFsoYml0cyA+PiAxMikgJiAweDNGXTtcbiAgICAgIHJlc3VsdCArPSBtYXBbKGJpdHMgPj4gNikgJiAweDNGXTtcbiAgICAgIHJlc3VsdCArPSBtYXBbYml0cyAmIDB4M0ZdO1xuICAgIH1cblxuICAgIGJpdHMgPSAoYml0cyA8PCA4KSArIG9iamVjdFtpZHhdO1xuICB9XG5cbiAgLy8gRHVtcCB0YWlsXG5cbiAgdGFpbCA9IG1heCAlIDM7XG5cbiAgaWYgKHRhaWwgPT09IDApIHtcbiAgICByZXN1bHQgKz0gbWFwWyhiaXRzID4+IDE4KSAmIDB4M0ZdO1xuICAgIHJlc3VsdCArPSBtYXBbKGJpdHMgPj4gMTIpICYgMHgzRl07XG4gICAgcmVzdWx0ICs9IG1hcFsoYml0cyA+PiA2KSAmIDB4M0ZdO1xuICAgIHJlc3VsdCArPSBtYXBbYml0cyAmIDB4M0ZdO1xuICB9IGVsc2UgaWYgKHRhaWwgPT09IDIpIHtcbiAgICByZXN1bHQgKz0gbWFwWyhiaXRzID4+IDEwKSAmIDB4M0ZdO1xuICAgIHJlc3VsdCArPSBtYXBbKGJpdHMgPj4gNCkgJiAweDNGXTtcbiAgICByZXN1bHQgKz0gbWFwWyhiaXRzIDw8IDIpICYgMHgzRl07XG4gICAgcmVzdWx0ICs9IG1hcFs2NF07XG4gIH0gZWxzZSBpZiAodGFpbCA9PT0gMSkge1xuICAgIHJlc3VsdCArPSBtYXBbKGJpdHMgPj4gMikgJiAweDNGXTtcbiAgICByZXN1bHQgKz0gbWFwWyhiaXRzIDw8IDQpICYgMHgzRl07XG4gICAgcmVzdWx0ICs9IG1hcFs2NF07XG4gICAgcmVzdWx0ICs9IG1hcFs2NF07XG4gIH1cblxuICByZXR1cm4gcmVzdWx0O1xufVxuXG5mdW5jdGlvbiBpc0JpbmFyeShvYmopIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbChvYmopID09PSAgJ1tvYmplY3QgVWludDhBcnJheV0nO1xufVxuXG52YXIgYmluYXJ5ID0gbmV3IHR5cGUoJ3RhZzp5YW1sLm9yZywyMDAyOmJpbmFyeScsIHtcbiAga2luZDogJ3NjYWxhcicsXG4gIHJlc29sdmU6IHJlc29sdmVZYW1sQmluYXJ5LFxuICBjb25zdHJ1Y3Q6IGNvbnN0cnVjdFlhbWxCaW5hcnksXG4gIHByZWRpY2F0ZTogaXNCaW5hcnksXG4gIHJlcHJlc2VudDogcmVwcmVzZW50WWFtbEJpbmFyeVxufSk7XG5cbnZhciBfaGFzT3duUHJvcGVydHkkMyA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XG52YXIgX3RvU3RyaW5nJDIgICAgICAgPSBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nO1xuXG5mdW5jdGlvbiByZXNvbHZlWWFtbE9tYXAoZGF0YSkge1xuICBpZiAoZGF0YSA9PT0gbnVsbCkgcmV0dXJuIHRydWU7XG5cbiAgdmFyIG9iamVjdEtleXMgPSBbXSwgaW5kZXgsIGxlbmd0aCwgcGFpciwgcGFpcktleSwgcGFpckhhc0tleSxcbiAgICAgIG9iamVjdCA9IGRhdGE7XG5cbiAgZm9yIChpbmRleCA9IDAsIGxlbmd0aCA9IG9iamVjdC5sZW5ndGg7IGluZGV4IDwgbGVuZ3RoOyBpbmRleCArPSAxKSB7XG4gICAgcGFpciA9IG9iamVjdFtpbmRleF07XG4gICAgcGFpckhhc0tleSA9IGZhbHNlO1xuXG4gICAgaWYgKF90b1N0cmluZyQyLmNhbGwocGFpcikgIT09ICdbb2JqZWN0IE9iamVjdF0nKSByZXR1cm4gZmFsc2U7XG5cbiAgICBmb3IgKHBhaXJLZXkgaW4gcGFpcikge1xuICAgICAgaWYgKF9oYXNPd25Qcm9wZXJ0eSQzLmNhbGwocGFpciwgcGFpcktleSkpIHtcbiAgICAgICAgaWYgKCFwYWlySGFzS2V5KSBwYWlySGFzS2V5ID0gdHJ1ZTtcbiAgICAgICAgZWxzZSByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCFwYWlySGFzS2V5KSByZXR1cm4gZmFsc2U7XG5cbiAgICBpZiAob2JqZWN0S2V5cy5pbmRleE9mKHBhaXJLZXkpID09PSAtMSkgb2JqZWN0S2V5cy5wdXNoKHBhaXJLZXkpO1xuICAgIGVsc2UgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgcmV0dXJuIHRydWU7XG59XG5cbmZ1bmN0aW9uIGNvbnN0cnVjdFlhbWxPbWFwKGRhdGEpIHtcbiAgcmV0dXJuIGRhdGEgIT09IG51bGwgPyBkYXRhIDogW107XG59XG5cbnZhciBvbWFwID0gbmV3IHR5cGUoJ3RhZzp5YW1sLm9yZywyMDAyOm9tYXAnLCB7XG4gIGtpbmQ6ICdzZXF1ZW5jZScsXG4gIHJlc29sdmU6IHJlc29sdmVZYW1sT21hcCxcbiAgY29uc3RydWN0OiBjb25zdHJ1Y3RZYW1sT21hcFxufSk7XG5cbnZhciBfdG9TdHJpbmckMSA9IE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmc7XG5cbmZ1bmN0aW9uIHJlc29sdmVZYW1sUGFpcnMoZGF0YSkge1xuICBpZiAoZGF0YSA9PT0gbnVsbCkgcmV0dXJuIHRydWU7XG5cbiAgdmFyIGluZGV4LCBsZW5ndGgsIHBhaXIsIGtleXMsIHJlc3VsdCxcbiAgICAgIG9iamVjdCA9IGRhdGE7XG5cbiAgcmVzdWx0ID0gbmV3IEFycmF5KG9iamVjdC5sZW5ndGgpO1xuXG4gIGZvciAoaW5kZXggPSAwLCBsZW5ndGggPSBvYmplY3QubGVuZ3RoOyBpbmRleCA8IGxlbmd0aDsgaW5kZXggKz0gMSkge1xuICAgIHBhaXIgPSBvYmplY3RbaW5kZXhdO1xuXG4gICAgaWYgKF90b1N0cmluZyQxLmNhbGwocGFpcikgIT09ICdbb2JqZWN0IE9iamVjdF0nKSByZXR1cm4gZmFsc2U7XG5cbiAgICBrZXlzID0gT2JqZWN0LmtleXMocGFpcik7XG5cbiAgICBpZiAoa2V5cy5sZW5ndGggIT09IDEpIHJldHVybiBmYWxzZTtcblxuICAgIHJlc3VsdFtpbmRleF0gPSBbIGtleXNbMF0sIHBhaXJba2V5c1swXV0gXTtcbiAgfVxuXG4gIHJldHVybiB0cnVlO1xufVxuXG5mdW5jdGlvbiBjb25zdHJ1Y3RZYW1sUGFpcnMoZGF0YSkge1xuICBpZiAoZGF0YSA9PT0gbnVsbCkgcmV0dXJuIFtdO1xuXG4gIHZhciBpbmRleCwgbGVuZ3RoLCBwYWlyLCBrZXlzLCByZXN1bHQsXG4gICAgICBvYmplY3QgPSBkYXRhO1xuXG4gIHJlc3VsdCA9IG5ldyBBcnJheShvYmplY3QubGVuZ3RoKTtcblxuICBmb3IgKGluZGV4ID0gMCwgbGVuZ3RoID0gb2JqZWN0Lmxlbmd0aDsgaW5kZXggPCBsZW5ndGg7IGluZGV4ICs9IDEpIHtcbiAgICBwYWlyID0gb2JqZWN0W2luZGV4XTtcblxuICAgIGtleXMgPSBPYmplY3Qua2V5cyhwYWlyKTtcblxuICAgIHJlc3VsdFtpbmRleF0gPSBbIGtleXNbMF0sIHBhaXJba2V5c1swXV0gXTtcbiAgfVxuXG4gIHJldHVybiByZXN1bHQ7XG59XG5cbnZhciBwYWlycyA9IG5ldyB0eXBlKCd0YWc6eWFtbC5vcmcsMjAwMjpwYWlycycsIHtcbiAga2luZDogJ3NlcXVlbmNlJyxcbiAgcmVzb2x2ZTogcmVzb2x2ZVlhbWxQYWlycyxcbiAgY29uc3RydWN0OiBjb25zdHJ1Y3RZYW1sUGFpcnNcbn0pO1xuXG52YXIgX2hhc093blByb3BlcnR5JDIgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xuXG5mdW5jdGlvbiByZXNvbHZlWWFtbFNldChkYXRhKSB7XG4gIGlmIChkYXRhID09PSBudWxsKSByZXR1cm4gdHJ1ZTtcblxuICB2YXIga2V5LCBvYmplY3QgPSBkYXRhO1xuXG4gIGZvciAoa2V5IGluIG9iamVjdCkge1xuICAgIGlmIChfaGFzT3duUHJvcGVydHkkMi5jYWxsKG9iamVjdCwga2V5KSkge1xuICAgICAgaWYgKG9iamVjdFtrZXldICE9PSBudWxsKSByZXR1cm4gZmFsc2U7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHRydWU7XG59XG5cbmZ1bmN0aW9uIGNvbnN0cnVjdFlhbWxTZXQoZGF0YSkge1xuICByZXR1cm4gZGF0YSAhPT0gbnVsbCA/IGRhdGEgOiB7fTtcbn1cblxudmFyIHNldCA9IG5ldyB0eXBlKCd0YWc6eWFtbC5vcmcsMjAwMjpzZXQnLCB7XG4gIGtpbmQ6ICdtYXBwaW5nJyxcbiAgcmVzb2x2ZTogcmVzb2x2ZVlhbWxTZXQsXG4gIGNvbnN0cnVjdDogY29uc3RydWN0WWFtbFNldFxufSk7XG5cbnZhciBfZGVmYXVsdCA9IGNvcmUuZXh0ZW5kKHtcbiAgaW1wbGljaXQ6IFtcbiAgICB0aW1lc3RhbXAsXG4gICAgbWVyZ2VcbiAgXSxcbiAgZXhwbGljaXQ6IFtcbiAgICBiaW5hcnksXG4gICAgb21hcCxcbiAgICBwYWlycyxcbiAgICBzZXRcbiAgXVxufSk7XG5cbi8qZXNsaW50LWRpc2FibGUgbWF4LWxlbixuby11c2UtYmVmb3JlLWRlZmluZSovXG5cblxuXG5cblxuXG5cbnZhciBfaGFzT3duUHJvcGVydHkkMSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XG5cblxudmFyIENPTlRFWFRfRkxPV19JTiAgID0gMTtcbnZhciBDT05URVhUX0ZMT1dfT1VUICA9IDI7XG52YXIgQ09OVEVYVF9CTE9DS19JTiAgPSAzO1xudmFyIENPTlRFWFRfQkxPQ0tfT1VUID0gNDtcblxuXG52YXIgQ0hPTVBJTkdfQ0xJUCAgPSAxO1xudmFyIENIT01QSU5HX1NUUklQID0gMjtcbnZhciBDSE9NUElOR19LRUVQICA9IDM7XG5cblxudmFyIFBBVFRFUk5fTk9OX1BSSU5UQUJMRSAgICAgICAgID0gL1tcXHgwMC1cXHgwOFxceDBCXFx4MENcXHgwRS1cXHgxRlxceDdGLVxceDg0XFx4ODYtXFx4OUZcXHVGRkZFXFx1RkZGRl18W1xcdUQ4MDAtXFx1REJGRl0oPyFbXFx1REMwMC1cXHVERkZGXSl8KD86W15cXHVEODAwLVxcdURCRkZdfF4pW1xcdURDMDAtXFx1REZGRl0vO1xudmFyIFBBVFRFUk5fTk9OX0FTQ0lJX0xJTkVfQlJFQUtTID0gL1tcXHg4NVxcdTIwMjhcXHUyMDI5XS87XG52YXIgUEFUVEVSTl9GTE9XX0lORElDQVRPUlMgICAgICAgPSAvWyxcXFtcXF1cXHtcXH1dLztcbnZhciBQQVRURVJOX1RBR19IQU5ETEUgICAgICAgICAgICA9IC9eKD86IXwhIXwhW2EtelxcLV0rISkkL2k7XG52YXIgUEFUVEVSTl9UQUdfVVJJICAgICAgICAgICAgICAgPSAvXig/OiF8W14sXFxbXFxdXFx7XFx9XSkoPzolWzAtOWEtZl17Mn18WzAtOWEtelxcLSM7XFwvXFw/OkAmPVxcK1xcJCxfXFwuIX5cXConXFwoXFwpXFxbXFxdXSkqJC9pO1xuXG5cbmZ1bmN0aW9uIF9jbGFzcyhvYmopIHsgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbChvYmopOyB9XG5cbmZ1bmN0aW9uIGlzX0VPTChjKSB7XG4gIHJldHVybiAoYyA9PT0gMHgwQS8qIExGICovKSB8fCAoYyA9PT0gMHgwRC8qIENSICovKTtcbn1cblxuZnVuY3Rpb24gaXNfV0hJVEVfU1BBQ0UoYykge1xuICByZXR1cm4gKGMgPT09IDB4MDkvKiBUYWIgKi8pIHx8IChjID09PSAweDIwLyogU3BhY2UgKi8pO1xufVxuXG5mdW5jdGlvbiBpc19XU19PUl9FT0woYykge1xuICByZXR1cm4gKGMgPT09IDB4MDkvKiBUYWIgKi8pIHx8XG4gICAgICAgICAoYyA9PT0gMHgyMC8qIFNwYWNlICovKSB8fFxuICAgICAgICAgKGMgPT09IDB4MEEvKiBMRiAqLykgfHxcbiAgICAgICAgIChjID09PSAweDBELyogQ1IgKi8pO1xufVxuXG5mdW5jdGlvbiBpc19GTE9XX0lORElDQVRPUihjKSB7XG4gIHJldHVybiBjID09PSAweDJDLyogLCAqLyB8fFxuICAgICAgICAgYyA9PT0gMHg1Qi8qIFsgKi8gfHxcbiAgICAgICAgIGMgPT09IDB4NUQvKiBdICovIHx8XG4gICAgICAgICBjID09PSAweDdCLyogeyAqLyB8fFxuICAgICAgICAgYyA9PT0gMHg3RC8qIH0gKi87XG59XG5cbmZ1bmN0aW9uIGZyb21IZXhDb2RlKGMpIHtcbiAgdmFyIGxjO1xuXG4gIGlmICgoMHgzMC8qIDAgKi8gPD0gYykgJiYgKGMgPD0gMHgzOS8qIDkgKi8pKSB7XG4gICAgcmV0dXJuIGMgLSAweDMwO1xuICB9XG5cbiAgLyplc2xpbnQtZGlzYWJsZSBuby1iaXR3aXNlKi9cbiAgbGMgPSBjIHwgMHgyMDtcblxuICBpZiAoKDB4NjEvKiBhICovIDw9IGxjKSAmJiAobGMgPD0gMHg2Ni8qIGYgKi8pKSB7XG4gICAgcmV0dXJuIGxjIC0gMHg2MSArIDEwO1xuICB9XG5cbiAgcmV0dXJuIC0xO1xufVxuXG5mdW5jdGlvbiBlc2NhcGVkSGV4TGVuKGMpIHtcbiAgaWYgKGMgPT09IDB4NzgvKiB4ICovKSB7IHJldHVybiAyOyB9XG4gIGlmIChjID09PSAweDc1LyogdSAqLykgeyByZXR1cm4gNDsgfVxuICBpZiAoYyA9PT0gMHg1NS8qIFUgKi8pIHsgcmV0dXJuIDg7IH1cbiAgcmV0dXJuIDA7XG59XG5cbmZ1bmN0aW9uIGZyb21EZWNpbWFsQ29kZShjKSB7XG4gIGlmICgoMHgzMC8qIDAgKi8gPD0gYykgJiYgKGMgPD0gMHgzOS8qIDkgKi8pKSB7XG4gICAgcmV0dXJuIGMgLSAweDMwO1xuICB9XG5cbiAgcmV0dXJuIC0xO1xufVxuXG5mdW5jdGlvbiBzaW1wbGVFc2NhcGVTZXF1ZW5jZShjKSB7XG4gIC8qIGVzbGludC1kaXNhYmxlIGluZGVudCAqL1xuICByZXR1cm4gKGMgPT09IDB4MzAvKiAwICovKSA/ICdcXHgwMCcgOlxuICAgICAgICAoYyA9PT0gMHg2MS8qIGEgKi8pID8gJ1xceDA3JyA6XG4gICAgICAgIChjID09PSAweDYyLyogYiAqLykgPyAnXFx4MDgnIDpcbiAgICAgICAgKGMgPT09IDB4NzQvKiB0ICovKSA/ICdcXHgwOScgOlxuICAgICAgICAoYyA9PT0gMHgwOS8qIFRhYiAqLykgPyAnXFx4MDknIDpcbiAgICAgICAgKGMgPT09IDB4NkUvKiBuICovKSA/ICdcXHgwQScgOlxuICAgICAgICAoYyA9PT0gMHg3Ni8qIHYgKi8pID8gJ1xceDBCJyA6XG4gICAgICAgIChjID09PSAweDY2LyogZiAqLykgPyAnXFx4MEMnIDpcbiAgICAgICAgKGMgPT09IDB4NzIvKiByICovKSA/ICdcXHgwRCcgOlxuICAgICAgICAoYyA9PT0gMHg2NS8qIGUgKi8pID8gJ1xceDFCJyA6XG4gICAgICAgIChjID09PSAweDIwLyogU3BhY2UgKi8pID8gJyAnIDpcbiAgICAgICAgKGMgPT09IDB4MjIvKiBcIiAqLykgPyAnXFx4MjInIDpcbiAgICAgICAgKGMgPT09IDB4MkYvKiAvICovKSA/ICcvJyA6XG4gICAgICAgIChjID09PSAweDVDLyogXFwgKi8pID8gJ1xceDVDJyA6XG4gICAgICAgIChjID09PSAweDRFLyogTiAqLykgPyAnXFx4ODUnIDpcbiAgICAgICAgKGMgPT09IDB4NUYvKiBfICovKSA/ICdcXHhBMCcgOlxuICAgICAgICAoYyA9PT0gMHg0Qy8qIEwgKi8pID8gJ1xcdTIwMjgnIDpcbiAgICAgICAgKGMgPT09IDB4NTAvKiBQICovKSA/ICdcXHUyMDI5JyA6ICcnO1xufVxuXG5mdW5jdGlvbiBjaGFyRnJvbUNvZGVwb2ludChjKSB7XG4gIGlmIChjIDw9IDB4RkZGRikge1xuICAgIHJldHVybiBTdHJpbmcuZnJvbUNoYXJDb2RlKGMpO1xuICB9XG4gIC8vIEVuY29kZSBVVEYtMTYgc3Vycm9nYXRlIHBhaXJcbiAgLy8gaHR0cHM6Ly9lbi53aWtpcGVkaWEub3JnL3dpa2kvVVRGLTE2I0NvZGVfcG9pbnRzX1UuMkIwMTAwMDBfdG9fVS4yQjEwRkZGRlxuICByZXR1cm4gU3RyaW5nLmZyb21DaGFyQ29kZShcbiAgICAoKGMgLSAweDAxMDAwMCkgPj4gMTApICsgMHhEODAwLFxuICAgICgoYyAtIDB4MDEwMDAwKSAmIDB4MDNGRikgKyAweERDMDBcbiAgKTtcbn1cblxudmFyIHNpbXBsZUVzY2FwZUNoZWNrID0gbmV3IEFycmF5KDI1Nik7IC8vIGludGVnZXIsIGZvciBmYXN0IGFjY2Vzc1xudmFyIHNpbXBsZUVzY2FwZU1hcCA9IG5ldyBBcnJheSgyNTYpO1xuZm9yICh2YXIgaSA9IDA7IGkgPCAyNTY7IGkrKykge1xuICBzaW1wbGVFc2NhcGVDaGVja1tpXSA9IHNpbXBsZUVzY2FwZVNlcXVlbmNlKGkpID8gMSA6IDA7XG4gIHNpbXBsZUVzY2FwZU1hcFtpXSA9IHNpbXBsZUVzY2FwZVNlcXVlbmNlKGkpO1xufVxuXG5cbmZ1bmN0aW9uIFN0YXRlJDEoaW5wdXQsIG9wdGlvbnMpIHtcbiAgdGhpcy5pbnB1dCA9IGlucHV0O1xuXG4gIHRoaXMuZmlsZW5hbWUgID0gb3B0aW9uc1snZmlsZW5hbWUnXSAgfHwgbnVsbDtcbiAgdGhpcy5zY2hlbWEgICAgPSBvcHRpb25zWydzY2hlbWEnXSAgICB8fCBfZGVmYXVsdDtcbiAgdGhpcy5vbldhcm5pbmcgPSBvcHRpb25zWydvbldhcm5pbmcnXSB8fCBudWxsO1xuICAvLyAoSGlkZGVuKSBSZW1vdmU/IG1ha2VzIHRoZSBsb2FkZXIgdG8gZXhwZWN0IFlBTUwgMS4xIGRvY3VtZW50c1xuICAvLyBpZiBzdWNoIGRvY3VtZW50cyBoYXZlIG5vIGV4cGxpY2l0ICVZQU1MIGRpcmVjdGl2ZVxuICB0aGlzLmxlZ2FjeSAgICA9IG9wdGlvbnNbJ2xlZ2FjeSddICAgIHx8IGZhbHNlO1xuXG4gIHRoaXMuanNvbiAgICAgID0gb3B0aW9uc1snanNvbiddICAgICAgfHwgZmFsc2U7XG4gIHRoaXMubGlzdGVuZXIgID0gb3B0aW9uc1snbGlzdGVuZXInXSAgfHwgbnVsbDtcblxuICB0aGlzLmltcGxpY2l0VHlwZXMgPSB0aGlzLnNjaGVtYS5jb21waWxlZEltcGxpY2l0O1xuICB0aGlzLnR5cGVNYXAgICAgICAgPSB0aGlzLnNjaGVtYS5jb21waWxlZFR5cGVNYXA7XG5cbiAgdGhpcy5sZW5ndGggICAgID0gaW5wdXQubGVuZ3RoO1xuICB0aGlzLnBvc2l0aW9uICAgPSAwO1xuICB0aGlzLmxpbmUgICAgICAgPSAwO1xuICB0aGlzLmxpbmVTdGFydCAgPSAwO1xuICB0aGlzLmxpbmVJbmRlbnQgPSAwO1xuXG4gIC8vIHBvc2l0aW9uIG9mIGZpcnN0IGxlYWRpbmcgdGFiIGluIHRoZSBjdXJyZW50IGxpbmUsXG4gIC8vIHVzZWQgdG8gbWFrZSBzdXJlIHRoZXJlIGFyZSBubyB0YWJzIGluIHRoZSBpbmRlbnRhdGlvblxuICB0aGlzLmZpcnN0VGFiSW5MaW5lID0gLTE7XG5cbiAgdGhpcy5kb2N1bWVudHMgPSBbXTtcblxuICAvKlxuICB0aGlzLnZlcnNpb247XG4gIHRoaXMuY2hlY2tMaW5lQnJlYWtzO1xuICB0aGlzLnRhZ01hcDtcbiAgdGhpcy5hbmNob3JNYXA7XG4gIHRoaXMudGFnO1xuICB0aGlzLmFuY2hvcjtcbiAgdGhpcy5raW5kO1xuICB0aGlzLnJlc3VsdDsqL1xuXG59XG5cblxuZnVuY3Rpb24gZ2VuZXJhdGVFcnJvcihzdGF0ZSwgbWVzc2FnZSkge1xuICB2YXIgbWFyayA9IHtcbiAgICBuYW1lOiAgICAgc3RhdGUuZmlsZW5hbWUsXG4gICAgYnVmZmVyOiAgIHN0YXRlLmlucHV0LnNsaWNlKDAsIC0xKSwgLy8gb21pdCB0cmFpbGluZyBcXDBcbiAgICBwb3NpdGlvbjogc3RhdGUucG9zaXRpb24sXG4gICAgbGluZTogICAgIHN0YXRlLmxpbmUsXG4gICAgY29sdW1uOiAgIHN0YXRlLnBvc2l0aW9uIC0gc3RhdGUubGluZVN0YXJ0XG4gIH07XG5cbiAgbWFyay5zbmlwcGV0ID0gc25pcHBldChtYXJrKTtcblxuICByZXR1cm4gbmV3IGV4Y2VwdGlvbihtZXNzYWdlLCBtYXJrKTtcbn1cblxuZnVuY3Rpb24gdGhyb3dFcnJvcihzdGF0ZSwgbWVzc2FnZSkge1xuICB0aHJvdyBnZW5lcmF0ZUVycm9yKHN0YXRlLCBtZXNzYWdlKTtcbn1cblxuZnVuY3Rpb24gdGhyb3dXYXJuaW5nKHN0YXRlLCBtZXNzYWdlKSB7XG4gIGlmIChzdGF0ZS5vbldhcm5pbmcpIHtcbiAgICBzdGF0ZS5vbldhcm5pbmcuY2FsbChudWxsLCBnZW5lcmF0ZUVycm9yKHN0YXRlLCBtZXNzYWdlKSk7XG4gIH1cbn1cblxuXG52YXIgZGlyZWN0aXZlSGFuZGxlcnMgPSB7XG5cbiAgWUFNTDogZnVuY3Rpb24gaGFuZGxlWWFtbERpcmVjdGl2ZShzdGF0ZSwgbmFtZSwgYXJncykge1xuXG4gICAgdmFyIG1hdGNoLCBtYWpvciwgbWlub3I7XG5cbiAgICBpZiAoc3RhdGUudmVyc2lvbiAhPT0gbnVsbCkge1xuICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ2R1cGxpY2F0aW9uIG9mICVZQU1MIGRpcmVjdGl2ZScpO1xuICAgIH1cblxuICAgIGlmIChhcmdzLmxlbmd0aCAhPT0gMSkge1xuICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ1lBTUwgZGlyZWN0aXZlIGFjY2VwdHMgZXhhY3RseSBvbmUgYXJndW1lbnQnKTtcbiAgICB9XG5cbiAgICBtYXRjaCA9IC9eKFswLTldKylcXC4oWzAtOV0rKSQvLmV4ZWMoYXJnc1swXSk7XG5cbiAgICBpZiAobWF0Y2ggPT09IG51bGwpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICdpbGwtZm9ybWVkIGFyZ3VtZW50IG9mIHRoZSBZQU1MIGRpcmVjdGl2ZScpO1xuICAgIH1cblxuICAgIG1ham9yID0gcGFyc2VJbnQobWF0Y2hbMV0sIDEwKTtcbiAgICBtaW5vciA9IHBhcnNlSW50KG1hdGNoWzJdLCAxMCk7XG5cbiAgICBpZiAobWFqb3IgIT09IDEpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICd1bmFjY2VwdGFibGUgWUFNTCB2ZXJzaW9uIG9mIHRoZSBkb2N1bWVudCcpO1xuICAgIH1cblxuICAgIHN0YXRlLnZlcnNpb24gPSBhcmdzWzBdO1xuICAgIHN0YXRlLmNoZWNrTGluZUJyZWFrcyA9IChtaW5vciA8IDIpO1xuXG4gICAgaWYgKG1pbm9yICE9PSAxICYmIG1pbm9yICE9PSAyKSB7XG4gICAgICB0aHJvd1dhcm5pbmcoc3RhdGUsICd1bnN1cHBvcnRlZCBZQU1MIHZlcnNpb24gb2YgdGhlIGRvY3VtZW50Jyk7XG4gICAgfVxuICB9LFxuXG4gIFRBRzogZnVuY3Rpb24gaGFuZGxlVGFnRGlyZWN0aXZlKHN0YXRlLCBuYW1lLCBhcmdzKSB7XG5cbiAgICB2YXIgaGFuZGxlLCBwcmVmaXg7XG5cbiAgICBpZiAoYXJncy5sZW5ndGggIT09IDIpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICdUQUcgZGlyZWN0aXZlIGFjY2VwdHMgZXhhY3RseSB0d28gYXJndW1lbnRzJyk7XG4gICAgfVxuXG4gICAgaGFuZGxlID0gYXJnc1swXTtcbiAgICBwcmVmaXggPSBhcmdzWzFdO1xuXG4gICAgaWYgKCFQQVRURVJOX1RBR19IQU5ETEUudGVzdChoYW5kbGUpKSB7XG4gICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnaWxsLWZvcm1lZCB0YWcgaGFuZGxlIChmaXJzdCBhcmd1bWVudCkgb2YgdGhlIFRBRyBkaXJlY3RpdmUnKTtcbiAgICB9XG5cbiAgICBpZiAoX2hhc093blByb3BlcnR5JDEuY2FsbChzdGF0ZS50YWdNYXAsIGhhbmRsZSkpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICd0aGVyZSBpcyBhIHByZXZpb3VzbHkgZGVjbGFyZWQgc3VmZml4IGZvciBcIicgKyBoYW5kbGUgKyAnXCIgdGFnIGhhbmRsZScpO1xuICAgIH1cblxuICAgIGlmICghUEFUVEVSTl9UQUdfVVJJLnRlc3QocHJlZml4KSkge1xuICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ2lsbC1mb3JtZWQgdGFnIHByZWZpeCAoc2Vjb25kIGFyZ3VtZW50KSBvZiB0aGUgVEFHIGRpcmVjdGl2ZScpO1xuICAgIH1cblxuICAgIHRyeSB7XG4gICAgICBwcmVmaXggPSBkZWNvZGVVUklDb21wb25lbnQocHJlZml4KTtcbiAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICd0YWcgcHJlZml4IGlzIG1hbGZvcm1lZDogJyArIHByZWZpeCk7XG4gICAgfVxuXG4gICAgc3RhdGUudGFnTWFwW2hhbmRsZV0gPSBwcmVmaXg7XG4gIH1cbn07XG5cblxuZnVuY3Rpb24gY2FwdHVyZVNlZ21lbnQoc3RhdGUsIHN0YXJ0LCBlbmQsIGNoZWNrSnNvbikge1xuICB2YXIgX3Bvc2l0aW9uLCBfbGVuZ3RoLCBfY2hhcmFjdGVyLCBfcmVzdWx0O1xuXG4gIGlmIChzdGFydCA8IGVuZCkge1xuICAgIF9yZXN1bHQgPSBzdGF0ZS5pbnB1dC5zbGljZShzdGFydCwgZW5kKTtcblxuICAgIGlmIChjaGVja0pzb24pIHtcbiAgICAgIGZvciAoX3Bvc2l0aW9uID0gMCwgX2xlbmd0aCA9IF9yZXN1bHQubGVuZ3RoOyBfcG9zaXRpb24gPCBfbGVuZ3RoOyBfcG9zaXRpb24gKz0gMSkge1xuICAgICAgICBfY2hhcmFjdGVyID0gX3Jlc3VsdC5jaGFyQ29kZUF0KF9wb3NpdGlvbik7XG4gICAgICAgIGlmICghKF9jaGFyYWN0ZXIgPT09IDB4MDkgfHxcbiAgICAgICAgICAgICAgKDB4MjAgPD0gX2NoYXJhY3RlciAmJiBfY2hhcmFjdGVyIDw9IDB4MTBGRkZGKSkpIHtcbiAgICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnZXhwZWN0ZWQgdmFsaWQgSlNPTiBjaGFyYWN0ZXInKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gZWxzZSBpZiAoUEFUVEVSTl9OT05fUFJJTlRBQkxFLnRlc3QoX3Jlc3VsdCkpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICd0aGUgc3RyZWFtIGNvbnRhaW5zIG5vbi1wcmludGFibGUgY2hhcmFjdGVycycpO1xuICAgIH1cblxuICAgIHN0YXRlLnJlc3VsdCArPSBfcmVzdWx0O1xuICB9XG59XG5cbmZ1bmN0aW9uIG1lcmdlTWFwcGluZ3Moc3RhdGUsIGRlc3RpbmF0aW9uLCBzb3VyY2UsIG92ZXJyaWRhYmxlS2V5cykge1xuICB2YXIgc291cmNlS2V5cywga2V5LCBpbmRleCwgcXVhbnRpdHk7XG5cbiAgaWYgKCFjb21tb24uaXNPYmplY3Qoc291cmNlKSkge1xuICAgIHRocm93RXJyb3Ioc3RhdGUsICdjYW5ub3QgbWVyZ2UgbWFwcGluZ3M7IHRoZSBwcm92aWRlZCBzb3VyY2Ugb2JqZWN0IGlzIHVuYWNjZXB0YWJsZScpO1xuICB9XG5cbiAgc291cmNlS2V5cyA9IE9iamVjdC5rZXlzKHNvdXJjZSk7XG5cbiAgZm9yIChpbmRleCA9IDAsIHF1YW50aXR5ID0gc291cmNlS2V5cy5sZW5ndGg7IGluZGV4IDwgcXVhbnRpdHk7IGluZGV4ICs9IDEpIHtcbiAgICBrZXkgPSBzb3VyY2VLZXlzW2luZGV4XTtcblxuICAgIGlmICghX2hhc093blByb3BlcnR5JDEuY2FsbChkZXN0aW5hdGlvbiwga2V5KSkge1xuICAgICAgZGVzdGluYXRpb25ba2V5XSA9IHNvdXJjZVtrZXldO1xuICAgICAgb3ZlcnJpZGFibGVLZXlzW2tleV0gPSB0cnVlO1xuICAgIH1cbiAgfVxufVxuXG5mdW5jdGlvbiBzdG9yZU1hcHBpbmdQYWlyKHN0YXRlLCBfcmVzdWx0LCBvdmVycmlkYWJsZUtleXMsIGtleVRhZywga2V5Tm9kZSwgdmFsdWVOb2RlLFxuICBzdGFydExpbmUsIHN0YXJ0TGluZVN0YXJ0LCBzdGFydFBvcykge1xuXG4gIHZhciBpbmRleCwgcXVhbnRpdHk7XG5cbiAgLy8gVGhlIG91dHB1dCBpcyBhIHBsYWluIG9iamVjdCBoZXJlLCBzbyBrZXlzIGNhbiBvbmx5IGJlIHN0cmluZ3MuXG4gIC8vIFdlIG5lZWQgdG8gY29udmVydCBrZXlOb2RlIHRvIGEgc3RyaW5nLCBidXQgZG9pbmcgc28gY2FuIGhhbmcgdGhlIHByb2Nlc3NcbiAgLy8gKGRlZXBseSBuZXN0ZWQgYXJyYXlzIHRoYXQgZXhwbG9kZSBleHBvbmVudGlhbGx5IHVzaW5nIGFsaWFzZXMpLlxuICBpZiAoQXJyYXkuaXNBcnJheShrZXlOb2RlKSkge1xuICAgIGtleU5vZGUgPSBBcnJheS5wcm90b3R5cGUuc2xpY2UuY2FsbChrZXlOb2RlKTtcblxuICAgIGZvciAoaW5kZXggPSAwLCBxdWFudGl0eSA9IGtleU5vZGUubGVuZ3RoOyBpbmRleCA8IHF1YW50aXR5OyBpbmRleCArPSAxKSB7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShrZXlOb2RlW2luZGV4XSkpIHtcbiAgICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ25lc3RlZCBhcnJheXMgYXJlIG5vdCBzdXBwb3J0ZWQgaW5zaWRlIGtleXMnKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGVvZiBrZXlOb2RlID09PSAnb2JqZWN0JyAmJiBfY2xhc3Moa2V5Tm9kZVtpbmRleF0pID09PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgICAgICBrZXlOb2RlW2luZGV4XSA9ICdbb2JqZWN0IE9iamVjdF0nO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIC8vIEF2b2lkIGNvZGUgZXhlY3V0aW9uIGluIGxvYWQoKSB2aWEgdG9TdHJpbmcgcHJvcGVydHlcbiAgLy8gKHN0aWxsIHVzZSBpdHMgb3duIHRvU3RyaW5nIGZvciBhcnJheXMsIHRpbWVzdGFtcHMsXG4gIC8vIGFuZCB3aGF0ZXZlciB1c2VyIHNjaGVtYSBleHRlbnNpb25zIGhhcHBlbiB0byBoYXZlIEBAdG9TdHJpbmdUYWcpXG4gIGlmICh0eXBlb2Yga2V5Tm9kZSA9PT0gJ29iamVjdCcgJiYgX2NsYXNzKGtleU5vZGUpID09PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgIGtleU5vZGUgPSAnW29iamVjdCBPYmplY3RdJztcbiAgfVxuXG5cbiAga2V5Tm9kZSA9IFN0cmluZyhrZXlOb2RlKTtcblxuICBpZiAoX3Jlc3VsdCA9PT0gbnVsbCkge1xuICAgIF9yZXN1bHQgPSB7fTtcbiAgfVxuXG4gIGlmIChrZXlUYWcgPT09ICd0YWc6eWFtbC5vcmcsMjAwMjptZXJnZScpIHtcbiAgICBpZiAoQXJyYXkuaXNBcnJheSh2YWx1ZU5vZGUpKSB7XG4gICAgICBmb3IgKGluZGV4ID0gMCwgcXVhbnRpdHkgPSB2YWx1ZU5vZGUubGVuZ3RoOyBpbmRleCA8IHF1YW50aXR5OyBpbmRleCArPSAxKSB7XG4gICAgICAgIG1lcmdlTWFwcGluZ3Moc3RhdGUsIF9yZXN1bHQsIHZhbHVlTm9kZVtpbmRleF0sIG92ZXJyaWRhYmxlS2V5cyk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIG1lcmdlTWFwcGluZ3Moc3RhdGUsIF9yZXN1bHQsIHZhbHVlTm9kZSwgb3ZlcnJpZGFibGVLZXlzKTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgaWYgKCFzdGF0ZS5qc29uICYmXG4gICAgICAgICFfaGFzT3duUHJvcGVydHkkMS5jYWxsKG92ZXJyaWRhYmxlS2V5cywga2V5Tm9kZSkgJiZcbiAgICAgICAgX2hhc093blByb3BlcnR5JDEuY2FsbChfcmVzdWx0LCBrZXlOb2RlKSkge1xuICAgICAgc3RhdGUubGluZSA9IHN0YXJ0TGluZSB8fCBzdGF0ZS5saW5lO1xuICAgICAgc3RhdGUubGluZVN0YXJ0ID0gc3RhcnRMaW5lU3RhcnQgfHwgc3RhdGUubGluZVN0YXJ0O1xuICAgICAgc3RhdGUucG9zaXRpb24gPSBzdGFydFBvcyB8fCBzdGF0ZS5wb3NpdGlvbjtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICdkdXBsaWNhdGVkIG1hcHBpbmcga2V5Jyk7XG4gICAgfVxuXG4gICAgLy8gdXNlZCBmb3IgdGhpcyBzcGVjaWZpYyBrZXkgb25seSBiZWNhdXNlIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSBpcyBzbG93XG4gICAgaWYgKGtleU5vZGUgPT09ICdfX3Byb3RvX18nKSB7XG4gICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoX3Jlc3VsdCwga2V5Tm9kZSwge1xuICAgICAgICBjb25maWd1cmFibGU6IHRydWUsXG4gICAgICAgIGVudW1lcmFibGU6IHRydWUsXG4gICAgICAgIHdyaXRhYmxlOiB0cnVlLFxuICAgICAgICB2YWx1ZTogdmFsdWVOb2RlXG4gICAgICB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgX3Jlc3VsdFtrZXlOb2RlXSA9IHZhbHVlTm9kZTtcbiAgICB9XG4gICAgZGVsZXRlIG92ZXJyaWRhYmxlS2V5c1trZXlOb2RlXTtcbiAgfVxuXG4gIHJldHVybiBfcmVzdWx0O1xufVxuXG5mdW5jdGlvbiByZWFkTGluZUJyZWFrKHN0YXRlKSB7XG4gIHZhciBjaDtcblxuICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuXG4gIGlmIChjaCA9PT0gMHgwQS8qIExGICovKSB7XG4gICAgc3RhdGUucG9zaXRpb24rKztcbiAgfSBlbHNlIGlmIChjaCA9PT0gMHgwRC8qIENSICovKSB7XG4gICAgc3RhdGUucG9zaXRpb24rKztcbiAgICBpZiAoc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbikgPT09IDB4MEEvKiBMRiAqLykge1xuICAgICAgc3RhdGUucG9zaXRpb24rKztcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgdGhyb3dFcnJvcihzdGF0ZSwgJ2EgbGluZSBicmVhayBpcyBleHBlY3RlZCcpO1xuICB9XG5cbiAgc3RhdGUubGluZSArPSAxO1xuICBzdGF0ZS5saW5lU3RhcnQgPSBzdGF0ZS5wb3NpdGlvbjtcbiAgc3RhdGUuZmlyc3RUYWJJbkxpbmUgPSAtMTtcbn1cblxuZnVuY3Rpb24gc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgYWxsb3dDb21tZW50cywgY2hlY2tJbmRlbnQpIHtcbiAgdmFyIGxpbmVCcmVha3MgPSAwLFxuICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICB3aGlsZSAoY2ggIT09IDApIHtcbiAgICB3aGlsZSAoaXNfV0hJVEVfU1BBQ0UoY2gpKSB7XG4gICAgICBpZiAoY2ggPT09IDB4MDkvKiBUYWIgKi8gJiYgc3RhdGUuZmlyc3RUYWJJbkxpbmUgPT09IC0xKSB7XG4gICAgICAgIHN0YXRlLmZpcnN0VGFiSW5MaW5lID0gc3RhdGUucG9zaXRpb247XG4gICAgICB9XG4gICAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoKytzdGF0ZS5wb3NpdGlvbik7XG4gICAgfVxuXG4gICAgaWYgKGFsbG93Q29tbWVudHMgJiYgY2ggPT09IDB4MjMvKiAjICovKSB7XG4gICAgICBkbyB7XG4gICAgICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgICAgIH0gd2hpbGUgKGNoICE9PSAweDBBLyogTEYgKi8gJiYgY2ggIT09IDB4MEQvKiBDUiAqLyAmJiBjaCAhPT0gMCk7XG4gICAgfVxuXG4gICAgaWYgKGlzX0VPTChjaCkpIHtcbiAgICAgIHJlYWRMaW5lQnJlYWsoc3RhdGUpO1xuXG4gICAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuICAgICAgbGluZUJyZWFrcysrO1xuICAgICAgc3RhdGUubGluZUluZGVudCA9IDA7XG5cbiAgICAgIHdoaWxlIChjaCA9PT0gMHgyMC8qIFNwYWNlICovKSB7XG4gICAgICAgIHN0YXRlLmxpbmVJbmRlbnQrKztcbiAgICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBicmVhaztcbiAgICB9XG4gIH1cblxuICBpZiAoY2hlY2tJbmRlbnQgIT09IC0xICYmIGxpbmVCcmVha3MgIT09IDAgJiYgc3RhdGUubGluZUluZGVudCA8IGNoZWNrSW5kZW50KSB7XG4gICAgdGhyb3dXYXJuaW5nKHN0YXRlLCAnZGVmaWNpZW50IGluZGVudGF0aW9uJyk7XG4gIH1cblxuICByZXR1cm4gbGluZUJyZWFrcztcbn1cblxuZnVuY3Rpb24gdGVzdERvY3VtZW50U2VwYXJhdG9yKHN0YXRlKSB7XG4gIHZhciBfcG9zaXRpb24gPSBzdGF0ZS5wb3NpdGlvbixcbiAgICAgIGNoO1xuXG4gIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChfcG9zaXRpb24pO1xuXG4gIC8vIENvbmRpdGlvbiBzdGF0ZS5wb3NpdGlvbiA9PT0gc3RhdGUubGluZVN0YXJ0IGlzIHRlc3RlZFxuICAvLyBpbiBwYXJlbnQgb24gZWFjaCBjYWxsLCBmb3IgZWZmaWNpZW5jeS4gTm8gbmVlZHMgdG8gdGVzdCBoZXJlIGFnYWluLlxuICBpZiAoKGNoID09PSAweDJELyogLSAqLyB8fCBjaCA9PT0gMHgyRS8qIC4gKi8pICYmXG4gICAgICBjaCA9PT0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChfcG9zaXRpb24gKyAxKSAmJlxuICAgICAgY2ggPT09IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoX3Bvc2l0aW9uICsgMikpIHtcblxuICAgIF9wb3NpdGlvbiArPSAzO1xuXG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KF9wb3NpdGlvbik7XG5cbiAgICBpZiAoY2ggPT09IDAgfHwgaXNfV1NfT1JfRU9MKGNoKSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5mdW5jdGlvbiB3cml0ZUZvbGRlZExpbmVzKHN0YXRlLCBjb3VudCkge1xuICBpZiAoY291bnQgPT09IDEpIHtcbiAgICBzdGF0ZS5yZXN1bHQgKz0gJyAnO1xuICB9IGVsc2UgaWYgKGNvdW50ID4gMSkge1xuICAgIHN0YXRlLnJlc3VsdCArPSBjb21tb24ucmVwZWF0KCdcXG4nLCBjb3VudCAtIDEpO1xuICB9XG59XG5cblxuZnVuY3Rpb24gcmVhZFBsYWluU2NhbGFyKHN0YXRlLCBub2RlSW5kZW50LCB3aXRoaW5GbG93Q29sbGVjdGlvbikge1xuICB2YXIgcHJlY2VkaW5nLFxuICAgICAgZm9sbG93aW5nLFxuICAgICAgY2FwdHVyZVN0YXJ0LFxuICAgICAgY2FwdHVyZUVuZCxcbiAgICAgIGhhc1BlbmRpbmdDb250ZW50LFxuICAgICAgX2xpbmUsXG4gICAgICBfbGluZVN0YXJ0LFxuICAgICAgX2xpbmVJbmRlbnQsXG4gICAgICBfa2luZCA9IHN0YXRlLmtpbmQsXG4gICAgICBfcmVzdWx0ID0gc3RhdGUucmVzdWx0LFxuICAgICAgY2g7XG5cbiAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICBpZiAoaXNfV1NfT1JfRU9MKGNoKSAgICAgIHx8XG4gICAgICBpc19GTE9XX0lORElDQVRPUihjaCkgfHxcbiAgICAgIGNoID09PSAweDIzLyogIyAqLyAgICB8fFxuICAgICAgY2ggPT09IDB4MjYvKiAmICovICAgIHx8XG4gICAgICBjaCA9PT0gMHgyQS8qICogKi8gICAgfHxcbiAgICAgIGNoID09PSAweDIxLyogISAqLyAgICB8fFxuICAgICAgY2ggPT09IDB4N0MvKiB8ICovICAgIHx8XG4gICAgICBjaCA9PT0gMHgzRS8qID4gKi8gICAgfHxcbiAgICAgIGNoID09PSAweDI3LyogJyAqLyAgICB8fFxuICAgICAgY2ggPT09IDB4MjIvKiBcIiAqLyAgICB8fFxuICAgICAgY2ggPT09IDB4MjUvKiAlICovICAgIHx8XG4gICAgICBjaCA9PT0gMHg0MC8qIEAgKi8gICAgfHxcbiAgICAgIGNoID09PSAweDYwLyogYCAqLykge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIGlmIChjaCA9PT0gMHgzRi8qID8gKi8gfHwgY2ggPT09IDB4MkQvKiAtICovKSB7XG4gICAgZm9sbG93aW5nID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbiArIDEpO1xuXG4gICAgaWYgKGlzX1dTX09SX0VPTChmb2xsb3dpbmcpIHx8XG4gICAgICAgIHdpdGhpbkZsb3dDb2xsZWN0aW9uICYmIGlzX0ZMT1dfSU5ESUNBVE9SKGZvbGxvd2luZykpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH1cblxuICBzdGF0ZS5raW5kID0gJ3NjYWxhcic7XG4gIHN0YXRlLnJlc3VsdCA9ICcnO1xuICBjYXB0dXJlU3RhcnQgPSBjYXB0dXJlRW5kID0gc3RhdGUucG9zaXRpb247XG4gIGhhc1BlbmRpbmdDb250ZW50ID0gZmFsc2U7XG5cbiAgd2hpbGUgKGNoICE9PSAwKSB7XG4gICAgaWYgKGNoID09PSAweDNBLyogOiAqLykge1xuICAgICAgZm9sbG93aW5nID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbiArIDEpO1xuXG4gICAgICBpZiAoaXNfV1NfT1JfRU9MKGZvbGxvd2luZykgfHxcbiAgICAgICAgICB3aXRoaW5GbG93Q29sbGVjdGlvbiAmJiBpc19GTE9XX0lORElDQVRPUihmb2xsb3dpbmcpKSB7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuXG4gICAgfSBlbHNlIGlmIChjaCA9PT0gMHgyMy8qICMgKi8pIHtcbiAgICAgIHByZWNlZGluZyA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24gLSAxKTtcblxuICAgICAgaWYgKGlzX1dTX09SX0VPTChwcmVjZWRpbmcpKSB7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuXG4gICAgfSBlbHNlIGlmICgoc3RhdGUucG9zaXRpb24gPT09IHN0YXRlLmxpbmVTdGFydCAmJiB0ZXN0RG9jdW1lbnRTZXBhcmF0b3Ioc3RhdGUpKSB8fFxuICAgICAgICAgICAgICAgd2l0aGluRmxvd0NvbGxlY3Rpb24gJiYgaXNfRkxPV19JTkRJQ0FUT1IoY2gpKSB7XG4gICAgICBicmVhaztcblxuICAgIH0gZWxzZSBpZiAoaXNfRU9MKGNoKSkge1xuICAgICAgX2xpbmUgPSBzdGF0ZS5saW5lO1xuICAgICAgX2xpbmVTdGFydCA9IHN0YXRlLmxpbmVTdGFydDtcbiAgICAgIF9saW5lSW5kZW50ID0gc3RhdGUubGluZUluZGVudDtcbiAgICAgIHNraXBTZXBhcmF0aW9uU3BhY2Uoc3RhdGUsIGZhbHNlLCAtMSk7XG5cbiAgICAgIGlmIChzdGF0ZS5saW5lSW5kZW50ID49IG5vZGVJbmRlbnQpIHtcbiAgICAgICAgaGFzUGVuZGluZ0NvbnRlbnQgPSB0cnVlO1xuICAgICAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHN0YXRlLnBvc2l0aW9uID0gY2FwdHVyZUVuZDtcbiAgICAgICAgc3RhdGUubGluZSA9IF9saW5lO1xuICAgICAgICBzdGF0ZS5saW5lU3RhcnQgPSBfbGluZVN0YXJ0O1xuICAgICAgICBzdGF0ZS5saW5lSW5kZW50ID0gX2xpbmVJbmRlbnQ7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChoYXNQZW5kaW5nQ29udGVudCkge1xuICAgICAgY2FwdHVyZVNlZ21lbnQoc3RhdGUsIGNhcHR1cmVTdGFydCwgY2FwdHVyZUVuZCwgZmFsc2UpO1xuICAgICAgd3JpdGVGb2xkZWRMaW5lcyhzdGF0ZSwgc3RhdGUubGluZSAtIF9saW5lKTtcbiAgICAgIGNhcHR1cmVTdGFydCA9IGNhcHR1cmVFbmQgPSBzdGF0ZS5wb3NpdGlvbjtcbiAgICAgIGhhc1BlbmRpbmdDb250ZW50ID0gZmFsc2U7XG4gICAgfVxuXG4gICAgaWYgKCFpc19XSElURV9TUEFDRShjaCkpIHtcbiAgICAgIGNhcHR1cmVFbmQgPSBzdGF0ZS5wb3NpdGlvbiArIDE7XG4gICAgfVxuXG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuICB9XG5cbiAgY2FwdHVyZVNlZ21lbnQoc3RhdGUsIGNhcHR1cmVTdGFydCwgY2FwdHVyZUVuZCwgZmFsc2UpO1xuXG4gIGlmIChzdGF0ZS5yZXN1bHQpIHtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIHN0YXRlLmtpbmQgPSBfa2luZDtcbiAgc3RhdGUucmVzdWx0ID0gX3Jlc3VsdDtcbiAgcmV0dXJuIGZhbHNlO1xufVxuXG5mdW5jdGlvbiByZWFkU2luZ2xlUXVvdGVkU2NhbGFyKHN0YXRlLCBub2RlSW5kZW50KSB7XG4gIHZhciBjaCxcbiAgICAgIGNhcHR1cmVTdGFydCwgY2FwdHVyZUVuZDtcblxuICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuXG4gIGlmIChjaCAhPT0gMHgyNy8qICcgKi8pIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBzdGF0ZS5raW5kID0gJ3NjYWxhcic7XG4gIHN0YXRlLnJlc3VsdCA9ICcnO1xuICBzdGF0ZS5wb3NpdGlvbisrO1xuICBjYXB0dXJlU3RhcnQgPSBjYXB0dXJlRW5kID0gc3RhdGUucG9zaXRpb247XG5cbiAgd2hpbGUgKChjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pKSAhPT0gMCkge1xuICAgIGlmIChjaCA9PT0gMHgyNy8qICcgKi8pIHtcbiAgICAgIGNhcHR1cmVTZWdtZW50KHN0YXRlLCBjYXB0dXJlU3RhcnQsIHN0YXRlLnBvc2l0aW9uLCB0cnVlKTtcbiAgICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcblxuICAgICAgaWYgKGNoID09PSAweDI3LyogJyAqLykge1xuICAgICAgICBjYXB0dXJlU3RhcnQgPSBzdGF0ZS5wb3NpdGlvbjtcbiAgICAgICAgc3RhdGUucG9zaXRpb24rKztcbiAgICAgICAgY2FwdHVyZUVuZCA9IHN0YXRlLnBvc2l0aW9uO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9XG5cbiAgICB9IGVsc2UgaWYgKGlzX0VPTChjaCkpIHtcbiAgICAgIGNhcHR1cmVTZWdtZW50KHN0YXRlLCBjYXB0dXJlU3RhcnQsIGNhcHR1cmVFbmQsIHRydWUpO1xuICAgICAgd3JpdGVGb2xkZWRMaW5lcyhzdGF0ZSwgc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgZmFsc2UsIG5vZGVJbmRlbnQpKTtcbiAgICAgIGNhcHR1cmVTdGFydCA9IGNhcHR1cmVFbmQgPSBzdGF0ZS5wb3NpdGlvbjtcblxuICAgIH0gZWxzZSBpZiAoc3RhdGUucG9zaXRpb24gPT09IHN0YXRlLmxpbmVTdGFydCAmJiB0ZXN0RG9jdW1lbnRTZXBhcmF0b3Ioc3RhdGUpKSB7XG4gICAgICB0aHJvd0Vycm9yKHN0YXRlLCAndW5leHBlY3RlZCBlbmQgb2YgdGhlIGRvY3VtZW50IHdpdGhpbiBhIHNpbmdsZSBxdW90ZWQgc2NhbGFyJyk7XG5cbiAgICB9IGVsc2Uge1xuICAgICAgc3RhdGUucG9zaXRpb24rKztcbiAgICAgIGNhcHR1cmVFbmQgPSBzdGF0ZS5wb3NpdGlvbjtcbiAgICB9XG4gIH1cblxuICB0aHJvd0Vycm9yKHN0YXRlLCAndW5leHBlY3RlZCBlbmQgb2YgdGhlIHN0cmVhbSB3aXRoaW4gYSBzaW5nbGUgcXVvdGVkIHNjYWxhcicpO1xufVxuXG5mdW5jdGlvbiByZWFkRG91YmxlUXVvdGVkU2NhbGFyKHN0YXRlLCBub2RlSW5kZW50KSB7XG4gIHZhciBjYXB0dXJlU3RhcnQsXG4gICAgICBjYXB0dXJlRW5kLFxuICAgICAgaGV4TGVuZ3RoLFxuICAgICAgaGV4UmVzdWx0LFxuICAgICAgdG1wLFxuICAgICAgY2g7XG5cbiAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICBpZiAoY2ggIT09IDB4MjIvKiBcIiAqLykge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIHN0YXRlLmtpbmQgPSAnc2NhbGFyJztcbiAgc3RhdGUucmVzdWx0ID0gJyc7XG4gIHN0YXRlLnBvc2l0aW9uKys7XG4gIGNhcHR1cmVTdGFydCA9IGNhcHR1cmVFbmQgPSBzdGF0ZS5wb3NpdGlvbjtcblxuICB3aGlsZSAoKGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbikpICE9PSAwKSB7XG4gICAgaWYgKGNoID09PSAweDIyLyogXCIgKi8pIHtcbiAgICAgIGNhcHR1cmVTZWdtZW50KHN0YXRlLCBjYXB0dXJlU3RhcnQsIHN0YXRlLnBvc2l0aW9uLCB0cnVlKTtcbiAgICAgIHN0YXRlLnBvc2l0aW9uKys7XG4gICAgICByZXR1cm4gdHJ1ZTtcblxuICAgIH0gZWxzZSBpZiAoY2ggPT09IDB4NUMvKiBcXCAqLykge1xuICAgICAgY2FwdHVyZVNlZ21lbnQoc3RhdGUsIGNhcHR1cmVTdGFydCwgc3RhdGUucG9zaXRpb24sIHRydWUpO1xuICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuXG4gICAgICBpZiAoaXNfRU9MKGNoKSkge1xuICAgICAgICBza2lwU2VwYXJhdGlvblNwYWNlKHN0YXRlLCBmYWxzZSwgbm9kZUluZGVudCk7XG5cbiAgICAgICAgLy8gVE9ETzogcmV3b3JrIHRvIGlubGluZSBmbiB3aXRoIG5vIHR5cGUgY2FzdD9cbiAgICAgIH0gZWxzZSBpZiAoY2ggPCAyNTYgJiYgc2ltcGxlRXNjYXBlQ2hlY2tbY2hdKSB7XG4gICAgICAgIHN0YXRlLnJlc3VsdCArPSBzaW1wbGVFc2NhcGVNYXBbY2hdO1xuICAgICAgICBzdGF0ZS5wb3NpdGlvbisrO1xuXG4gICAgICB9IGVsc2UgaWYgKCh0bXAgPSBlc2NhcGVkSGV4TGVuKGNoKSkgPiAwKSB7XG4gICAgICAgIGhleExlbmd0aCA9IHRtcDtcbiAgICAgICAgaGV4UmVzdWx0ID0gMDtcblxuICAgICAgICBmb3IgKDsgaGV4TGVuZ3RoID4gMDsgaGV4TGVuZ3RoLS0pIHtcbiAgICAgICAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoKytzdGF0ZS5wb3NpdGlvbik7XG5cbiAgICAgICAgICBpZiAoKHRtcCA9IGZyb21IZXhDb2RlKGNoKSkgPj0gMCkge1xuICAgICAgICAgICAgaGV4UmVzdWx0ID0gKGhleFJlc3VsdCA8PCA0KSArIHRtcDtcblxuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnZXhwZWN0ZWQgaGV4YWRlY2ltYWwgY2hhcmFjdGVyJyk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgc3RhdGUucmVzdWx0ICs9IGNoYXJGcm9tQ29kZXBvaW50KGhleFJlc3VsdCk7XG5cbiAgICAgICAgc3RhdGUucG9zaXRpb24rKztcblxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3Vua25vd24gZXNjYXBlIHNlcXVlbmNlJyk7XG4gICAgICB9XG5cbiAgICAgIGNhcHR1cmVTdGFydCA9IGNhcHR1cmVFbmQgPSBzdGF0ZS5wb3NpdGlvbjtcblxuICAgIH0gZWxzZSBpZiAoaXNfRU9MKGNoKSkge1xuICAgICAgY2FwdHVyZVNlZ21lbnQoc3RhdGUsIGNhcHR1cmVTdGFydCwgY2FwdHVyZUVuZCwgdHJ1ZSk7XG4gICAgICB3cml0ZUZvbGRlZExpbmVzKHN0YXRlLCBza2lwU2VwYXJhdGlvblNwYWNlKHN0YXRlLCBmYWxzZSwgbm9kZUluZGVudCkpO1xuICAgICAgY2FwdHVyZVN0YXJ0ID0gY2FwdHVyZUVuZCA9IHN0YXRlLnBvc2l0aW9uO1xuXG4gICAgfSBlbHNlIGlmIChzdGF0ZS5wb3NpdGlvbiA9PT0gc3RhdGUubGluZVN0YXJ0ICYmIHRlc3REb2N1bWVudFNlcGFyYXRvcihzdGF0ZSkpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICd1bmV4cGVjdGVkIGVuZCBvZiB0aGUgZG9jdW1lbnQgd2l0aGluIGEgZG91YmxlIHF1b3RlZCBzY2FsYXInKTtcblxuICAgIH0gZWxzZSB7XG4gICAgICBzdGF0ZS5wb3NpdGlvbisrO1xuICAgICAgY2FwdHVyZUVuZCA9IHN0YXRlLnBvc2l0aW9uO1xuICAgIH1cbiAgfVxuXG4gIHRocm93RXJyb3Ioc3RhdGUsICd1bmV4cGVjdGVkIGVuZCBvZiB0aGUgc3RyZWFtIHdpdGhpbiBhIGRvdWJsZSBxdW90ZWQgc2NhbGFyJyk7XG59XG5cbmZ1bmN0aW9uIHJlYWRGbG93Q29sbGVjdGlvbihzdGF0ZSwgbm9kZUluZGVudCkge1xuICB2YXIgcmVhZE5leHQgPSB0cnVlLFxuICAgICAgX2xpbmUsXG4gICAgICBfbGluZVN0YXJ0LFxuICAgICAgX3BvcyxcbiAgICAgIF90YWcgICAgID0gc3RhdGUudGFnLFxuICAgICAgX3Jlc3VsdCxcbiAgICAgIF9hbmNob3IgID0gc3RhdGUuYW5jaG9yLFxuICAgICAgZm9sbG93aW5nLFxuICAgICAgdGVybWluYXRvcixcbiAgICAgIGlzUGFpcixcbiAgICAgIGlzRXhwbGljaXRQYWlyLFxuICAgICAgaXNNYXBwaW5nLFxuICAgICAgb3ZlcnJpZGFibGVLZXlzID0gT2JqZWN0LmNyZWF0ZShudWxsKSxcbiAgICAgIGtleU5vZGUsXG4gICAgICBrZXlUYWcsXG4gICAgICB2YWx1ZU5vZGUsXG4gICAgICBjaDtcblxuICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuXG4gIGlmIChjaCA9PT0gMHg1Qi8qIFsgKi8pIHtcbiAgICB0ZXJtaW5hdG9yID0gMHg1RDsvKiBdICovXG4gICAgaXNNYXBwaW5nID0gZmFsc2U7XG4gICAgX3Jlc3VsdCA9IFtdO1xuICB9IGVsc2UgaWYgKGNoID09PSAweDdCLyogeyAqLykge1xuICAgIHRlcm1pbmF0b3IgPSAweDdEOy8qIH0gKi9cbiAgICBpc01hcHBpbmcgPSB0cnVlO1xuICAgIF9yZXN1bHQgPSB7fTtcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBpZiAoc3RhdGUuYW5jaG9yICE9PSBudWxsKSB7XG4gICAgc3RhdGUuYW5jaG9yTWFwW3N0YXRlLmFuY2hvcl0gPSBfcmVzdWx0O1xuICB9XG5cbiAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuXG4gIHdoaWxlIChjaCAhPT0gMCkge1xuICAgIHNraXBTZXBhcmF0aW9uU3BhY2Uoc3RhdGUsIHRydWUsIG5vZGVJbmRlbnQpO1xuXG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICAgIGlmIChjaCA9PT0gdGVybWluYXRvcikge1xuICAgICAgc3RhdGUucG9zaXRpb24rKztcbiAgICAgIHN0YXRlLnRhZyA9IF90YWc7XG4gICAgICBzdGF0ZS5hbmNob3IgPSBfYW5jaG9yO1xuICAgICAgc3RhdGUua2luZCA9IGlzTWFwcGluZyA/ICdtYXBwaW5nJyA6ICdzZXF1ZW5jZSc7XG4gICAgICBzdGF0ZS5yZXN1bHQgPSBfcmVzdWx0O1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSBlbHNlIGlmICghcmVhZE5leHQpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICdtaXNzZWQgY29tbWEgYmV0d2VlbiBmbG93IGNvbGxlY3Rpb24gZW50cmllcycpO1xuICAgIH0gZWxzZSBpZiAoY2ggPT09IDB4MkMvKiAsICovKSB7XG4gICAgICAvLyBcImZsb3cgY29sbGVjdGlvbiBlbnRyaWVzIGNhbiBuZXZlciBiZSBjb21wbGV0ZWx5IGVtcHR5XCIsIGFzIHBlciBZQU1MIDEuMiwgc2VjdGlvbiA3LjRcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsIFwiZXhwZWN0ZWQgdGhlIG5vZGUgY29udGVudCwgYnV0IGZvdW5kICcsJ1wiKTtcbiAgICB9XG5cbiAgICBrZXlUYWcgPSBrZXlOb2RlID0gdmFsdWVOb2RlID0gbnVsbDtcbiAgICBpc1BhaXIgPSBpc0V4cGxpY2l0UGFpciA9IGZhbHNlO1xuXG4gICAgaWYgKGNoID09PSAweDNGLyogPyAqLykge1xuICAgICAgZm9sbG93aW5nID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbiArIDEpO1xuXG4gICAgICBpZiAoaXNfV1NfT1JfRU9MKGZvbGxvd2luZykpIHtcbiAgICAgICAgaXNQYWlyID0gaXNFeHBsaWNpdFBhaXIgPSB0cnVlO1xuICAgICAgICBzdGF0ZS5wb3NpdGlvbisrO1xuICAgICAgICBza2lwU2VwYXJhdGlvblNwYWNlKHN0YXRlLCB0cnVlLCBub2RlSW5kZW50KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBfbGluZSA9IHN0YXRlLmxpbmU7IC8vIFNhdmUgdGhlIGN1cnJlbnQgbGluZS5cbiAgICBfbGluZVN0YXJ0ID0gc3RhdGUubGluZVN0YXJ0O1xuICAgIF9wb3MgPSBzdGF0ZS5wb3NpdGlvbjtcbiAgICBjb21wb3NlTm9kZShzdGF0ZSwgbm9kZUluZGVudCwgQ09OVEVYVF9GTE9XX0lOLCBmYWxzZSwgdHJ1ZSk7XG4gICAga2V5VGFnID0gc3RhdGUudGFnO1xuICAgIGtleU5vZGUgPSBzdGF0ZS5yZXN1bHQ7XG4gICAgc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgbm9kZUluZGVudCk7XG5cbiAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuXG4gICAgaWYgKChpc0V4cGxpY2l0UGFpciB8fCBzdGF0ZS5saW5lID09PSBfbGluZSkgJiYgY2ggPT09IDB4M0EvKiA6ICovKSB7XG4gICAgICBpc1BhaXIgPSB0cnVlO1xuICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuICAgICAgc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgbm9kZUluZGVudCk7XG4gICAgICBjb21wb3NlTm9kZShzdGF0ZSwgbm9kZUluZGVudCwgQ09OVEVYVF9GTE9XX0lOLCBmYWxzZSwgdHJ1ZSk7XG4gICAgICB2YWx1ZU5vZGUgPSBzdGF0ZS5yZXN1bHQ7XG4gICAgfVxuXG4gICAgaWYgKGlzTWFwcGluZykge1xuICAgICAgc3RvcmVNYXBwaW5nUGFpcihzdGF0ZSwgX3Jlc3VsdCwgb3ZlcnJpZGFibGVLZXlzLCBrZXlUYWcsIGtleU5vZGUsIHZhbHVlTm9kZSwgX2xpbmUsIF9saW5lU3RhcnQsIF9wb3MpO1xuICAgIH0gZWxzZSBpZiAoaXNQYWlyKSB7XG4gICAgICBfcmVzdWx0LnB1c2goc3RvcmVNYXBwaW5nUGFpcihzdGF0ZSwgbnVsbCwgb3ZlcnJpZGFibGVLZXlzLCBrZXlUYWcsIGtleU5vZGUsIHZhbHVlTm9kZSwgX2xpbmUsIF9saW5lU3RhcnQsIF9wb3MpKTtcbiAgICB9IGVsc2Uge1xuICAgICAgX3Jlc3VsdC5wdXNoKGtleU5vZGUpO1xuICAgIH1cblxuICAgIHNraXBTZXBhcmF0aW9uU3BhY2Uoc3RhdGUsIHRydWUsIG5vZGVJbmRlbnQpO1xuXG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICAgIGlmIChjaCA9PT0gMHgyQy8qICwgKi8pIHtcbiAgICAgIHJlYWROZXh0ID0gdHJ1ZTtcbiAgICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVhZE5leHQgPSBmYWxzZTtcbiAgICB9XG4gIH1cblxuICB0aHJvd0Vycm9yKHN0YXRlLCAndW5leHBlY3RlZCBlbmQgb2YgdGhlIHN0cmVhbSB3aXRoaW4gYSBmbG93IGNvbGxlY3Rpb24nKTtcbn1cblxuZnVuY3Rpb24gcmVhZEJsb2NrU2NhbGFyKHN0YXRlLCBub2RlSW5kZW50KSB7XG4gIHZhciBjYXB0dXJlU3RhcnQsXG4gICAgICBmb2xkaW5nLFxuICAgICAgY2hvbXBpbmcgICAgICAgPSBDSE9NUElOR19DTElQLFxuICAgICAgZGlkUmVhZENvbnRlbnQgPSBmYWxzZSxcbiAgICAgIGRldGVjdGVkSW5kZW50ID0gZmFsc2UsXG4gICAgICB0ZXh0SW5kZW50ICAgICA9IG5vZGVJbmRlbnQsXG4gICAgICBlbXB0eUxpbmVzICAgICA9IDAsXG4gICAgICBhdE1vcmVJbmRlbnRlZCA9IGZhbHNlLFxuICAgICAgdG1wLFxuICAgICAgY2g7XG5cbiAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICBpZiAoY2ggPT09IDB4N0MvKiB8ICovKSB7XG4gICAgZm9sZGluZyA9IGZhbHNlO1xuICB9IGVsc2UgaWYgKGNoID09PSAweDNFLyogPiAqLykge1xuICAgIGZvbGRpbmcgPSB0cnVlO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIHN0YXRlLmtpbmQgPSAnc2NhbGFyJztcbiAgc3RhdGUucmVzdWx0ID0gJyc7XG5cbiAgd2hpbGUgKGNoICE9PSAwKSB7XG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuXG4gICAgaWYgKGNoID09PSAweDJCLyogKyAqLyB8fCBjaCA9PT0gMHgyRC8qIC0gKi8pIHtcbiAgICAgIGlmIChDSE9NUElOR19DTElQID09PSBjaG9tcGluZykge1xuICAgICAgICBjaG9tcGluZyA9IChjaCA9PT0gMHgyQi8qICsgKi8pID8gQ0hPTVBJTkdfS0VFUCA6IENIT01QSU5HX1NUUklQO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3JlcGVhdCBvZiBhIGNob21waW5nIG1vZGUgaWRlbnRpZmllcicpO1xuICAgICAgfVxuXG4gICAgfSBlbHNlIGlmICgodG1wID0gZnJvbURlY2ltYWxDb2RlKGNoKSkgPj0gMCkge1xuICAgICAgaWYgKHRtcCA9PT0gMCkge1xuICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnYmFkIGV4cGxpY2l0IGluZGVudGF0aW9uIHdpZHRoIG9mIGEgYmxvY2sgc2NhbGFyOyBpdCBjYW5ub3QgYmUgbGVzcyB0aGFuIG9uZScpO1xuICAgICAgfSBlbHNlIGlmICghZGV0ZWN0ZWRJbmRlbnQpIHtcbiAgICAgICAgdGV4dEluZGVudCA9IG5vZGVJbmRlbnQgKyB0bXAgLSAxO1xuICAgICAgICBkZXRlY3RlZEluZGVudCA9IHRydWU7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAncmVwZWF0IG9mIGFuIGluZGVudGF0aW9uIHdpZHRoIGlkZW50aWZpZXInKTtcbiAgICAgIH1cblxuICAgIH0gZWxzZSB7XG4gICAgICBicmVhaztcbiAgICB9XG4gIH1cblxuICBpZiAoaXNfV0hJVEVfU1BBQ0UoY2gpKSB7XG4gICAgZG8geyBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoKytzdGF0ZS5wb3NpdGlvbik7IH1cbiAgICB3aGlsZSAoaXNfV0hJVEVfU1BBQ0UoY2gpKTtcblxuICAgIGlmIChjaCA9PT0gMHgyMy8qICMgKi8pIHtcbiAgICAgIGRvIHsgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pOyB9XG4gICAgICB3aGlsZSAoIWlzX0VPTChjaCkgJiYgKGNoICE9PSAwKSk7XG4gICAgfVxuICB9XG5cbiAgd2hpbGUgKGNoICE9PSAwKSB7XG4gICAgcmVhZExpbmVCcmVhayhzdGF0ZSk7XG4gICAgc3RhdGUubGluZUluZGVudCA9IDA7XG5cbiAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuXG4gICAgd2hpbGUgKCghZGV0ZWN0ZWRJbmRlbnQgfHwgc3RhdGUubGluZUluZGVudCA8IHRleHRJbmRlbnQpICYmXG4gICAgICAgICAgIChjaCA9PT0gMHgyMC8qIFNwYWNlICovKSkge1xuICAgICAgc3RhdGUubGluZUluZGVudCsrO1xuICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuICAgIH1cblxuICAgIGlmICghZGV0ZWN0ZWRJbmRlbnQgJiYgc3RhdGUubGluZUluZGVudCA+IHRleHRJbmRlbnQpIHtcbiAgICAgIHRleHRJbmRlbnQgPSBzdGF0ZS5saW5lSW5kZW50O1xuICAgIH1cblxuICAgIGlmIChpc19FT0woY2gpKSB7XG4gICAgICBlbXB0eUxpbmVzKys7XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICAvLyBFbmQgb2YgdGhlIHNjYWxhci5cbiAgICBpZiAoc3RhdGUubGluZUluZGVudCA8IHRleHRJbmRlbnQpIHtcblxuICAgICAgLy8gUGVyZm9ybSB0aGUgY2hvbXBpbmcuXG4gICAgICBpZiAoY2hvbXBpbmcgPT09IENIT01QSU5HX0tFRVApIHtcbiAgICAgICAgc3RhdGUucmVzdWx0ICs9IGNvbW1vbi5yZXBlYXQoJ1xcbicsIGRpZFJlYWRDb250ZW50ID8gMSArIGVtcHR5TGluZXMgOiBlbXB0eUxpbmVzKTtcbiAgICAgIH0gZWxzZSBpZiAoY2hvbXBpbmcgPT09IENIT01QSU5HX0NMSVApIHtcbiAgICAgICAgaWYgKGRpZFJlYWRDb250ZW50KSB7IC8vIGkuZS4gb25seSBpZiB0aGUgc2NhbGFyIGlzIG5vdCBlbXB0eS5cbiAgICAgICAgICBzdGF0ZS5yZXN1bHQgKz0gJ1xcbic7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgLy8gQnJlYWsgdGhpcyBgd2hpbGVgIGN5Y2xlIGFuZCBnbyB0byB0aGUgZnVuY2l0b24ncyBlcGlsb2d1ZS5cbiAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIC8vIEZvbGRlZCBzdHlsZTogdXNlIGZhbmN5IHJ1bGVzIHRvIGhhbmRsZSBsaW5lIGJyZWFrcy5cbiAgICBpZiAoZm9sZGluZykge1xuXG4gICAgICAvLyBMaW5lcyBzdGFydGluZyB3aXRoIHdoaXRlIHNwYWNlIGNoYXJhY3RlcnMgKG1vcmUtaW5kZW50ZWQgbGluZXMpIGFyZSBub3QgZm9sZGVkLlxuICAgICAgaWYgKGlzX1dISVRFX1NQQUNFKGNoKSkge1xuICAgICAgICBhdE1vcmVJbmRlbnRlZCA9IHRydWU7XG4gICAgICAgIC8vIGV4Y2VwdCBmb3IgdGhlIGZpcnN0IGNvbnRlbnQgbGluZSAoY2YuIEV4YW1wbGUgOC4xKVxuICAgICAgICBzdGF0ZS5yZXN1bHQgKz0gY29tbW9uLnJlcGVhdCgnXFxuJywgZGlkUmVhZENvbnRlbnQgPyAxICsgZW1wdHlMaW5lcyA6IGVtcHR5TGluZXMpO1xuXG4gICAgICAvLyBFbmQgb2YgbW9yZS1pbmRlbnRlZCBibG9jay5cbiAgICAgIH0gZWxzZSBpZiAoYXRNb3JlSW5kZW50ZWQpIHtcbiAgICAgICAgYXRNb3JlSW5kZW50ZWQgPSBmYWxzZTtcbiAgICAgICAgc3RhdGUucmVzdWx0ICs9IGNvbW1vbi5yZXBlYXQoJ1xcbicsIGVtcHR5TGluZXMgKyAxKTtcblxuICAgICAgLy8gSnVzdCBvbmUgbGluZSBicmVhayAtIHBlcmNlaXZlIGFzIHRoZSBzYW1lIGxpbmUuXG4gICAgICB9IGVsc2UgaWYgKGVtcHR5TGluZXMgPT09IDApIHtcbiAgICAgICAgaWYgKGRpZFJlYWRDb250ZW50KSB7IC8vIGkuZS4gb25seSBpZiB3ZSBoYXZlIGFscmVhZHkgcmVhZCBzb21lIHNjYWxhciBjb250ZW50LlxuICAgICAgICAgIHN0YXRlLnJlc3VsdCArPSAnICc7XG4gICAgICAgIH1cblxuICAgICAgLy8gU2V2ZXJhbCBsaW5lIGJyZWFrcyAtIHBlcmNlaXZlIGFzIGRpZmZlcmVudCBsaW5lcy5cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHN0YXRlLnJlc3VsdCArPSBjb21tb24ucmVwZWF0KCdcXG4nLCBlbXB0eUxpbmVzKTtcbiAgICAgIH1cblxuICAgIC8vIExpdGVyYWwgc3R5bGU6IGp1c3QgYWRkIGV4YWN0IG51bWJlciBvZiBsaW5lIGJyZWFrcyBiZXR3ZWVuIGNvbnRlbnQgbGluZXMuXG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIEtlZXAgYWxsIGxpbmUgYnJlYWtzIGV4Y2VwdCB0aGUgaGVhZGVyIGxpbmUgYnJlYWsuXG4gICAgICBzdGF0ZS5yZXN1bHQgKz0gY29tbW9uLnJlcGVhdCgnXFxuJywgZGlkUmVhZENvbnRlbnQgPyAxICsgZW1wdHlMaW5lcyA6IGVtcHR5TGluZXMpO1xuICAgIH1cblxuICAgIGRpZFJlYWRDb250ZW50ID0gdHJ1ZTtcbiAgICBkZXRlY3RlZEluZGVudCA9IHRydWU7XG4gICAgZW1wdHlMaW5lcyA9IDA7XG4gICAgY2FwdHVyZVN0YXJ0ID0gc3RhdGUucG9zaXRpb247XG5cbiAgICB3aGlsZSAoIWlzX0VPTChjaCkgJiYgKGNoICE9PSAwKSkge1xuICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuICAgIH1cblxuICAgIGNhcHR1cmVTZWdtZW50KHN0YXRlLCBjYXB0dXJlU3RhcnQsIHN0YXRlLnBvc2l0aW9uLCBmYWxzZSk7XG4gIH1cblxuICByZXR1cm4gdHJ1ZTtcbn1cblxuZnVuY3Rpb24gcmVhZEJsb2NrU2VxdWVuY2Uoc3RhdGUsIG5vZGVJbmRlbnQpIHtcbiAgdmFyIF9saW5lLFxuICAgICAgX3RhZyAgICAgID0gc3RhdGUudGFnLFxuICAgICAgX2FuY2hvciAgID0gc3RhdGUuYW5jaG9yLFxuICAgICAgX3Jlc3VsdCAgID0gW10sXG4gICAgICBmb2xsb3dpbmcsXG4gICAgICBkZXRlY3RlZCAgPSBmYWxzZSxcbiAgICAgIGNoO1xuXG4gIC8vIHRoZXJlIGlzIGEgbGVhZGluZyB0YWIgYmVmb3JlIHRoaXMgdG9rZW4sIHNvIGl0IGNhbid0IGJlIGEgYmxvY2sgc2VxdWVuY2UvbWFwcGluZztcbiAgLy8gaXQgY2FuIHN0aWxsIGJlIGZsb3cgc2VxdWVuY2UvbWFwcGluZyBvciBhIHNjYWxhclxuICBpZiAoc3RhdGUuZmlyc3RUYWJJbkxpbmUgIT09IC0xKSByZXR1cm4gZmFsc2U7XG5cbiAgaWYgKHN0YXRlLmFuY2hvciAhPT0gbnVsbCkge1xuICAgIHN0YXRlLmFuY2hvck1hcFtzdGF0ZS5hbmNob3JdID0gX3Jlc3VsdDtcbiAgfVxuXG4gIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbik7XG5cbiAgd2hpbGUgKGNoICE9PSAwKSB7XG4gICAgaWYgKHN0YXRlLmZpcnN0VGFiSW5MaW5lICE9PSAtMSkge1xuICAgICAgc3RhdGUucG9zaXRpb24gPSBzdGF0ZS5maXJzdFRhYkluTGluZTtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICd0YWIgY2hhcmFjdGVycyBtdXN0IG5vdCBiZSB1c2VkIGluIGluZGVudGF0aW9uJyk7XG4gICAgfVxuXG4gICAgaWYgKGNoICE9PSAweDJELyogLSAqLykge1xuICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgZm9sbG93aW5nID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbiArIDEpO1xuXG4gICAgaWYgKCFpc19XU19PUl9FT0woZm9sbG93aW5nKSkge1xuICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgZGV0ZWN0ZWQgPSB0cnVlO1xuICAgIHN0YXRlLnBvc2l0aW9uKys7XG5cbiAgICBpZiAoc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgLTEpKSB7XG4gICAgICBpZiAoc3RhdGUubGluZUluZGVudCA8PSBub2RlSW5kZW50KSB7XG4gICAgICAgIF9yZXN1bHQucHVzaChudWxsKTtcbiAgICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgfVxuXG4gICAgX2xpbmUgPSBzdGF0ZS5saW5lO1xuICAgIGNvbXBvc2VOb2RlKHN0YXRlLCBub2RlSW5kZW50LCBDT05URVhUX0JMT0NLX0lOLCBmYWxzZSwgdHJ1ZSk7XG4gICAgX3Jlc3VsdC5wdXNoKHN0YXRlLnJlc3VsdCk7XG4gICAgc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgLTEpO1xuXG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICAgIGlmICgoc3RhdGUubGluZSA9PT0gX2xpbmUgfHwgc3RhdGUubGluZUluZGVudCA+IG5vZGVJbmRlbnQpICYmIChjaCAhPT0gMCkpIHtcbiAgICAgIHRocm93RXJyb3Ioc3RhdGUsICdiYWQgaW5kZW50YXRpb24gb2YgYSBzZXF1ZW5jZSBlbnRyeScpO1xuICAgIH0gZWxzZSBpZiAoc3RhdGUubGluZUluZGVudCA8IG5vZGVJbmRlbnQpIHtcbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgfVxuXG4gIGlmIChkZXRlY3RlZCkge1xuICAgIHN0YXRlLnRhZyA9IF90YWc7XG4gICAgc3RhdGUuYW5jaG9yID0gX2FuY2hvcjtcbiAgICBzdGF0ZS5raW5kID0gJ3NlcXVlbmNlJztcbiAgICBzdGF0ZS5yZXN1bHQgPSBfcmVzdWx0O1xuICAgIHJldHVybiB0cnVlO1xuICB9XG4gIHJldHVybiBmYWxzZTtcbn1cblxuZnVuY3Rpb24gcmVhZEJsb2NrTWFwcGluZyhzdGF0ZSwgbm9kZUluZGVudCwgZmxvd0luZGVudCkge1xuICB2YXIgZm9sbG93aW5nLFxuICAgICAgYWxsb3dDb21wYWN0LFxuICAgICAgX2xpbmUsXG4gICAgICBfa2V5TGluZSxcbiAgICAgIF9rZXlMaW5lU3RhcnQsXG4gICAgICBfa2V5UG9zLFxuICAgICAgX3RhZyAgICAgICAgICA9IHN0YXRlLnRhZyxcbiAgICAgIF9hbmNob3IgICAgICAgPSBzdGF0ZS5hbmNob3IsXG4gICAgICBfcmVzdWx0ICAgICAgID0ge30sXG4gICAgICBvdmVycmlkYWJsZUtleXMgPSBPYmplY3QuY3JlYXRlKG51bGwpLFxuICAgICAga2V5VGFnICAgICAgICA9IG51bGwsXG4gICAgICBrZXlOb2RlICAgICAgID0gbnVsbCxcbiAgICAgIHZhbHVlTm9kZSAgICAgPSBudWxsLFxuICAgICAgYXRFeHBsaWNpdEtleSA9IGZhbHNlLFxuICAgICAgZGV0ZWN0ZWQgICAgICA9IGZhbHNlLFxuICAgICAgY2g7XG5cbiAgLy8gdGhlcmUgaXMgYSBsZWFkaW5nIHRhYiBiZWZvcmUgdGhpcyB0b2tlbiwgc28gaXQgY2FuJ3QgYmUgYSBibG9jayBzZXF1ZW5jZS9tYXBwaW5nO1xuICAvLyBpdCBjYW4gc3RpbGwgYmUgZmxvdyBzZXF1ZW5jZS9tYXBwaW5nIG9yIGEgc2NhbGFyXG4gIGlmIChzdGF0ZS5maXJzdFRhYkluTGluZSAhPT0gLTEpIHJldHVybiBmYWxzZTtcblxuICBpZiAoc3RhdGUuYW5jaG9yICE9PSBudWxsKSB7XG4gICAgc3RhdGUuYW5jaG9yTWFwW3N0YXRlLmFuY2hvcl0gPSBfcmVzdWx0O1xuICB9XG5cbiAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICB3aGlsZSAoY2ggIT09IDApIHtcbiAgICBpZiAoIWF0RXhwbGljaXRLZXkgJiYgc3RhdGUuZmlyc3RUYWJJbkxpbmUgIT09IC0xKSB7XG4gICAgICBzdGF0ZS5wb3NpdGlvbiA9IHN0YXRlLmZpcnN0VGFiSW5MaW5lO1xuICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3RhYiBjaGFyYWN0ZXJzIG11c3Qgbm90IGJlIHVzZWQgaW4gaW5kZW50YXRpb24nKTtcbiAgICB9XG5cbiAgICBmb2xsb3dpbmcgPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uICsgMSk7XG4gICAgX2xpbmUgPSBzdGF0ZS5saW5lOyAvLyBTYXZlIHRoZSBjdXJyZW50IGxpbmUuXG5cbiAgICAvL1xuICAgIC8vIEV4cGxpY2l0IG5vdGF0aW9uIGNhc2UuIFRoZXJlIGFyZSB0d28gc2VwYXJhdGUgYmxvY2tzOlxuICAgIC8vIGZpcnN0IGZvciB0aGUga2V5IChkZW5vdGVkIGJ5IFwiP1wiKSBhbmQgc2Vjb25kIGZvciB0aGUgdmFsdWUgKGRlbm90ZWQgYnkgXCI6XCIpXG4gICAgLy9cbiAgICBpZiAoKGNoID09PSAweDNGLyogPyAqLyB8fCBjaCA9PT0gMHgzQS8qIDogKi8pICYmIGlzX1dTX09SX0VPTChmb2xsb3dpbmcpKSB7XG5cbiAgICAgIGlmIChjaCA9PT0gMHgzRi8qID8gKi8pIHtcbiAgICAgICAgaWYgKGF0RXhwbGljaXRLZXkpIHtcbiAgICAgICAgICBzdG9yZU1hcHBpbmdQYWlyKHN0YXRlLCBfcmVzdWx0LCBvdmVycmlkYWJsZUtleXMsIGtleVRhZywga2V5Tm9kZSwgbnVsbCwgX2tleUxpbmUsIF9rZXlMaW5lU3RhcnQsIF9rZXlQb3MpO1xuICAgICAgICAgIGtleVRhZyA9IGtleU5vZGUgPSB2YWx1ZU5vZGUgPSBudWxsO1xuICAgICAgICB9XG5cbiAgICAgICAgZGV0ZWN0ZWQgPSB0cnVlO1xuICAgICAgICBhdEV4cGxpY2l0S2V5ID0gdHJ1ZTtcbiAgICAgICAgYWxsb3dDb21wYWN0ID0gdHJ1ZTtcblxuICAgICAgfSBlbHNlIGlmIChhdEV4cGxpY2l0S2V5KSB7XG4gICAgICAgIC8vIGkuZS4gMHgzQS8qIDogKi8gPT09IGNoYXJhY3RlciBhZnRlciB0aGUgZXhwbGljaXQga2V5LlxuICAgICAgICBhdEV4cGxpY2l0S2V5ID0gZmFsc2U7XG4gICAgICAgIGFsbG93Q29tcGFjdCA9IHRydWU7XG5cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRocm93RXJyb3Ioc3RhdGUsICdpbmNvbXBsZXRlIGV4cGxpY2l0IG1hcHBpbmcgcGFpcjsgYSBrZXkgbm9kZSBpcyBtaXNzZWQ7IG9yIGZvbGxvd2VkIGJ5IGEgbm9uLXRhYnVsYXRlZCBlbXB0eSBsaW5lJyk7XG4gICAgICB9XG5cbiAgICAgIHN0YXRlLnBvc2l0aW9uICs9IDE7XG4gICAgICBjaCA9IGZvbGxvd2luZztcblxuICAgIC8vXG4gICAgLy8gSW1wbGljaXQgbm90YXRpb24gY2FzZS4gRmxvdy1zdHlsZSBub2RlIGFzIHRoZSBrZXkgZmlyc3QsIHRoZW4gXCI6XCIsIGFuZCB0aGUgdmFsdWUuXG4gICAgLy9cbiAgICB9IGVsc2Uge1xuICAgICAgX2tleUxpbmUgPSBzdGF0ZS5saW5lO1xuICAgICAgX2tleUxpbmVTdGFydCA9IHN0YXRlLmxpbmVTdGFydDtcbiAgICAgIF9rZXlQb3MgPSBzdGF0ZS5wb3NpdGlvbjtcblxuICAgICAgaWYgKCFjb21wb3NlTm9kZShzdGF0ZSwgZmxvd0luZGVudCwgQ09OVEVYVF9GTE9XX09VVCwgZmFsc2UsIHRydWUpKSB7XG4gICAgICAgIC8vIE5laXRoZXIgaW1wbGljaXQgbm9yIGV4cGxpY2l0IG5vdGF0aW9uLlxuICAgICAgICAvLyBSZWFkaW5nIGlzIGRvbmUuIEdvIHRvIHRoZSBlcGlsb2d1ZS5cbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG5cbiAgICAgIGlmIChzdGF0ZS5saW5lID09PSBfbGluZSkge1xuICAgICAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pO1xuXG4gICAgICAgIHdoaWxlIChpc19XSElURV9TUEFDRShjaCkpIHtcbiAgICAgICAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoKytzdGF0ZS5wb3NpdGlvbik7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoY2ggPT09IDB4M0EvKiA6ICovKSB7XG4gICAgICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuXG4gICAgICAgICAgaWYgKCFpc19XU19PUl9FT0woY2gpKSB7XG4gICAgICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnYSB3aGl0ZXNwYWNlIGNoYXJhY3RlciBpcyBleHBlY3RlZCBhZnRlciB0aGUga2V5LXZhbHVlIHNlcGFyYXRvciB3aXRoaW4gYSBibG9jayBtYXBwaW5nJyk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKGF0RXhwbGljaXRLZXkpIHtcbiAgICAgICAgICAgIHN0b3JlTWFwcGluZ1BhaXIoc3RhdGUsIF9yZXN1bHQsIG92ZXJyaWRhYmxlS2V5cywga2V5VGFnLCBrZXlOb2RlLCBudWxsLCBfa2V5TGluZSwgX2tleUxpbmVTdGFydCwgX2tleVBvcyk7XG4gICAgICAgICAgICBrZXlUYWcgPSBrZXlOb2RlID0gdmFsdWVOb2RlID0gbnVsbDtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBkZXRlY3RlZCA9IHRydWU7XG4gICAgICAgICAgYXRFeHBsaWNpdEtleSA9IGZhbHNlO1xuICAgICAgICAgIGFsbG93Q29tcGFjdCA9IGZhbHNlO1xuICAgICAgICAgIGtleVRhZyA9IHN0YXRlLnRhZztcbiAgICAgICAgICBrZXlOb2RlID0gc3RhdGUucmVzdWx0O1xuXG4gICAgICAgIH0gZWxzZSBpZiAoZGV0ZWN0ZWQpIHtcbiAgICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnY2FuIG5vdCByZWFkIGFuIGltcGxpY2l0IG1hcHBpbmcgcGFpcjsgYSBjb2xvbiBpcyBtaXNzZWQnKTtcblxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHN0YXRlLnRhZyA9IF90YWc7XG4gICAgICAgICAgc3RhdGUuYW5jaG9yID0gX2FuY2hvcjtcbiAgICAgICAgICByZXR1cm4gdHJ1ZTsgLy8gS2VlcCB0aGUgcmVzdWx0IG9mIGBjb21wb3NlTm9kZWAuXG4gICAgICAgIH1cblxuICAgICAgfSBlbHNlIGlmIChkZXRlY3RlZCkge1xuICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnY2FuIG5vdCByZWFkIGEgYmxvY2sgbWFwcGluZyBlbnRyeTsgYSBtdWx0aWxpbmUga2V5IG1heSBub3QgYmUgYW4gaW1wbGljaXQga2V5Jyk7XG5cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHN0YXRlLnRhZyA9IF90YWc7XG4gICAgICAgIHN0YXRlLmFuY2hvciA9IF9hbmNob3I7XG4gICAgICAgIHJldHVybiB0cnVlOyAvLyBLZWVwIHRoZSByZXN1bHQgb2YgYGNvbXBvc2VOb2RlYC5cbiAgICAgIH1cbiAgICB9XG5cbiAgICAvL1xuICAgIC8vIENvbW1vbiByZWFkaW5nIGNvZGUgZm9yIGJvdGggZXhwbGljaXQgYW5kIGltcGxpY2l0IG5vdGF0aW9ucy5cbiAgICAvL1xuICAgIGlmIChzdGF0ZS5saW5lID09PSBfbGluZSB8fCBzdGF0ZS5saW5lSW5kZW50ID4gbm9kZUluZGVudCkge1xuICAgICAgaWYgKGF0RXhwbGljaXRLZXkpIHtcbiAgICAgICAgX2tleUxpbmUgPSBzdGF0ZS5saW5lO1xuICAgICAgICBfa2V5TGluZVN0YXJ0ID0gc3RhdGUubGluZVN0YXJ0O1xuICAgICAgICBfa2V5UG9zID0gc3RhdGUucG9zaXRpb247XG4gICAgICB9XG5cbiAgICAgIGlmIChjb21wb3NlTm9kZShzdGF0ZSwgbm9kZUluZGVudCwgQ09OVEVYVF9CTE9DS19PVVQsIHRydWUsIGFsbG93Q29tcGFjdCkpIHtcbiAgICAgICAgaWYgKGF0RXhwbGljaXRLZXkpIHtcbiAgICAgICAgICBrZXlOb2RlID0gc3RhdGUucmVzdWx0O1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHZhbHVlTm9kZSA9IHN0YXRlLnJlc3VsdDtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoIWF0RXhwbGljaXRLZXkpIHtcbiAgICAgICAgc3RvcmVNYXBwaW5nUGFpcihzdGF0ZSwgX3Jlc3VsdCwgb3ZlcnJpZGFibGVLZXlzLCBrZXlUYWcsIGtleU5vZGUsIHZhbHVlTm9kZSwgX2tleUxpbmUsIF9rZXlMaW5lU3RhcnQsIF9rZXlQb3MpO1xuICAgICAgICBrZXlUYWcgPSBrZXlOb2RlID0gdmFsdWVOb2RlID0gbnVsbDtcbiAgICAgIH1cblxuICAgICAgc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgLTEpO1xuICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcbiAgICB9XG5cbiAgICBpZiAoKHN0YXRlLmxpbmUgPT09IF9saW5lIHx8IHN0YXRlLmxpbmVJbmRlbnQgPiBub2RlSW5kZW50KSAmJiAoY2ggIT09IDApKSB7XG4gICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnYmFkIGluZGVudGF0aW9uIG9mIGEgbWFwcGluZyBlbnRyeScpO1xuICAgIH0gZWxzZSBpZiAoc3RhdGUubGluZUluZGVudCA8IG5vZGVJbmRlbnQpIHtcbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgfVxuXG4gIC8vXG4gIC8vIEVwaWxvZ3VlLlxuICAvL1xuXG4gIC8vIFNwZWNpYWwgY2FzZTogbGFzdCBtYXBwaW5nJ3Mgbm9kZSBjb250YWlucyBvbmx5IHRoZSBrZXkgaW4gZXhwbGljaXQgbm90YXRpb24uXG4gIGlmIChhdEV4cGxpY2l0S2V5KSB7XG4gICAgc3RvcmVNYXBwaW5nUGFpcihzdGF0ZSwgX3Jlc3VsdCwgb3ZlcnJpZGFibGVLZXlzLCBrZXlUYWcsIGtleU5vZGUsIG51bGwsIF9rZXlMaW5lLCBfa2V5TGluZVN0YXJ0LCBfa2V5UG9zKTtcbiAgfVxuXG4gIC8vIEV4cG9zZSB0aGUgcmVzdWx0aW5nIG1hcHBpbmcuXG4gIGlmIChkZXRlY3RlZCkge1xuICAgIHN0YXRlLnRhZyA9IF90YWc7XG4gICAgc3RhdGUuYW5jaG9yID0gX2FuY2hvcjtcbiAgICBzdGF0ZS5raW5kID0gJ21hcHBpbmcnO1xuICAgIHN0YXRlLnJlc3VsdCA9IF9yZXN1bHQ7XG4gIH1cblxuICByZXR1cm4gZGV0ZWN0ZWQ7XG59XG5cbmZ1bmN0aW9uIHJlYWRUYWdQcm9wZXJ0eShzdGF0ZSkge1xuICB2YXIgX3Bvc2l0aW9uLFxuICAgICAgaXNWZXJiYXRpbSA9IGZhbHNlLFxuICAgICAgaXNOYW1lZCAgICA9IGZhbHNlLFxuICAgICAgdGFnSGFuZGxlLFxuICAgICAgdGFnTmFtZSxcbiAgICAgIGNoO1xuXG4gIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbik7XG5cbiAgaWYgKGNoICE9PSAweDIxLyogISAqLykgcmV0dXJuIGZhbHNlO1xuXG4gIGlmIChzdGF0ZS50YWcgIT09IG51bGwpIHtcbiAgICB0aHJvd0Vycm9yKHN0YXRlLCAnZHVwbGljYXRpb24gb2YgYSB0YWcgcHJvcGVydHknKTtcbiAgfVxuXG4gIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcblxuICBpZiAoY2ggPT09IDB4M0MvKiA8ICovKSB7XG4gICAgaXNWZXJiYXRpbSA9IHRydWU7XG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuXG4gIH0gZWxzZSBpZiAoY2ggPT09IDB4MjEvKiAhICovKSB7XG4gICAgaXNOYW1lZCA9IHRydWU7XG4gICAgdGFnSGFuZGxlID0gJyEhJztcbiAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoKytzdGF0ZS5wb3NpdGlvbik7XG5cbiAgfSBlbHNlIHtcbiAgICB0YWdIYW5kbGUgPSAnISc7XG4gIH1cblxuICBfcG9zaXRpb24gPSBzdGF0ZS5wb3NpdGlvbjtcblxuICBpZiAoaXNWZXJiYXRpbSkge1xuICAgIGRvIHsgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pOyB9XG4gICAgd2hpbGUgKGNoICE9PSAwICYmIGNoICE9PSAweDNFLyogPiAqLyk7XG5cbiAgICBpZiAoc3RhdGUucG9zaXRpb24gPCBzdGF0ZS5sZW5ndGgpIHtcbiAgICAgIHRhZ05hbWUgPSBzdGF0ZS5pbnB1dC5zbGljZShfcG9zaXRpb24sIHN0YXRlLnBvc2l0aW9uKTtcbiAgICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3VuZXhwZWN0ZWQgZW5kIG9mIHRoZSBzdHJlYW0gd2l0aGluIGEgdmVyYmF0aW0gdGFnJyk7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIHdoaWxlIChjaCAhPT0gMCAmJiAhaXNfV1NfT1JfRU9MKGNoKSkge1xuXG4gICAgICBpZiAoY2ggPT09IDB4MjEvKiAhICovKSB7XG4gICAgICAgIGlmICghaXNOYW1lZCkge1xuICAgICAgICAgIHRhZ0hhbmRsZSA9IHN0YXRlLmlucHV0LnNsaWNlKF9wb3NpdGlvbiAtIDEsIHN0YXRlLnBvc2l0aW9uICsgMSk7XG5cbiAgICAgICAgICBpZiAoIVBBVFRFUk5fVEFHX0hBTkRMRS50ZXN0KHRhZ0hhbmRsZSkpIHtcbiAgICAgICAgICAgIHRocm93RXJyb3Ioc3RhdGUsICduYW1lZCB0YWcgaGFuZGxlIGNhbm5vdCBjb250YWluIHN1Y2ggY2hhcmFjdGVycycpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlzTmFtZWQgPSB0cnVlO1xuICAgICAgICAgIF9wb3NpdGlvbiA9IHN0YXRlLnBvc2l0aW9uICsgMTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAndGFnIHN1ZmZpeCBjYW5ub3QgY29udGFpbiBleGNsYW1hdGlvbiBtYXJrcycpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgICB9XG5cbiAgICB0YWdOYW1lID0gc3RhdGUuaW5wdXQuc2xpY2UoX3Bvc2l0aW9uLCBzdGF0ZS5wb3NpdGlvbik7XG5cbiAgICBpZiAoUEFUVEVSTl9GTE9XX0lORElDQVRPUlMudGVzdCh0YWdOYW1lKSkge1xuICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3RhZyBzdWZmaXggY2Fubm90IGNvbnRhaW4gZmxvdyBpbmRpY2F0b3IgY2hhcmFjdGVycycpO1xuICAgIH1cbiAgfVxuXG4gIGlmICh0YWdOYW1lICYmICFQQVRURVJOX1RBR19VUkkudGVzdCh0YWdOYW1lKSkge1xuICAgIHRocm93RXJyb3Ioc3RhdGUsICd0YWcgbmFtZSBjYW5ub3QgY29udGFpbiBzdWNoIGNoYXJhY3RlcnM6ICcgKyB0YWdOYW1lKTtcbiAgfVxuXG4gIHRyeSB7XG4gICAgdGFnTmFtZSA9IGRlY29kZVVSSUNvbXBvbmVudCh0YWdOYW1lKTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3RhZyBuYW1lIGlzIG1hbGZvcm1lZDogJyArIHRhZ05hbWUpO1xuICB9XG5cbiAgaWYgKGlzVmVyYmF0aW0pIHtcbiAgICBzdGF0ZS50YWcgPSB0YWdOYW1lO1xuXG4gIH0gZWxzZSBpZiAoX2hhc093blByb3BlcnR5JDEuY2FsbChzdGF0ZS50YWdNYXAsIHRhZ0hhbmRsZSkpIHtcbiAgICBzdGF0ZS50YWcgPSBzdGF0ZS50YWdNYXBbdGFnSGFuZGxlXSArIHRhZ05hbWU7XG5cbiAgfSBlbHNlIGlmICh0YWdIYW5kbGUgPT09ICchJykge1xuICAgIHN0YXRlLnRhZyA9ICchJyArIHRhZ05hbWU7XG5cbiAgfSBlbHNlIGlmICh0YWdIYW5kbGUgPT09ICchIScpIHtcbiAgICBzdGF0ZS50YWcgPSAndGFnOnlhbWwub3JnLDIwMDI6JyArIHRhZ05hbWU7XG5cbiAgfSBlbHNlIHtcbiAgICB0aHJvd0Vycm9yKHN0YXRlLCAndW5kZWNsYXJlZCB0YWcgaGFuZGxlIFwiJyArIHRhZ0hhbmRsZSArICdcIicpO1xuICB9XG5cbiAgcmV0dXJuIHRydWU7XG59XG5cbmZ1bmN0aW9uIHJlYWRBbmNob3JQcm9wZXJ0eShzdGF0ZSkge1xuICB2YXIgX3Bvc2l0aW9uLFxuICAgICAgY2g7XG5cbiAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICBpZiAoY2ggIT09IDB4MjYvKiAmICovKSByZXR1cm4gZmFsc2U7XG5cbiAgaWYgKHN0YXRlLmFuY2hvciAhPT0gbnVsbCkge1xuICAgIHRocm93RXJyb3Ioc3RhdGUsICdkdXBsaWNhdGlvbiBvZiBhbiBhbmNob3IgcHJvcGVydHknKTtcbiAgfVxuXG4gIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgX3Bvc2l0aW9uID0gc3RhdGUucG9zaXRpb247XG5cbiAgd2hpbGUgKGNoICE9PSAwICYmICFpc19XU19PUl9FT0woY2gpICYmICFpc19GTE9XX0lORElDQVRPUihjaCkpIHtcbiAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoKytzdGF0ZS5wb3NpdGlvbik7XG4gIH1cblxuICBpZiAoc3RhdGUucG9zaXRpb24gPT09IF9wb3NpdGlvbikge1xuICAgIHRocm93RXJyb3Ioc3RhdGUsICduYW1lIG9mIGFuIGFuY2hvciBub2RlIG11c3QgY29udGFpbiBhdCBsZWFzdCBvbmUgY2hhcmFjdGVyJyk7XG4gIH1cblxuICBzdGF0ZS5hbmNob3IgPSBzdGF0ZS5pbnB1dC5zbGljZShfcG9zaXRpb24sIHN0YXRlLnBvc2l0aW9uKTtcbiAgcmV0dXJuIHRydWU7XG59XG5cbmZ1bmN0aW9uIHJlYWRBbGlhcyhzdGF0ZSkge1xuICB2YXIgX3Bvc2l0aW9uLCBhbGlhcyxcbiAgICAgIGNoO1xuXG4gIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbik7XG5cbiAgaWYgKGNoICE9PSAweDJBLyogKiAqLykgcmV0dXJuIGZhbHNlO1xuXG4gIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgX3Bvc2l0aW9uID0gc3RhdGUucG9zaXRpb247XG5cbiAgd2hpbGUgKGNoICE9PSAwICYmICFpc19XU19PUl9FT0woY2gpICYmICFpc19GTE9XX0lORElDQVRPUihjaCkpIHtcbiAgICBjaCA9IHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoKytzdGF0ZS5wb3NpdGlvbik7XG4gIH1cblxuICBpZiAoc3RhdGUucG9zaXRpb24gPT09IF9wb3NpdGlvbikge1xuICAgIHRocm93RXJyb3Ioc3RhdGUsICduYW1lIG9mIGFuIGFsaWFzIG5vZGUgbXVzdCBjb250YWluIGF0IGxlYXN0IG9uZSBjaGFyYWN0ZXInKTtcbiAgfVxuXG4gIGFsaWFzID0gc3RhdGUuaW5wdXQuc2xpY2UoX3Bvc2l0aW9uLCBzdGF0ZS5wb3NpdGlvbik7XG5cbiAgaWYgKCFfaGFzT3duUHJvcGVydHkkMS5jYWxsKHN0YXRlLmFuY2hvck1hcCwgYWxpYXMpKSB7XG4gICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3VuaWRlbnRpZmllZCBhbGlhcyBcIicgKyBhbGlhcyArICdcIicpO1xuICB9XG5cbiAgc3RhdGUucmVzdWx0ID0gc3RhdGUuYW5jaG9yTWFwW2FsaWFzXTtcbiAgc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgLTEpO1xuICByZXR1cm4gdHJ1ZTtcbn1cblxuZnVuY3Rpb24gY29tcG9zZU5vZGUoc3RhdGUsIHBhcmVudEluZGVudCwgbm9kZUNvbnRleHQsIGFsbG93VG9TZWVrLCBhbGxvd0NvbXBhY3QpIHtcbiAgdmFyIGFsbG93QmxvY2tTdHlsZXMsXG4gICAgICBhbGxvd0Jsb2NrU2NhbGFycyxcbiAgICAgIGFsbG93QmxvY2tDb2xsZWN0aW9ucyxcbiAgICAgIGluZGVudFN0YXR1cyA9IDEsIC8vIDE6IHRoaXM+cGFyZW50LCAwOiB0aGlzPXBhcmVudCwgLTE6IHRoaXM8cGFyZW50XG4gICAgICBhdE5ld0xpbmUgID0gZmFsc2UsXG4gICAgICBoYXNDb250ZW50ID0gZmFsc2UsXG4gICAgICB0eXBlSW5kZXgsXG4gICAgICB0eXBlUXVhbnRpdHksXG4gICAgICB0eXBlTGlzdCxcbiAgICAgIHR5cGUsXG4gICAgICBmbG93SW5kZW50LFxuICAgICAgYmxvY2tJbmRlbnQ7XG5cbiAgaWYgKHN0YXRlLmxpc3RlbmVyICE9PSBudWxsKSB7XG4gICAgc3RhdGUubGlzdGVuZXIoJ29wZW4nLCBzdGF0ZSk7XG4gIH1cblxuICBzdGF0ZS50YWcgICAgPSBudWxsO1xuICBzdGF0ZS5hbmNob3IgPSBudWxsO1xuICBzdGF0ZS5raW5kICAgPSBudWxsO1xuICBzdGF0ZS5yZXN1bHQgPSBudWxsO1xuXG4gIGFsbG93QmxvY2tTdHlsZXMgPSBhbGxvd0Jsb2NrU2NhbGFycyA9IGFsbG93QmxvY2tDb2xsZWN0aW9ucyA9XG4gICAgQ09OVEVYVF9CTE9DS19PVVQgPT09IG5vZGVDb250ZXh0IHx8XG4gICAgQ09OVEVYVF9CTE9DS19JTiAgPT09IG5vZGVDb250ZXh0O1xuXG4gIGlmIChhbGxvd1RvU2Vlaykge1xuICAgIGlmIChza2lwU2VwYXJhdGlvblNwYWNlKHN0YXRlLCB0cnVlLCAtMSkpIHtcbiAgICAgIGF0TmV3TGluZSA9IHRydWU7XG5cbiAgICAgIGlmIChzdGF0ZS5saW5lSW5kZW50ID4gcGFyZW50SW5kZW50KSB7XG4gICAgICAgIGluZGVudFN0YXR1cyA9IDE7XG4gICAgICB9IGVsc2UgaWYgKHN0YXRlLmxpbmVJbmRlbnQgPT09IHBhcmVudEluZGVudCkge1xuICAgICAgICBpbmRlbnRTdGF0dXMgPSAwO1xuICAgICAgfSBlbHNlIGlmIChzdGF0ZS5saW5lSW5kZW50IDwgcGFyZW50SW5kZW50KSB7XG4gICAgICAgIGluZGVudFN0YXR1cyA9IC0xO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGlmIChpbmRlbnRTdGF0dXMgPT09IDEpIHtcbiAgICB3aGlsZSAocmVhZFRhZ1Byb3BlcnR5KHN0YXRlKSB8fCByZWFkQW5jaG9yUHJvcGVydHkoc3RhdGUpKSB7XG4gICAgICBpZiAoc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgLTEpKSB7XG4gICAgICAgIGF0TmV3TGluZSA9IHRydWU7XG4gICAgICAgIGFsbG93QmxvY2tDb2xsZWN0aW9ucyA9IGFsbG93QmxvY2tTdHlsZXM7XG5cbiAgICAgICAgaWYgKHN0YXRlLmxpbmVJbmRlbnQgPiBwYXJlbnRJbmRlbnQpIHtcbiAgICAgICAgICBpbmRlbnRTdGF0dXMgPSAxO1xuICAgICAgICB9IGVsc2UgaWYgKHN0YXRlLmxpbmVJbmRlbnQgPT09IHBhcmVudEluZGVudCkge1xuICAgICAgICAgIGluZGVudFN0YXR1cyA9IDA7XG4gICAgICAgIH0gZWxzZSBpZiAoc3RhdGUubGluZUluZGVudCA8IHBhcmVudEluZGVudCkge1xuICAgICAgICAgIGluZGVudFN0YXR1cyA9IC0xO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBhbGxvd0Jsb2NrQ29sbGVjdGlvbnMgPSBmYWxzZTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBpZiAoYWxsb3dCbG9ja0NvbGxlY3Rpb25zKSB7XG4gICAgYWxsb3dCbG9ja0NvbGxlY3Rpb25zID0gYXROZXdMaW5lIHx8IGFsbG93Q29tcGFjdDtcbiAgfVxuXG4gIGlmIChpbmRlbnRTdGF0dXMgPT09IDEgfHwgQ09OVEVYVF9CTE9DS19PVVQgPT09IG5vZGVDb250ZXh0KSB7XG4gICAgaWYgKENPTlRFWFRfRkxPV19JTiA9PT0gbm9kZUNvbnRleHQgfHwgQ09OVEVYVF9GTE9XX09VVCA9PT0gbm9kZUNvbnRleHQpIHtcbiAgICAgIGZsb3dJbmRlbnQgPSBwYXJlbnRJbmRlbnQ7XG4gICAgfSBlbHNlIHtcbiAgICAgIGZsb3dJbmRlbnQgPSBwYXJlbnRJbmRlbnQgKyAxO1xuICAgIH1cblxuICAgIGJsb2NrSW5kZW50ID0gc3RhdGUucG9zaXRpb24gLSBzdGF0ZS5saW5lU3RhcnQ7XG5cbiAgICBpZiAoaW5kZW50U3RhdHVzID09PSAxKSB7XG4gICAgICBpZiAoYWxsb3dCbG9ja0NvbGxlY3Rpb25zICYmXG4gICAgICAgICAgKHJlYWRCbG9ja1NlcXVlbmNlKHN0YXRlLCBibG9ja0luZGVudCkgfHxcbiAgICAgICAgICAgcmVhZEJsb2NrTWFwcGluZyhzdGF0ZSwgYmxvY2tJbmRlbnQsIGZsb3dJbmRlbnQpKSB8fFxuICAgICAgICAgIHJlYWRGbG93Q29sbGVjdGlvbihzdGF0ZSwgZmxvd0luZGVudCkpIHtcbiAgICAgICAgaGFzQ29udGVudCA9IHRydWU7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAoKGFsbG93QmxvY2tTY2FsYXJzICYmIHJlYWRCbG9ja1NjYWxhcihzdGF0ZSwgZmxvd0luZGVudCkpIHx8XG4gICAgICAgICAgICByZWFkU2luZ2xlUXVvdGVkU2NhbGFyKHN0YXRlLCBmbG93SW5kZW50KSB8fFxuICAgICAgICAgICAgcmVhZERvdWJsZVF1b3RlZFNjYWxhcihzdGF0ZSwgZmxvd0luZGVudCkpIHtcbiAgICAgICAgICBoYXNDb250ZW50ID0gdHJ1ZTtcblxuICAgICAgICB9IGVsc2UgaWYgKHJlYWRBbGlhcyhzdGF0ZSkpIHtcbiAgICAgICAgICBoYXNDb250ZW50ID0gdHJ1ZTtcblxuICAgICAgICAgIGlmIChzdGF0ZS50YWcgIT09IG51bGwgfHwgc3RhdGUuYW5jaG9yICE9PSBudWxsKSB7XG4gICAgICAgICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnYWxpYXMgbm9kZSBzaG91bGQgbm90IGhhdmUgYW55IHByb3BlcnRpZXMnKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgfSBlbHNlIGlmIChyZWFkUGxhaW5TY2FsYXIoc3RhdGUsIGZsb3dJbmRlbnQsIENPTlRFWFRfRkxPV19JTiA9PT0gbm9kZUNvbnRleHQpKSB7XG4gICAgICAgICAgaGFzQ29udGVudCA9IHRydWU7XG5cbiAgICAgICAgICBpZiAoc3RhdGUudGFnID09PSBudWxsKSB7XG4gICAgICAgICAgICBzdGF0ZS50YWcgPSAnPyc7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHN0YXRlLmFuY2hvciAhPT0gbnVsbCkge1xuICAgICAgICAgIHN0YXRlLmFuY2hvck1hcFtzdGF0ZS5hbmNob3JdID0gc3RhdGUucmVzdWx0O1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBlbHNlIGlmIChpbmRlbnRTdGF0dXMgPT09IDApIHtcbiAgICAgIC8vIFNwZWNpYWwgY2FzZTogYmxvY2sgc2VxdWVuY2VzIGFyZSBhbGxvd2VkIHRvIGhhdmUgc2FtZSBpbmRlbnRhdGlvbiBsZXZlbCBhcyB0aGUgcGFyZW50LlxuICAgICAgLy8gaHR0cDovL3d3dy55YW1sLm9yZy9zcGVjLzEuMi9zcGVjLmh0bWwjaWQyNzk5Nzg0XG4gICAgICBoYXNDb250ZW50ID0gYWxsb3dCbG9ja0NvbGxlY3Rpb25zICYmIHJlYWRCbG9ja1NlcXVlbmNlKHN0YXRlLCBibG9ja0luZGVudCk7XG4gICAgfVxuICB9XG5cbiAgaWYgKHN0YXRlLnRhZyA9PT0gbnVsbCkge1xuICAgIGlmIChzdGF0ZS5hbmNob3IgIT09IG51bGwpIHtcbiAgICAgIHN0YXRlLmFuY2hvck1hcFtzdGF0ZS5hbmNob3JdID0gc3RhdGUucmVzdWx0O1xuICAgIH1cblxuICB9IGVsc2UgaWYgKHN0YXRlLnRhZyA9PT0gJz8nKSB7XG4gICAgLy8gSW1wbGljaXQgcmVzb2x2aW5nIGlzIG5vdCBhbGxvd2VkIGZvciBub24tc2NhbGFyIHR5cGVzLCBhbmQgJz8nXG4gICAgLy8gbm9uLXNwZWNpZmljIHRhZyBpcyBvbmx5IGF1dG9tYXRpY2FsbHkgYXNzaWduZWQgdG8gcGxhaW4gc2NhbGFycy5cbiAgICAvL1xuICAgIC8vIFdlIG9ubHkgbmVlZCB0byBjaGVjayBraW5kIGNvbmZvcm1pdHkgaW4gY2FzZSB1c2VyIGV4cGxpY2l0bHkgYXNzaWducyAnPydcbiAgICAvLyB0YWcsIGZvciBleGFtcGxlIGxpa2UgdGhpczogXCIhPD8+IFswXVwiXG4gICAgLy9cbiAgICBpZiAoc3RhdGUucmVzdWx0ICE9PSBudWxsICYmIHN0YXRlLmtpbmQgIT09ICdzY2FsYXInKSB7XG4gICAgICB0aHJvd0Vycm9yKHN0YXRlLCAndW5hY2NlcHRhYmxlIG5vZGUga2luZCBmb3IgITw/PiB0YWc7IGl0IHNob3VsZCBiZSBcInNjYWxhclwiLCBub3QgXCInICsgc3RhdGUua2luZCArICdcIicpO1xuICAgIH1cblxuICAgIGZvciAodHlwZUluZGV4ID0gMCwgdHlwZVF1YW50aXR5ID0gc3RhdGUuaW1wbGljaXRUeXBlcy5sZW5ndGg7IHR5cGVJbmRleCA8IHR5cGVRdWFudGl0eTsgdHlwZUluZGV4ICs9IDEpIHtcbiAgICAgIHR5cGUgPSBzdGF0ZS5pbXBsaWNpdFR5cGVzW3R5cGVJbmRleF07XG5cbiAgICAgIGlmICh0eXBlLnJlc29sdmUoc3RhdGUucmVzdWx0KSkgeyAvLyBgc3RhdGUucmVzdWx0YCB1cGRhdGVkIGluIHJlc29sdmVyIGlmIG1hdGNoZWRcbiAgICAgICAgc3RhdGUucmVzdWx0ID0gdHlwZS5jb25zdHJ1Y3Qoc3RhdGUucmVzdWx0KTtcbiAgICAgICAgc3RhdGUudGFnID0gdHlwZS50YWc7XG4gICAgICAgIGlmIChzdGF0ZS5hbmNob3IgIT09IG51bGwpIHtcbiAgICAgICAgICBzdGF0ZS5hbmNob3JNYXBbc3RhdGUuYW5jaG9yXSA9IHN0YXRlLnJlc3VsdDtcbiAgICAgICAgfVxuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICB9XG4gIH0gZWxzZSBpZiAoc3RhdGUudGFnICE9PSAnIScpIHtcbiAgICBpZiAoX2hhc093blByb3BlcnR5JDEuY2FsbChzdGF0ZS50eXBlTWFwW3N0YXRlLmtpbmQgfHwgJ2ZhbGxiYWNrJ10sIHN0YXRlLnRhZykpIHtcbiAgICAgIHR5cGUgPSBzdGF0ZS50eXBlTWFwW3N0YXRlLmtpbmQgfHwgJ2ZhbGxiYWNrJ11bc3RhdGUudGFnXTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gbG9va2luZyBmb3IgbXVsdGkgdHlwZVxuICAgICAgdHlwZSA9IG51bGw7XG4gICAgICB0eXBlTGlzdCA9IHN0YXRlLnR5cGVNYXAubXVsdGlbc3RhdGUua2luZCB8fCAnZmFsbGJhY2snXTtcblxuICAgICAgZm9yICh0eXBlSW5kZXggPSAwLCB0eXBlUXVhbnRpdHkgPSB0eXBlTGlzdC5sZW5ndGg7IHR5cGVJbmRleCA8IHR5cGVRdWFudGl0eTsgdHlwZUluZGV4ICs9IDEpIHtcbiAgICAgICAgaWYgKHN0YXRlLnRhZy5zbGljZSgwLCB0eXBlTGlzdFt0eXBlSW5kZXhdLnRhZy5sZW5ndGgpID09PSB0eXBlTGlzdFt0eXBlSW5kZXhdLnRhZykge1xuICAgICAgICAgIHR5cGUgPSB0eXBlTGlzdFt0eXBlSW5kZXhdO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCF0eXBlKSB7XG4gICAgICB0aHJvd0Vycm9yKHN0YXRlLCAndW5rbm93biB0YWcgITwnICsgc3RhdGUudGFnICsgJz4nKTtcbiAgICB9XG5cbiAgICBpZiAoc3RhdGUucmVzdWx0ICE9PSBudWxsICYmIHR5cGUua2luZCAhPT0gc3RhdGUua2luZCkge1xuICAgICAgdGhyb3dFcnJvcihzdGF0ZSwgJ3VuYWNjZXB0YWJsZSBub2RlIGtpbmQgZm9yICE8JyArIHN0YXRlLnRhZyArICc+IHRhZzsgaXQgc2hvdWxkIGJlIFwiJyArIHR5cGUua2luZCArICdcIiwgbm90IFwiJyArIHN0YXRlLmtpbmQgKyAnXCInKTtcbiAgICB9XG5cbiAgICBpZiAoIXR5cGUucmVzb2x2ZShzdGF0ZS5yZXN1bHQsIHN0YXRlLnRhZykpIHsgLy8gYHN0YXRlLnJlc3VsdGAgdXBkYXRlZCBpbiByZXNvbHZlciBpZiBtYXRjaGVkXG4gICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnY2Fubm90IHJlc29sdmUgYSBub2RlIHdpdGggITwnICsgc3RhdGUudGFnICsgJz4gZXhwbGljaXQgdGFnJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0YXRlLnJlc3VsdCA9IHR5cGUuY29uc3RydWN0KHN0YXRlLnJlc3VsdCwgc3RhdGUudGFnKTtcbiAgICAgIGlmIChzdGF0ZS5hbmNob3IgIT09IG51bGwpIHtcbiAgICAgICAgc3RhdGUuYW5jaG9yTWFwW3N0YXRlLmFuY2hvcl0gPSBzdGF0ZS5yZXN1bHQ7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgaWYgKHN0YXRlLmxpc3RlbmVyICE9PSBudWxsKSB7XG4gICAgc3RhdGUubGlzdGVuZXIoJ2Nsb3NlJywgc3RhdGUpO1xuICB9XG4gIHJldHVybiBzdGF0ZS50YWcgIT09IG51bGwgfHwgIHN0YXRlLmFuY2hvciAhPT0gbnVsbCB8fCBoYXNDb250ZW50O1xufVxuXG5mdW5jdGlvbiByZWFkRG9jdW1lbnQoc3RhdGUpIHtcbiAgdmFyIGRvY3VtZW50U3RhcnQgPSBzdGF0ZS5wb3NpdGlvbixcbiAgICAgIF9wb3NpdGlvbixcbiAgICAgIGRpcmVjdGl2ZU5hbWUsXG4gICAgICBkaXJlY3RpdmVBcmdzLFxuICAgICAgaGFzRGlyZWN0aXZlcyA9IGZhbHNlLFxuICAgICAgY2g7XG5cbiAgc3RhdGUudmVyc2lvbiA9IG51bGw7XG4gIHN0YXRlLmNoZWNrTGluZUJyZWFrcyA9IHN0YXRlLmxlZ2FjeTtcbiAgc3RhdGUudGFnTWFwID0gT2JqZWN0LmNyZWF0ZShudWxsKTtcbiAgc3RhdGUuYW5jaG9yTWFwID0gT2JqZWN0LmNyZWF0ZShudWxsKTtcblxuICB3aGlsZSAoKGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdChzdGF0ZS5wb3NpdGlvbikpICE9PSAwKSB7XG4gICAgc2tpcFNlcGFyYXRpb25TcGFjZShzdGF0ZSwgdHJ1ZSwgLTEpO1xuXG4gICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKTtcblxuICAgIGlmIChzdGF0ZS5saW5lSW5kZW50ID4gMCB8fCBjaCAhPT0gMHgyNS8qICUgKi8pIHtcbiAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIGhhc0RpcmVjdGl2ZXMgPSB0cnVlO1xuICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgICBfcG9zaXRpb24gPSBzdGF0ZS5wb3NpdGlvbjtcblxuICAgIHdoaWxlIChjaCAhPT0gMCAmJiAhaXNfV1NfT1JfRU9MKGNoKSkge1xuICAgICAgY2ggPSBzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KCsrc3RhdGUucG9zaXRpb24pO1xuICAgIH1cblxuICAgIGRpcmVjdGl2ZU5hbWUgPSBzdGF0ZS5pbnB1dC5zbGljZShfcG9zaXRpb24sIHN0YXRlLnBvc2l0aW9uKTtcbiAgICBkaXJlY3RpdmVBcmdzID0gW107XG5cbiAgICBpZiAoZGlyZWN0aXZlTmFtZS5sZW5ndGggPCAxKSB7XG4gICAgICB0aHJvd0Vycm9yKHN0YXRlLCAnZGlyZWN0aXZlIG5hbWUgbXVzdCBub3QgYmUgbGVzcyB0aGFuIG9uZSBjaGFyYWN0ZXIgaW4gbGVuZ3RoJyk7XG4gICAgfVxuXG4gICAgd2hpbGUgKGNoICE9PSAwKSB7XG4gICAgICB3aGlsZSAoaXNfV0hJVEVfU1BBQ0UoY2gpKSB7XG4gICAgICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGNoID09PSAweDIzLyogIyAqLykge1xuICAgICAgICBkbyB7IGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTsgfVxuICAgICAgICB3aGlsZSAoY2ggIT09IDAgJiYgIWlzX0VPTChjaCkpO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cblxuICAgICAgaWYgKGlzX0VPTChjaCkpIGJyZWFrO1xuXG4gICAgICBfcG9zaXRpb24gPSBzdGF0ZS5wb3NpdGlvbjtcblxuICAgICAgd2hpbGUgKGNoICE9PSAwICYmICFpc19XU19PUl9FT0woY2gpKSB7XG4gICAgICAgIGNoID0gc3RhdGUuaW5wdXQuY2hhckNvZGVBdCgrK3N0YXRlLnBvc2l0aW9uKTtcbiAgICAgIH1cblxuICAgICAgZGlyZWN0aXZlQXJncy5wdXNoKHN0YXRlLmlucHV0LnNsaWNlKF9wb3NpdGlvbiwgc3RhdGUucG9zaXRpb24pKTtcbiAgICB9XG5cbiAgICBpZiAoY2ggIT09IDApIHJlYWRMaW5lQnJlYWsoc3RhdGUpO1xuXG4gICAgaWYgKF9oYXNPd25Qcm9wZXJ0eSQxLmNhbGwoZGlyZWN0aXZlSGFuZGxlcnMsIGRpcmVjdGl2ZU5hbWUpKSB7XG4gICAgICBkaXJlY3RpdmVIYW5kbGVyc1tkaXJlY3RpdmVOYW1lXShzdGF0ZSwgZGlyZWN0aXZlTmFtZSwgZGlyZWN0aXZlQXJncyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRocm93V2FybmluZyhzdGF0ZSwgJ3Vua25vd24gZG9jdW1lbnQgZGlyZWN0aXZlIFwiJyArIGRpcmVjdGl2ZU5hbWUgKyAnXCInKTtcbiAgICB9XG4gIH1cblxuICBza2lwU2VwYXJhdGlvblNwYWNlKHN0YXRlLCB0cnVlLCAtMSk7XG5cbiAgaWYgKHN0YXRlLmxpbmVJbmRlbnQgPT09IDAgJiZcbiAgICAgIHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24pICAgICA9PT0gMHgyRC8qIC0gKi8gJiZcbiAgICAgIHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24gKyAxKSA9PT0gMHgyRC8qIC0gKi8gJiZcbiAgICAgIHN0YXRlLmlucHV0LmNoYXJDb2RlQXQoc3RhdGUucG9zaXRpb24gKyAyKSA9PT0gMHgyRC8qIC0gKi8pIHtcbiAgICBzdGF0ZS5wb3NpdGlvbiArPSAzO1xuICAgIHNraXBTZXBhcmF0aW9uU3BhY2Uoc3RhdGUsIHRydWUsIC0xKTtcblxuICB9IGVsc2UgaWYgKGhhc0RpcmVjdGl2ZXMpIHtcbiAgICB0aHJvd0Vycm9yKHN0YXRlLCAnZGlyZWN0aXZlcyBlbmQgbWFyayBpcyBleHBlY3RlZCcpO1xuICB9XG5cbiAgY29tcG9zZU5vZGUoc3RhdGUsIHN0YXRlLmxpbmVJbmRlbnQgLSAxLCBDT05URVhUX0JMT0NLX09VVCwgZmFsc2UsIHRydWUpO1xuICBza2lwU2VwYXJhdGlvblNwYWNlKHN0YXRlLCB0cnVlLCAtMSk7XG5cbiAgaWYgKHN0YXRlLmNoZWNrTGluZUJyZWFrcyAmJlxuICAgICAgUEFUVEVSTl9OT05fQVNDSUlfTElORV9CUkVBS1MudGVzdChzdGF0ZS5pbnB1dC5zbGljZShkb2N1bWVudFN0YXJ0LCBzdGF0ZS5wb3NpdGlvbikpKSB7XG4gICAgdGhyb3dXYXJuaW5nKHN0YXRlLCAnbm9uLUFTQ0lJIGxpbmUgYnJlYWtzIGFyZSBpbnRlcnByZXRlZCBhcyBjb250ZW50Jyk7XG4gIH1cblxuICBzdGF0ZS5kb2N1bWVudHMucHVzaChzdGF0ZS5yZXN1bHQpO1xuXG4gIGlmIChzdGF0ZS5wb3NpdGlvbiA9PT0gc3RhdGUubGluZVN0YXJ0ICYmIHRlc3REb2N1bWVudFNlcGFyYXRvcihzdGF0ZSkpIHtcblxuICAgIGlmIChzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKSA9PT0gMHgyRS8qIC4gKi8pIHtcbiAgICAgIHN0YXRlLnBvc2l0aW9uICs9IDM7XG4gICAgICBza2lwU2VwYXJhdGlvblNwYWNlKHN0YXRlLCB0cnVlLCAtMSk7XG4gICAgfVxuICAgIHJldHVybjtcbiAgfVxuXG4gIGlmIChzdGF0ZS5wb3NpdGlvbiA8IChzdGF0ZS5sZW5ndGggLSAxKSkge1xuICAgIHRocm93RXJyb3Ioc3RhdGUsICdlbmQgb2YgdGhlIHN0cmVhbSBvciBhIGRvY3VtZW50IHNlcGFyYXRvciBpcyBleHBlY3RlZCcpO1xuICB9IGVsc2Uge1xuICAgIHJldHVybjtcbiAgfVxufVxuXG5cbmZ1bmN0aW9uIGxvYWREb2N1bWVudHMoaW5wdXQsIG9wdGlvbnMpIHtcbiAgaW5wdXQgPSBTdHJpbmcoaW5wdXQpO1xuICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcblxuICBpZiAoaW5wdXQubGVuZ3RoICE9PSAwKSB7XG5cbiAgICAvLyBBZGQgdGFpbGluZyBgXFxuYCBpZiBub3QgZXhpc3RzXG4gICAgaWYgKGlucHV0LmNoYXJDb2RlQXQoaW5wdXQubGVuZ3RoIC0gMSkgIT09IDB4MEEvKiBMRiAqLyAmJlxuICAgICAgICBpbnB1dC5jaGFyQ29kZUF0KGlucHV0Lmxlbmd0aCAtIDEpICE9PSAweDBELyogQ1IgKi8pIHtcbiAgICAgIGlucHV0ICs9ICdcXG4nO1xuICAgIH1cblxuICAgIC8vIFN0cmlwIEJPTVxuICAgIGlmIChpbnB1dC5jaGFyQ29kZUF0KDApID09PSAweEZFRkYpIHtcbiAgICAgIGlucHV0ID0gaW5wdXQuc2xpY2UoMSk7XG4gICAgfVxuICB9XG5cbiAgdmFyIHN0YXRlID0gbmV3IFN0YXRlJDEoaW5wdXQsIG9wdGlvbnMpO1xuXG4gIHZhciBudWxscG9zID0gaW5wdXQuaW5kZXhPZignXFwwJyk7XG5cbiAgaWYgKG51bGxwb3MgIT09IC0xKSB7XG4gICAgc3RhdGUucG9zaXRpb24gPSBudWxscG9zO1xuICAgIHRocm93RXJyb3Ioc3RhdGUsICdudWxsIGJ5dGUgaXMgbm90IGFsbG93ZWQgaW4gaW5wdXQnKTtcbiAgfVxuXG4gIC8vIFVzZSAwIGFzIHN0cmluZyB0ZXJtaW5hdG9yLiBUaGF0IHNpZ25pZmljYW50bHkgc2ltcGxpZmllcyBib3VuZHMgY2hlY2suXG4gIHN0YXRlLmlucHV0ICs9ICdcXDAnO1xuXG4gIHdoaWxlIChzdGF0ZS5pbnB1dC5jaGFyQ29kZUF0KHN0YXRlLnBvc2l0aW9uKSA9PT0gMHgyMC8qIFNwYWNlICovKSB7XG4gICAgc3RhdGUubGluZUluZGVudCArPSAxO1xuICAgIHN0YXRlLnBvc2l0aW9uICs9IDE7XG4gIH1cblxuICB3aGlsZSAoc3RhdGUucG9zaXRpb24gPCAoc3RhdGUubGVuZ3RoIC0gMSkpIHtcbiAgICByZWFkRG9jdW1lbnQoc3RhdGUpO1xuICB9XG5cbiAgcmV0dXJuIHN0YXRlLmRvY3VtZW50cztcbn1cblxuXG5mdW5jdGlvbiBsb2FkQWxsJDEoaW5wdXQsIGl0ZXJhdG9yLCBvcHRpb25zKSB7XG4gIGlmIChpdGVyYXRvciAhPT0gbnVsbCAmJiB0eXBlb2YgaXRlcmF0b3IgPT09ICdvYmplY3QnICYmIHR5cGVvZiBvcHRpb25zID09PSAndW5kZWZpbmVkJykge1xuICAgIG9wdGlvbnMgPSBpdGVyYXRvcjtcbiAgICBpdGVyYXRvciA9IG51bGw7XG4gIH1cblxuICB2YXIgZG9jdW1lbnRzID0gbG9hZERvY3VtZW50cyhpbnB1dCwgb3B0aW9ucyk7XG5cbiAgaWYgKHR5cGVvZiBpdGVyYXRvciAhPT0gJ2Z1bmN0aW9uJykge1xuICAgIHJldHVybiBkb2N1bWVudHM7XG4gIH1cblxuICBmb3IgKHZhciBpbmRleCA9IDAsIGxlbmd0aCA9IGRvY3VtZW50cy5sZW5ndGg7IGluZGV4IDwgbGVuZ3RoOyBpbmRleCArPSAxKSB7XG4gICAgaXRlcmF0b3IoZG9jdW1lbnRzW2luZGV4XSk7XG4gIH1cbn1cblxuXG5mdW5jdGlvbiBsb2FkJDEoaW5wdXQsIG9wdGlvbnMpIHtcbiAgdmFyIGRvY3VtZW50cyA9IGxvYWREb2N1bWVudHMoaW5wdXQsIG9wdGlvbnMpO1xuXG4gIGlmIChkb2N1bWVudHMubGVuZ3RoID09PSAwKSB7XG4gICAgLyplc2xpbnQtZGlzYWJsZSBuby11bmRlZmluZWQqL1xuICAgIHJldHVybiB1bmRlZmluZWQ7XG4gIH0gZWxzZSBpZiAoZG9jdW1lbnRzLmxlbmd0aCA9PT0gMSkge1xuICAgIHJldHVybiBkb2N1bWVudHNbMF07XG4gIH1cbiAgdGhyb3cgbmV3IGV4Y2VwdGlvbignZXhwZWN0ZWQgYSBzaW5nbGUgZG9jdW1lbnQgaW4gdGhlIHN0cmVhbSwgYnV0IGZvdW5kIG1vcmUnKTtcbn1cblxuXG52YXIgbG9hZEFsbF8xID0gbG9hZEFsbCQxO1xudmFyIGxvYWRfMSAgICA9IGxvYWQkMTtcblxudmFyIGxvYWRlciA9IHtcblx0bG9hZEFsbDogbG9hZEFsbF8xLFxuXHRsb2FkOiBsb2FkXzFcbn07XG5cbi8qZXNsaW50LWRpc2FibGUgbm8tdXNlLWJlZm9yZS1kZWZpbmUqL1xuXG5cblxuXG5cbnZhciBfdG9TdHJpbmcgICAgICAgPSBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nO1xudmFyIF9oYXNPd25Qcm9wZXJ0eSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XG5cbnZhciBDSEFSX0JPTSAgICAgICAgICAgICAgICAgID0gMHhGRUZGO1xudmFyIENIQVJfVEFCICAgICAgICAgICAgICAgICAgPSAweDA5OyAvKiBUYWIgKi9cbnZhciBDSEFSX0xJTkVfRkVFRCAgICAgICAgICAgID0gMHgwQTsgLyogTEYgKi9cbnZhciBDSEFSX0NBUlJJQUdFX1JFVFVSTiAgICAgID0gMHgwRDsgLyogQ1IgKi9cbnZhciBDSEFSX1NQQUNFICAgICAgICAgICAgICAgID0gMHgyMDsgLyogU3BhY2UgKi9cbnZhciBDSEFSX0VYQ0xBTUFUSU9OICAgICAgICAgID0gMHgyMTsgLyogISAqL1xudmFyIENIQVJfRE9VQkxFX1FVT1RFICAgICAgICAgPSAweDIyOyAvKiBcIiAqL1xudmFyIENIQVJfU0hBUlAgICAgICAgICAgICAgICAgPSAweDIzOyAvKiAjICovXG52YXIgQ0hBUl9QRVJDRU5UICAgICAgICAgICAgICA9IDB4MjU7IC8qICUgKi9cbnZhciBDSEFSX0FNUEVSU0FORCAgICAgICAgICAgID0gMHgyNjsgLyogJiAqL1xudmFyIENIQVJfU0lOR0xFX1FVT1RFICAgICAgICAgPSAweDI3OyAvKiAnICovXG52YXIgQ0hBUl9BU1RFUklTSyAgICAgICAgICAgICA9IDB4MkE7IC8qICogKi9cbnZhciBDSEFSX0NPTU1BICAgICAgICAgICAgICAgID0gMHgyQzsgLyogLCAqL1xudmFyIENIQVJfTUlOVVMgICAgICAgICAgICAgICAgPSAweDJEOyAvKiAtICovXG52YXIgQ0hBUl9DT0xPTiAgICAgICAgICAgICAgICA9IDB4M0E7IC8qIDogKi9cbnZhciBDSEFSX0VRVUFMUyAgICAgICAgICAgICAgID0gMHgzRDsgLyogPSAqL1xudmFyIENIQVJfR1JFQVRFUl9USEFOICAgICAgICAgPSAweDNFOyAvKiA+ICovXG52YXIgQ0hBUl9RVUVTVElPTiAgICAgICAgICAgICA9IDB4M0Y7IC8qID8gKi9cbnZhciBDSEFSX0NPTU1FUkNJQUxfQVQgICAgICAgID0gMHg0MDsgLyogQCAqL1xudmFyIENIQVJfTEVGVF9TUVVBUkVfQlJBQ0tFVCAgPSAweDVCOyAvKiBbICovXG52YXIgQ0hBUl9SSUdIVF9TUVVBUkVfQlJBQ0tFVCA9IDB4NUQ7IC8qIF0gKi9cbnZhciBDSEFSX0dSQVZFX0FDQ0VOVCAgICAgICAgID0gMHg2MDsgLyogYCAqL1xudmFyIENIQVJfTEVGVF9DVVJMWV9CUkFDS0VUICAgPSAweDdCOyAvKiB7ICovXG52YXIgQ0hBUl9WRVJUSUNBTF9MSU5FICAgICAgICA9IDB4N0M7IC8qIHwgKi9cbnZhciBDSEFSX1JJR0hUX0NVUkxZX0JSQUNLRVQgID0gMHg3RDsgLyogfSAqL1xuXG52YXIgRVNDQVBFX1NFUVVFTkNFUyA9IHt9O1xuXG5FU0NBUEVfU0VRVUVOQ0VTWzB4MDBdICAgPSAnXFxcXDAnO1xuRVNDQVBFX1NFUVVFTkNFU1sweDA3XSAgID0gJ1xcXFxhJztcbkVTQ0FQRV9TRVFVRU5DRVNbMHgwOF0gICA9ICdcXFxcYic7XG5FU0NBUEVfU0VRVUVOQ0VTWzB4MDldICAgPSAnXFxcXHQnO1xuRVNDQVBFX1NFUVVFTkNFU1sweDBBXSAgID0gJ1xcXFxuJztcbkVTQ0FQRV9TRVFVRU5DRVNbMHgwQl0gICA9ICdcXFxcdic7XG5FU0NBUEVfU0VRVUVOQ0VTWzB4MENdICAgPSAnXFxcXGYnO1xuRVNDQVBFX1NFUVVFTkNFU1sweDBEXSAgID0gJ1xcXFxyJztcbkVTQ0FQRV9TRVFVRU5DRVNbMHgxQl0gICA9ICdcXFxcZSc7XG5FU0NBUEVfU0VRVUVOQ0VTWzB4MjJdICAgPSAnXFxcXFwiJztcbkVTQ0FQRV9TRVFVRU5DRVNbMHg1Q10gICA9ICdcXFxcXFxcXCc7XG5FU0NBUEVfU0VRVUVOQ0VTWzB4ODVdICAgPSAnXFxcXE4nO1xuRVNDQVBFX1NFUVVFTkNFU1sweEEwXSAgID0gJ1xcXFxfJztcbkVTQ0FQRV9TRVFVRU5DRVNbMHgyMDI4XSA9ICdcXFxcTCc7XG5FU0NBUEVfU0VRVUVOQ0VTWzB4MjAyOV0gPSAnXFxcXFAnO1xuXG52YXIgREVQUkVDQVRFRF9CT09MRUFOU19TWU5UQVggPSBbXG4gICd5JywgJ1knLCAneWVzJywgJ1llcycsICdZRVMnLCAnb24nLCAnT24nLCAnT04nLFxuICAnbicsICdOJywgJ25vJywgJ05vJywgJ05PJywgJ29mZicsICdPZmYnLCAnT0ZGJ1xuXTtcblxudmFyIERFUFJFQ0FURURfQkFTRTYwX1NZTlRBWCA9IC9eWy0rXT9bMC05X10rKD86OlswLTlfXSspKyg/OlxcLlswLTlfXSopPyQvO1xuXG5mdW5jdGlvbiBjb21waWxlU3R5bGVNYXAoc2NoZW1hLCBtYXApIHtcbiAgdmFyIHJlc3VsdCwga2V5cywgaW5kZXgsIGxlbmd0aCwgdGFnLCBzdHlsZSwgdHlwZTtcblxuICBpZiAobWFwID09PSBudWxsKSByZXR1cm4ge307XG5cbiAgcmVzdWx0ID0ge307XG4gIGtleXMgPSBPYmplY3Qua2V5cyhtYXApO1xuXG4gIGZvciAoaW5kZXggPSAwLCBsZW5ndGggPSBrZXlzLmxlbmd0aDsgaW5kZXggPCBsZW5ndGg7IGluZGV4ICs9IDEpIHtcbiAgICB0YWcgPSBrZXlzW2luZGV4XTtcbiAgICBzdHlsZSA9IFN0cmluZyhtYXBbdGFnXSk7XG5cbiAgICBpZiAodGFnLnNsaWNlKDAsIDIpID09PSAnISEnKSB7XG4gICAgICB0YWcgPSAndGFnOnlhbWwub3JnLDIwMDI6JyArIHRhZy5zbGljZSgyKTtcbiAgICB9XG4gICAgdHlwZSA9IHNjaGVtYS5jb21waWxlZFR5cGVNYXBbJ2ZhbGxiYWNrJ11bdGFnXTtcblxuICAgIGlmICh0eXBlICYmIF9oYXNPd25Qcm9wZXJ0eS5jYWxsKHR5cGUuc3R5bGVBbGlhc2VzLCBzdHlsZSkpIHtcbiAgICAgIHN0eWxlID0gdHlwZS5zdHlsZUFsaWFzZXNbc3R5bGVdO1xuICAgIH1cblxuICAgIHJlc3VsdFt0YWddID0gc3R5bGU7XG4gIH1cblxuICByZXR1cm4gcmVzdWx0O1xufVxuXG5mdW5jdGlvbiBlbmNvZGVIZXgoY2hhcmFjdGVyKSB7XG4gIHZhciBzdHJpbmcsIGhhbmRsZSwgbGVuZ3RoO1xuXG4gIHN0cmluZyA9IGNoYXJhY3Rlci50b1N0cmluZygxNikudG9VcHBlckNhc2UoKTtcblxuICBpZiAoY2hhcmFjdGVyIDw9IDB4RkYpIHtcbiAgICBoYW5kbGUgPSAneCc7XG4gICAgbGVuZ3RoID0gMjtcbiAgfSBlbHNlIGlmIChjaGFyYWN0ZXIgPD0gMHhGRkZGKSB7XG4gICAgaGFuZGxlID0gJ3UnO1xuICAgIGxlbmd0aCA9IDQ7XG4gIH0gZWxzZSBpZiAoY2hhcmFjdGVyIDw9IDB4RkZGRkZGRkYpIHtcbiAgICBoYW5kbGUgPSAnVSc7XG4gICAgbGVuZ3RoID0gODtcbiAgfSBlbHNlIHtcbiAgICB0aHJvdyBuZXcgZXhjZXB0aW9uKCdjb2RlIHBvaW50IHdpdGhpbiBhIHN0cmluZyBtYXkgbm90IGJlIGdyZWF0ZXIgdGhhbiAweEZGRkZGRkZGJyk7XG4gIH1cblxuICByZXR1cm4gJ1xcXFwnICsgaGFuZGxlICsgY29tbW9uLnJlcGVhdCgnMCcsIGxlbmd0aCAtIHN0cmluZy5sZW5ndGgpICsgc3RyaW5nO1xufVxuXG5cbnZhciBRVU9USU5HX1RZUEVfU0lOR0xFID0gMSxcbiAgICBRVU9USU5HX1RZUEVfRE9VQkxFID0gMjtcblxuZnVuY3Rpb24gU3RhdGUob3B0aW9ucykge1xuICB0aGlzLnNjaGVtYSAgICAgICAgPSBvcHRpb25zWydzY2hlbWEnXSB8fCBfZGVmYXVsdDtcbiAgdGhpcy5pbmRlbnQgICAgICAgID0gTWF0aC5tYXgoMSwgKG9wdGlvbnNbJ2luZGVudCddIHx8IDIpKTtcbiAgdGhpcy5ub0FycmF5SW5kZW50ID0gb3B0aW9uc1snbm9BcnJheUluZGVudCddIHx8IGZhbHNlO1xuICB0aGlzLnNraXBJbnZhbGlkICAgPSBvcHRpb25zWydza2lwSW52YWxpZCddIHx8IGZhbHNlO1xuICB0aGlzLmZsb3dMZXZlbCAgICAgPSAoY29tbW9uLmlzTm90aGluZyhvcHRpb25zWydmbG93TGV2ZWwnXSkgPyAtMSA6IG9wdGlvbnNbJ2Zsb3dMZXZlbCddKTtcbiAgdGhpcy5zdHlsZU1hcCAgICAgID0gY29tcGlsZVN0eWxlTWFwKHRoaXMuc2NoZW1hLCBvcHRpb25zWydzdHlsZXMnXSB8fCBudWxsKTtcbiAgdGhpcy5zb3J0S2V5cyAgICAgID0gb3B0aW9uc1snc29ydEtleXMnXSB8fCBmYWxzZTtcbiAgdGhpcy5saW5lV2lkdGggICAgID0gb3B0aW9uc1snbGluZVdpZHRoJ10gfHwgODA7XG4gIHRoaXMubm9SZWZzICAgICAgICA9IG9wdGlvbnNbJ25vUmVmcyddIHx8IGZhbHNlO1xuICB0aGlzLm5vQ29tcGF0TW9kZSAgPSBvcHRpb25zWydub0NvbXBhdE1vZGUnXSB8fCBmYWxzZTtcbiAgdGhpcy5jb25kZW5zZUZsb3cgID0gb3B0aW9uc1snY29uZGVuc2VGbG93J10gfHwgZmFsc2U7XG4gIHRoaXMucXVvdGluZ1R5cGUgICA9IG9wdGlvbnNbJ3F1b3RpbmdUeXBlJ10gPT09ICdcIicgPyBRVU9USU5HX1RZUEVfRE9VQkxFIDogUVVPVElOR19UWVBFX1NJTkdMRTtcbiAgdGhpcy5mb3JjZVF1b3RlcyAgID0gb3B0aW9uc1snZm9yY2VRdW90ZXMnXSB8fCBmYWxzZTtcbiAgdGhpcy5yZXBsYWNlciAgICAgID0gdHlwZW9mIG9wdGlvbnNbJ3JlcGxhY2VyJ10gPT09ICdmdW5jdGlvbicgPyBvcHRpb25zWydyZXBsYWNlciddIDogbnVsbDtcblxuICB0aGlzLmltcGxpY2l0VHlwZXMgPSB0aGlzLnNjaGVtYS5jb21waWxlZEltcGxpY2l0O1xuICB0aGlzLmV4cGxpY2l0VHlwZXMgPSB0aGlzLnNjaGVtYS5jb21waWxlZEV4cGxpY2l0O1xuXG4gIHRoaXMudGFnID0gbnVsbDtcbiAgdGhpcy5yZXN1bHQgPSAnJztcblxuICB0aGlzLmR1cGxpY2F0ZXMgPSBbXTtcbiAgdGhpcy51c2VkRHVwbGljYXRlcyA9IG51bGw7XG59XG5cbi8vIEluZGVudHMgZXZlcnkgbGluZSBpbiBhIHN0cmluZy4gRW1wdHkgbGluZXMgKFxcbiBvbmx5KSBhcmUgbm90IGluZGVudGVkLlxuZnVuY3Rpb24gaW5kZW50U3RyaW5nKHN0cmluZywgc3BhY2VzKSB7XG4gIHZhciBpbmQgPSBjb21tb24ucmVwZWF0KCcgJywgc3BhY2VzKSxcbiAgICAgIHBvc2l0aW9uID0gMCxcbiAgICAgIG5leHQgPSAtMSxcbiAgICAgIHJlc3VsdCA9ICcnLFxuICAgICAgbGluZSxcbiAgICAgIGxlbmd0aCA9IHN0cmluZy5sZW5ndGg7XG5cbiAgd2hpbGUgKHBvc2l0aW9uIDwgbGVuZ3RoKSB7XG4gICAgbmV4dCA9IHN0cmluZy5pbmRleE9mKCdcXG4nLCBwb3NpdGlvbik7XG4gICAgaWYgKG5leHQgPT09IC0xKSB7XG4gICAgICBsaW5lID0gc3RyaW5nLnNsaWNlKHBvc2l0aW9uKTtcbiAgICAgIHBvc2l0aW9uID0gbGVuZ3RoO1xuICAgIH0gZWxzZSB7XG4gICAgICBsaW5lID0gc3RyaW5nLnNsaWNlKHBvc2l0aW9uLCBuZXh0ICsgMSk7XG4gICAgICBwb3NpdGlvbiA9IG5leHQgKyAxO1xuICAgIH1cblxuICAgIGlmIChsaW5lLmxlbmd0aCAmJiBsaW5lICE9PSAnXFxuJykgcmVzdWx0ICs9IGluZDtcblxuICAgIHJlc3VsdCArPSBsaW5lO1xuICB9XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn1cblxuZnVuY3Rpb24gZ2VuZXJhdGVOZXh0TGluZShzdGF0ZSwgbGV2ZWwpIHtcbiAgcmV0dXJuICdcXG4nICsgY29tbW9uLnJlcGVhdCgnICcsIHN0YXRlLmluZGVudCAqIGxldmVsKTtcbn1cblxuZnVuY3Rpb24gdGVzdEltcGxpY2l0UmVzb2x2aW5nKHN0YXRlLCBzdHIpIHtcbiAgdmFyIGluZGV4LCBsZW5ndGgsIHR5cGU7XG5cbiAgZm9yIChpbmRleCA9IDAsIGxlbmd0aCA9IHN0YXRlLmltcGxpY2l0VHlwZXMubGVuZ3RoOyBpbmRleCA8IGxlbmd0aDsgaW5kZXggKz0gMSkge1xuICAgIHR5cGUgPSBzdGF0ZS5pbXBsaWNpdFR5cGVzW2luZGV4XTtcblxuICAgIGlmICh0eXBlLnJlc29sdmUoc3RyKSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGZhbHNlO1xufVxuXG4vLyBbMzNdIHMtd2hpdGUgOjo9IHMtc3BhY2UgfCBzLXRhYlxuZnVuY3Rpb24gaXNXaGl0ZXNwYWNlKGMpIHtcbiAgcmV0dXJuIGMgPT09IENIQVJfU1BBQ0UgfHwgYyA9PT0gQ0hBUl9UQUI7XG59XG5cbi8vIFJldHVybnMgdHJ1ZSBpZiB0aGUgY2hhcmFjdGVyIGNhbiBiZSBwcmludGVkIHdpdGhvdXQgZXNjYXBpbmcuXG4vLyBGcm9tIFlBTUwgMS4yOiBcImFueSBhbGxvd2VkIGNoYXJhY3RlcnMga25vd24gdG8gYmUgbm9uLXByaW50YWJsZVxuLy8gc2hvdWxkIGFsc28gYmUgZXNjYXBlZC4gW0hvd2V2ZXIsXSBUaGlzIGlzblx1MjAxOXQgbWFuZGF0b3J5XCJcbi8vIERlcml2ZWQgZnJvbSBuYi1jaGFyIC0gXFx0IC0gI3g4NSAtICN4QTAgLSAjeDIwMjggLSAjeDIwMjkuXG5mdW5jdGlvbiBpc1ByaW50YWJsZShjKSB7XG4gIHJldHVybiAgKDB4MDAwMjAgPD0gYyAmJiBjIDw9IDB4MDAwMDdFKVxuICAgICAgfHwgKCgweDAwMEExIDw9IGMgJiYgYyA8PSAweDAwRDdGRikgJiYgYyAhPT0gMHgyMDI4ICYmIGMgIT09IDB4MjAyOSlcbiAgICAgIHx8ICgoMHgwRTAwMCA8PSBjICYmIGMgPD0gMHgwMEZGRkQpICYmIGMgIT09IENIQVJfQk9NKVxuICAgICAgfHwgICgweDEwMDAwIDw9IGMgJiYgYyA8PSAweDEwRkZGRik7XG59XG5cbi8vIFszNF0gbnMtY2hhciA6Oj0gbmItY2hhciAtIHMtd2hpdGVcbi8vIFsyN10gbmItY2hhciA6Oj0gYy1wcmludGFibGUgLSBiLWNoYXIgLSBjLWJ5dGUtb3JkZXItbWFya1xuLy8gWzI2XSBiLWNoYXIgIDo6PSBiLWxpbmUtZmVlZCB8IGItY2FycmlhZ2UtcmV0dXJuXG4vLyBJbmNsdWRpbmcgcy13aGl0ZSAoZm9yIHNvbWUgcmVhc29uLCBleGFtcGxlcyBkb2Vzbid0IG1hdGNoIHNwZWNzIGluIHRoaXMgYXNwZWN0KVxuLy8gbnMtY2hhciA6Oj0gYy1wcmludGFibGUgLSBiLWxpbmUtZmVlZCAtIGItY2FycmlhZ2UtcmV0dXJuIC0gYy1ieXRlLW9yZGVyLW1hcmtcbmZ1bmN0aW9uIGlzTnNDaGFyT3JXaGl0ZXNwYWNlKGMpIHtcbiAgcmV0dXJuIGlzUHJpbnRhYmxlKGMpXG4gICAgJiYgYyAhPT0gQ0hBUl9CT01cbiAgICAvLyAtIGItY2hhclxuICAgICYmIGMgIT09IENIQVJfQ0FSUklBR0VfUkVUVVJOXG4gICAgJiYgYyAhPT0gQ0hBUl9MSU5FX0ZFRUQ7XG59XG5cbi8vIFsxMjddICBucy1wbGFpbi1zYWZlKGMpIDo6PSBjID0gZmxvdy1vdXQgIFx1MjFEMiBucy1wbGFpbi1zYWZlLW91dFxuLy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgIGMgPSBmbG93LWluICAgXHUyMUQyIG5zLXBsYWluLXNhZmUtaW5cbi8vICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjID0gYmxvY2sta2V5IFx1MjFEMiBucy1wbGFpbi1zYWZlLW91dFxuLy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgIGMgPSBmbG93LWtleSAgXHUyMUQyIG5zLXBsYWluLXNhZmUtaW5cbi8vIFsxMjhdIG5zLXBsYWluLXNhZmUtb3V0IDo6PSBucy1jaGFyXG4vLyBbMTI5XSAgbnMtcGxhaW4tc2FmZS1pbiA6Oj0gbnMtY2hhciAtIGMtZmxvdy1pbmRpY2F0b3Jcbi8vIFsxMzBdICBucy1wbGFpbi1jaGFyKGMpIDo6PSAgKCBucy1wbGFpbi1zYWZlKGMpIC0gXHUyMDFDOlx1MjAxRCAtIFx1MjAxQyNcdTIwMUQgKVxuLy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgfCAoIC8qIEFuIG5zLWNoYXIgcHJlY2VkaW5nICovIFx1MjAxQyNcdTIwMUQgKVxuLy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgfCAoIFx1MjAxQzpcdTIwMUQgLyogRm9sbG93ZWQgYnkgYW4gbnMtcGxhaW4tc2FmZShjKSAqLyApXG5mdW5jdGlvbiBpc1BsYWluU2FmZShjLCBwcmV2LCBpbmJsb2NrKSB7XG4gIHZhciBjSXNOc0NoYXJPcldoaXRlc3BhY2UgPSBpc05zQ2hhck9yV2hpdGVzcGFjZShjKTtcbiAgdmFyIGNJc05zQ2hhciA9IGNJc05zQ2hhck9yV2hpdGVzcGFjZSAmJiAhaXNXaGl0ZXNwYWNlKGMpO1xuICByZXR1cm4gKFxuICAgIC8vIG5zLXBsYWluLXNhZmVcbiAgICBpbmJsb2NrID8gLy8gYyA9IGZsb3ctaW5cbiAgICAgIGNJc05zQ2hhck9yV2hpdGVzcGFjZVxuICAgICAgOiBjSXNOc0NoYXJPcldoaXRlc3BhY2VcbiAgICAgICAgLy8gLSBjLWZsb3ctaW5kaWNhdG9yXG4gICAgICAgICYmIGMgIT09IENIQVJfQ09NTUFcbiAgICAgICAgJiYgYyAhPT0gQ0hBUl9MRUZUX1NRVUFSRV9CUkFDS0VUXG4gICAgICAgICYmIGMgIT09IENIQVJfUklHSFRfU1FVQVJFX0JSQUNLRVRcbiAgICAgICAgJiYgYyAhPT0gQ0hBUl9MRUZUX0NVUkxZX0JSQUNLRVRcbiAgICAgICAgJiYgYyAhPT0gQ0hBUl9SSUdIVF9DVVJMWV9CUkFDS0VUXG4gIClcbiAgICAvLyBucy1wbGFpbi1jaGFyXG4gICAgJiYgYyAhPT0gQ0hBUl9TSEFSUCAvLyBmYWxzZSBvbiAnIydcbiAgICAmJiAhKHByZXYgPT09IENIQVJfQ09MT04gJiYgIWNJc05zQ2hhcikgLy8gZmFsc2Ugb24gJzogJ1xuICAgIHx8IChpc05zQ2hhck9yV2hpdGVzcGFjZShwcmV2KSAmJiAhaXNXaGl0ZXNwYWNlKHByZXYpICYmIGMgPT09IENIQVJfU0hBUlApIC8vIGNoYW5nZSB0byB0cnVlIG9uICdbXiBdIydcbiAgICB8fCAocHJldiA9PT0gQ0hBUl9DT0xPTiAmJiBjSXNOc0NoYXIpOyAvLyBjaGFuZ2UgdG8gdHJ1ZSBvbiAnOlteIF0nXG59XG5cbi8vIFNpbXBsaWZpZWQgdGVzdCBmb3IgdmFsdWVzIGFsbG93ZWQgYXMgdGhlIGZpcnN0IGNoYXJhY3RlciBpbiBwbGFpbiBzdHlsZS5cbmZ1bmN0aW9uIGlzUGxhaW5TYWZlRmlyc3QoYykge1xuICAvLyBVc2VzIGEgc3Vic2V0IG9mIG5zLWNoYXIgLSBjLWluZGljYXRvclxuICAvLyB3aGVyZSBucy1jaGFyID0gbmItY2hhciAtIHMtd2hpdGUuXG4gIC8vIE5vIHN1cHBvcnQgb2YgKCAoIFx1MjAxQz9cdTIwMUQgfCBcdTIwMUM6XHUyMDFEIHwgXHUyMDFDLVx1MjAxRCApIC8qIEZvbGxvd2VkIGJ5IGFuIG5zLXBsYWluLXNhZmUoYykpICovICkgcGFydFxuICByZXR1cm4gaXNQcmludGFibGUoYykgJiYgYyAhPT0gQ0hBUl9CT01cbiAgICAmJiAhaXNXaGl0ZXNwYWNlKGMpIC8vIC0gcy13aGl0ZVxuICAgIC8vIC0gKGMtaW5kaWNhdG9yIDo6PVxuICAgIC8vIFx1MjAxQy1cdTIwMUQgfCBcdTIwMUM/XHUyMDFEIHwgXHUyMDFDOlx1MjAxRCB8IFx1MjAxQyxcdTIwMUQgfCBcdTIwMUNbXHUyMDFEIHwgXHUyMDFDXVx1MjAxRCB8IFx1MjAxQ3tcdTIwMUQgfCBcdTIwMUN9XHUyMDFEXG4gICAgJiYgYyAhPT0gQ0hBUl9NSU5VU1xuICAgICYmIGMgIT09IENIQVJfUVVFU1RJT05cbiAgICAmJiBjICE9PSBDSEFSX0NPTE9OXG4gICAgJiYgYyAhPT0gQ0hBUl9DT01NQVxuICAgICYmIGMgIT09IENIQVJfTEVGVF9TUVVBUkVfQlJBQ0tFVFxuICAgICYmIGMgIT09IENIQVJfUklHSFRfU1FVQVJFX0JSQUNLRVRcbiAgICAmJiBjICE9PSBDSEFSX0xFRlRfQ1VSTFlfQlJBQ0tFVFxuICAgICYmIGMgIT09IENIQVJfUklHSFRfQ1VSTFlfQlJBQ0tFVFxuICAgIC8vIHwgXHUyMDFDI1x1MjAxRCB8IFx1MjAxQyZcdTIwMUQgfCBcdTIwMUMqXHUyMDFEIHwgXHUyMDFDIVx1MjAxRCB8IFx1MjAxQ3xcdTIwMUQgfCBcdTIwMUM9XHUyMDFEIHwgXHUyMDFDPlx1MjAxRCB8IFx1MjAxQydcdTIwMUQgfCBcdTIwMUNcIlx1MjAxRFxuICAgICYmIGMgIT09IENIQVJfU0hBUlBcbiAgICAmJiBjICE9PSBDSEFSX0FNUEVSU0FORFxuICAgICYmIGMgIT09IENIQVJfQVNURVJJU0tcbiAgICAmJiBjICE9PSBDSEFSX0VYQ0xBTUFUSU9OXG4gICAgJiYgYyAhPT0gQ0hBUl9WRVJUSUNBTF9MSU5FXG4gICAgJiYgYyAhPT0gQ0hBUl9FUVVBTFNcbiAgICAmJiBjICE9PSBDSEFSX0dSRUFURVJfVEhBTlxuICAgICYmIGMgIT09IENIQVJfU0lOR0xFX1FVT1RFXG4gICAgJiYgYyAhPT0gQ0hBUl9ET1VCTEVfUVVPVEVcbiAgICAvLyB8IFx1MjAxQyVcdTIwMUQgfCBcdTIwMUNAXHUyMDFEIHwgXHUyMDFDYFx1MjAxRClcbiAgICAmJiBjICE9PSBDSEFSX1BFUkNFTlRcbiAgICAmJiBjICE9PSBDSEFSX0NPTU1FUkNJQUxfQVRcbiAgICAmJiBjICE9PSBDSEFSX0dSQVZFX0FDQ0VOVDtcbn1cblxuLy8gU2ltcGxpZmllZCB0ZXN0IGZvciB2YWx1ZXMgYWxsb3dlZCBhcyB0aGUgbGFzdCBjaGFyYWN0ZXIgaW4gcGxhaW4gc3R5bGUuXG5mdW5jdGlvbiBpc1BsYWluU2FmZUxhc3QoYykge1xuICAvLyBqdXN0IG5vdCB3aGl0ZXNwYWNlIG9yIGNvbG9uLCBpdCB3aWxsIGJlIGNoZWNrZWQgdG8gYmUgcGxhaW4gY2hhcmFjdGVyIGxhdGVyXG4gIHJldHVybiAhaXNXaGl0ZXNwYWNlKGMpICYmIGMgIT09IENIQVJfQ09MT047XG59XG5cbi8vIFNhbWUgYXMgJ3N0cmluZycuY29kZVBvaW50QXQocG9zKSwgYnV0IHdvcmtzIGluIG9sZGVyIGJyb3dzZXJzLlxuZnVuY3Rpb24gY29kZVBvaW50QXQoc3RyaW5nLCBwb3MpIHtcbiAgdmFyIGZpcnN0ID0gc3RyaW5nLmNoYXJDb2RlQXQocG9zKSwgc2Vjb25kO1xuICBpZiAoZmlyc3QgPj0gMHhEODAwICYmIGZpcnN0IDw9IDB4REJGRiAmJiBwb3MgKyAxIDwgc3RyaW5nLmxlbmd0aCkge1xuICAgIHNlY29uZCA9IHN0cmluZy5jaGFyQ29kZUF0KHBvcyArIDEpO1xuICAgIGlmIChzZWNvbmQgPj0gMHhEQzAwICYmIHNlY29uZCA8PSAweERGRkYpIHtcbiAgICAgIC8vIGh0dHBzOi8vbWF0aGlhc2J5bmVucy5iZS9ub3Rlcy9qYXZhc2NyaXB0LWVuY29kaW5nI3N1cnJvZ2F0ZS1mb3JtdWxhZVxuICAgICAgcmV0dXJuIChmaXJzdCAtIDB4RDgwMCkgKiAweDQwMCArIHNlY29uZCAtIDB4REMwMCArIDB4MTAwMDA7XG4gICAgfVxuICB9XG4gIHJldHVybiBmaXJzdDtcbn1cblxuLy8gRGV0ZXJtaW5lcyB3aGV0aGVyIGJsb2NrIGluZGVudGF0aW9uIGluZGljYXRvciBpcyByZXF1aXJlZC5cbmZ1bmN0aW9uIG5lZWRJbmRlbnRJbmRpY2F0b3Ioc3RyaW5nKSB7XG4gIHZhciBsZWFkaW5nU3BhY2VSZSA9IC9eXFxuKiAvO1xuICByZXR1cm4gbGVhZGluZ1NwYWNlUmUudGVzdChzdHJpbmcpO1xufVxuXG52YXIgU1RZTEVfUExBSU4gICA9IDEsXG4gICAgU1RZTEVfU0lOR0xFICA9IDIsXG4gICAgU1RZTEVfTElURVJBTCA9IDMsXG4gICAgU1RZTEVfRk9MREVEICA9IDQsXG4gICAgU1RZTEVfRE9VQkxFICA9IDU7XG5cbi8vIERldGVybWluZXMgd2hpY2ggc2NhbGFyIHN0eWxlcyBhcmUgcG9zc2libGUgYW5kIHJldHVybnMgdGhlIHByZWZlcnJlZCBzdHlsZS5cbi8vIGxpbmVXaWR0aCA9IC0xID0+IG5vIGxpbWl0LlxuLy8gUHJlLWNvbmRpdGlvbnM6IHN0ci5sZW5ndGggPiAwLlxuLy8gUG9zdC1jb25kaXRpb25zOlxuLy8gICAgU1RZTEVfUExBSU4gb3IgU1RZTEVfU0lOR0xFID0+IG5vIFxcbiBhcmUgaW4gdGhlIHN0cmluZy5cbi8vICAgIFNUWUxFX0xJVEVSQUwgPT4gbm8gbGluZXMgYXJlIHN1aXRhYmxlIGZvciBmb2xkaW5nIChvciBsaW5lV2lkdGggaXMgLTEpLlxuLy8gICAgU1RZTEVfRk9MREVEID0+IGEgbGluZSA+IGxpbmVXaWR0aCBhbmQgY2FuIGJlIGZvbGRlZCAoYW5kIGxpbmVXaWR0aCAhPSAtMSkuXG5mdW5jdGlvbiBjaG9vc2VTY2FsYXJTdHlsZShzdHJpbmcsIHNpbmdsZUxpbmVPbmx5LCBpbmRlbnRQZXJMZXZlbCwgbGluZVdpZHRoLFxuICB0ZXN0QW1iaWd1b3VzVHlwZSwgcXVvdGluZ1R5cGUsIGZvcmNlUXVvdGVzLCBpbmJsb2NrKSB7XG5cbiAgdmFyIGk7XG4gIHZhciBjaGFyID0gMDtcbiAgdmFyIHByZXZDaGFyID0gbnVsbDtcbiAgdmFyIGhhc0xpbmVCcmVhayA9IGZhbHNlO1xuICB2YXIgaGFzRm9sZGFibGVMaW5lID0gZmFsc2U7IC8vIG9ubHkgY2hlY2tlZCBpZiBzaG91bGRUcmFja1dpZHRoXG4gIHZhciBzaG91bGRUcmFja1dpZHRoID0gbGluZVdpZHRoICE9PSAtMTtcbiAgdmFyIHByZXZpb3VzTGluZUJyZWFrID0gLTE7IC8vIGNvdW50IHRoZSBmaXJzdCBsaW5lIGNvcnJlY3RseVxuICB2YXIgcGxhaW4gPSBpc1BsYWluU2FmZUZpcnN0KGNvZGVQb2ludEF0KHN0cmluZywgMCkpXG4gICAgICAgICAgJiYgaXNQbGFpblNhZmVMYXN0KGNvZGVQb2ludEF0KHN0cmluZywgc3RyaW5nLmxlbmd0aCAtIDEpKTtcblxuICBpZiAoc2luZ2xlTGluZU9ubHkgfHwgZm9yY2VRdW90ZXMpIHtcbiAgICAvLyBDYXNlOiBubyBibG9jayBzdHlsZXMuXG4gICAgLy8gQ2hlY2sgZm9yIGRpc2FsbG93ZWQgY2hhcmFjdGVycyB0byBydWxlIG91dCBwbGFpbiBhbmQgc2luZ2xlLlxuICAgIGZvciAoaSA9IDA7IGkgPCBzdHJpbmcubGVuZ3RoOyBjaGFyID49IDB4MTAwMDAgPyBpICs9IDIgOiBpKyspIHtcbiAgICAgIGNoYXIgPSBjb2RlUG9pbnRBdChzdHJpbmcsIGkpO1xuICAgICAgaWYgKCFpc1ByaW50YWJsZShjaGFyKSkge1xuICAgICAgICByZXR1cm4gU1RZTEVfRE9VQkxFO1xuICAgICAgfVxuICAgICAgcGxhaW4gPSBwbGFpbiAmJiBpc1BsYWluU2FmZShjaGFyLCBwcmV2Q2hhciwgaW5ibG9jayk7XG4gICAgICBwcmV2Q2hhciA9IGNoYXI7XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIC8vIENhc2U6IGJsb2NrIHN0eWxlcyBwZXJtaXR0ZWQuXG4gICAgZm9yIChpID0gMDsgaSA8IHN0cmluZy5sZW5ndGg7IGNoYXIgPj0gMHgxMDAwMCA/IGkgKz0gMiA6IGkrKykge1xuICAgICAgY2hhciA9IGNvZGVQb2ludEF0KHN0cmluZywgaSk7XG4gICAgICBpZiAoY2hhciA9PT0gQ0hBUl9MSU5FX0ZFRUQpIHtcbiAgICAgICAgaGFzTGluZUJyZWFrID0gdHJ1ZTtcbiAgICAgICAgLy8gQ2hlY2sgaWYgYW55IGxpbmUgY2FuIGJlIGZvbGRlZC5cbiAgICAgICAgaWYgKHNob3VsZFRyYWNrV2lkdGgpIHtcbiAgICAgICAgICBoYXNGb2xkYWJsZUxpbmUgPSBoYXNGb2xkYWJsZUxpbmUgfHxcbiAgICAgICAgICAgIC8vIEZvbGRhYmxlIGxpbmUgPSB0b28gbG9uZywgYW5kIG5vdCBtb3JlLWluZGVudGVkLlxuICAgICAgICAgICAgKGkgLSBwcmV2aW91c0xpbmVCcmVhayAtIDEgPiBsaW5lV2lkdGggJiZcbiAgICAgICAgICAgICBzdHJpbmdbcHJldmlvdXNMaW5lQnJlYWsgKyAxXSAhPT0gJyAnKTtcbiAgICAgICAgICBwcmV2aW91c0xpbmVCcmVhayA9IGk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSBpZiAoIWlzUHJpbnRhYmxlKGNoYXIpKSB7XG4gICAgICAgIHJldHVybiBTVFlMRV9ET1VCTEU7XG4gICAgICB9XG4gICAgICBwbGFpbiA9IHBsYWluICYmIGlzUGxhaW5TYWZlKGNoYXIsIHByZXZDaGFyLCBpbmJsb2NrKTtcbiAgICAgIHByZXZDaGFyID0gY2hhcjtcbiAgICB9XG4gICAgLy8gaW4gY2FzZSB0aGUgZW5kIGlzIG1pc3NpbmcgYSBcXG5cbiAgICBoYXNGb2xkYWJsZUxpbmUgPSBoYXNGb2xkYWJsZUxpbmUgfHwgKHNob3VsZFRyYWNrV2lkdGggJiZcbiAgICAgIChpIC0gcHJldmlvdXNMaW5lQnJlYWsgLSAxID4gbGluZVdpZHRoICYmXG4gICAgICAgc3RyaW5nW3ByZXZpb3VzTGluZUJyZWFrICsgMV0gIT09ICcgJykpO1xuICB9XG4gIC8vIEFsdGhvdWdoIGV2ZXJ5IHN0eWxlIGNhbiByZXByZXNlbnQgXFxuIHdpdGhvdXQgZXNjYXBpbmcsIHByZWZlciBibG9jayBzdHlsZXNcbiAgLy8gZm9yIG11bHRpbGluZSwgc2luY2UgdGhleSdyZSBtb3JlIHJlYWRhYmxlIGFuZCB0aGV5IGRvbid0IGFkZCBlbXB0eSBsaW5lcy5cbiAgLy8gQWxzbyBwcmVmZXIgZm9sZGluZyBhIHN1cGVyLWxvbmcgbGluZS5cbiAgaWYgKCFoYXNMaW5lQnJlYWsgJiYgIWhhc0ZvbGRhYmxlTGluZSkge1xuICAgIC8vIFN0cmluZ3MgaW50ZXJwcmV0YWJsZSBhcyBhbm90aGVyIHR5cGUgaGF2ZSB0byBiZSBxdW90ZWQ7XG4gICAgLy8gZS5nLiB0aGUgc3RyaW5nICd0cnVlJyB2cy4gdGhlIGJvb2xlYW4gdHJ1ZS5cbiAgICBpZiAocGxhaW4gJiYgIWZvcmNlUXVvdGVzICYmICF0ZXN0QW1iaWd1b3VzVHlwZShzdHJpbmcpKSB7XG4gICAgICByZXR1cm4gU1RZTEVfUExBSU47XG4gICAgfVxuICAgIHJldHVybiBxdW90aW5nVHlwZSA9PT0gUVVPVElOR19UWVBFX0RPVUJMRSA/IFNUWUxFX0RPVUJMRSA6IFNUWUxFX1NJTkdMRTtcbiAgfVxuICAvLyBFZGdlIGNhc2U6IGJsb2NrIGluZGVudGF0aW9uIGluZGljYXRvciBjYW4gb25seSBoYXZlIG9uZSBkaWdpdC5cbiAgaWYgKGluZGVudFBlckxldmVsID4gOSAmJiBuZWVkSW5kZW50SW5kaWNhdG9yKHN0cmluZykpIHtcbiAgICByZXR1cm4gU1RZTEVfRE9VQkxFO1xuICB9XG4gIC8vIEF0IHRoaXMgcG9pbnQgd2Uga25vdyBibG9jayBzdHlsZXMgYXJlIHZhbGlkLlxuICAvLyBQcmVmZXIgbGl0ZXJhbCBzdHlsZSB1bmxlc3Mgd2Ugd2FudCB0byBmb2xkLlxuICBpZiAoIWZvcmNlUXVvdGVzKSB7XG4gICAgcmV0dXJuIGhhc0ZvbGRhYmxlTGluZSA/IFNUWUxFX0ZPTERFRCA6IFNUWUxFX0xJVEVSQUw7XG4gIH1cbiAgcmV0dXJuIHF1b3RpbmdUeXBlID09PSBRVU9USU5HX1RZUEVfRE9VQkxFID8gU1RZTEVfRE9VQkxFIDogU1RZTEVfU0lOR0xFO1xufVxuXG4vLyBOb3RlOiBsaW5lIGJyZWFraW5nL2ZvbGRpbmcgaXMgaW1wbGVtZW50ZWQgZm9yIG9ubHkgdGhlIGZvbGRlZCBzdHlsZS5cbi8vIE5CLiBXZSBkcm9wIHRoZSBsYXN0IHRyYWlsaW5nIG5ld2xpbmUgKGlmIGFueSkgb2YgYSByZXR1cm5lZCBibG9jayBzY2FsYXJcbi8vICBzaW5jZSB0aGUgZHVtcGVyIGFkZHMgaXRzIG93biBuZXdsaW5lLiBUaGlzIGFsd2F5cyB3b3Jrczpcbi8vICAgIFx1MjAyMiBObyBlbmRpbmcgbmV3bGluZSA9PiB1bmFmZmVjdGVkOyBhbHJlYWR5IHVzaW5nIHN0cmlwIFwiLVwiIGNob21waW5nLlxuLy8gICAgXHUyMDIyIEVuZGluZyBuZXdsaW5lICAgID0+IHJlbW92ZWQgdGhlbiByZXN0b3JlZC5cbi8vICBJbXBvcnRhbnRseSwgdGhpcyBrZWVwcyB0aGUgXCIrXCIgY2hvbXAgaW5kaWNhdG9yIGZyb20gZ2FpbmluZyBhbiBleHRyYSBsaW5lLlxuZnVuY3Rpb24gd3JpdGVTY2FsYXIoc3RhdGUsIHN0cmluZywgbGV2ZWwsIGlza2V5LCBpbmJsb2NrKSB7XG4gIHN0YXRlLmR1bXAgPSAoZnVuY3Rpb24gKCkge1xuICAgIGlmIChzdHJpbmcubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm4gc3RhdGUucXVvdGluZ1R5cGUgPT09IFFVT1RJTkdfVFlQRV9ET1VCTEUgPyAnXCJcIicgOiBcIicnXCI7XG4gICAgfVxuICAgIGlmICghc3RhdGUubm9Db21wYXRNb2RlKSB7XG4gICAgICBpZiAoREVQUkVDQVRFRF9CT09MRUFOU19TWU5UQVguaW5kZXhPZihzdHJpbmcpICE9PSAtMSB8fCBERVBSRUNBVEVEX0JBU0U2MF9TWU5UQVgudGVzdChzdHJpbmcpKSB7XG4gICAgICAgIHJldHVybiBzdGF0ZS5xdW90aW5nVHlwZSA9PT0gUVVPVElOR19UWVBFX0RPVUJMRSA/ICgnXCInICsgc3RyaW5nICsgJ1wiJykgOiAoXCInXCIgKyBzdHJpbmcgKyBcIidcIik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdmFyIGluZGVudCA9IHN0YXRlLmluZGVudCAqIE1hdGgubWF4KDEsIGxldmVsKTsgLy8gbm8gMC1pbmRlbnQgc2NhbGFyc1xuICAgIC8vIEFzIGluZGVudGF0aW9uIGdldHMgZGVlcGVyLCBsZXQgdGhlIHdpZHRoIGRlY3JlYXNlIG1vbm90b25pY2FsbHlcbiAgICAvLyB0byB0aGUgbG93ZXIgYm91bmQgbWluKHN0YXRlLmxpbmVXaWR0aCwgNDApLlxuICAgIC8vIE5vdGUgdGhhdCB0aGlzIGltcGxpZXNcbiAgICAvLyAgc3RhdGUubGluZVdpZHRoIFx1MjI2NCA0MCArIHN0YXRlLmluZGVudDogd2lkdGggaXMgZml4ZWQgYXQgdGhlIGxvd2VyIGJvdW5kLlxuICAgIC8vICBzdGF0ZS5saW5lV2lkdGggPiA0MCArIHN0YXRlLmluZGVudDogd2lkdGggZGVjcmVhc2VzIHVudGlsIHRoZSBsb3dlciBib3VuZC5cbiAgICAvLyBUaGlzIGJlaGF2ZXMgYmV0dGVyIHRoYW4gYSBjb25zdGFudCBtaW5pbXVtIHdpZHRoIHdoaWNoIGRpc2FsbG93cyBuYXJyb3dlciBvcHRpb25zLFxuICAgIC8vIG9yIGFuIGluZGVudCB0aHJlc2hvbGQgd2hpY2ggY2F1c2VzIHRoZSB3aWR0aCB0byBzdWRkZW5seSBpbmNyZWFzZS5cbiAgICB2YXIgbGluZVdpZHRoID0gc3RhdGUubGluZVdpZHRoID09PSAtMVxuICAgICAgPyAtMSA6IE1hdGgubWF4KE1hdGgubWluKHN0YXRlLmxpbmVXaWR0aCwgNDApLCBzdGF0ZS5saW5lV2lkdGggLSBpbmRlbnQpO1xuXG4gICAgLy8gV2l0aG91dCBrbm93aW5nIGlmIGtleXMgYXJlIGltcGxpY2l0L2V4cGxpY2l0LCBhc3N1bWUgaW1wbGljaXQgZm9yIHNhZmV0eS5cbiAgICB2YXIgc2luZ2xlTGluZU9ubHkgPSBpc2tleVxuICAgICAgLy8gTm8gYmxvY2sgc3R5bGVzIGluIGZsb3cgbW9kZS5cbiAgICAgIHx8IChzdGF0ZS5mbG93TGV2ZWwgPiAtMSAmJiBsZXZlbCA+PSBzdGF0ZS5mbG93TGV2ZWwpO1xuICAgIGZ1bmN0aW9uIHRlc3RBbWJpZ3VpdHkoc3RyaW5nKSB7XG4gICAgICByZXR1cm4gdGVzdEltcGxpY2l0UmVzb2x2aW5nKHN0YXRlLCBzdHJpbmcpO1xuICAgIH1cblxuICAgIHN3aXRjaCAoY2hvb3NlU2NhbGFyU3R5bGUoc3RyaW5nLCBzaW5nbGVMaW5lT25seSwgc3RhdGUuaW5kZW50LCBsaW5lV2lkdGgsXG4gICAgICB0ZXN0QW1iaWd1aXR5LCBzdGF0ZS5xdW90aW5nVHlwZSwgc3RhdGUuZm9yY2VRdW90ZXMgJiYgIWlza2V5LCBpbmJsb2NrKSkge1xuXG4gICAgICBjYXNlIFNUWUxFX1BMQUlOOlxuICAgICAgICByZXR1cm4gc3RyaW5nO1xuICAgICAgY2FzZSBTVFlMRV9TSU5HTEU6XG4gICAgICAgIHJldHVybiBcIidcIiArIHN0cmluZy5yZXBsYWNlKC8nL2csIFwiJydcIikgKyBcIidcIjtcbiAgICAgIGNhc2UgU1RZTEVfTElURVJBTDpcbiAgICAgICAgcmV0dXJuICd8JyArIGJsb2NrSGVhZGVyKHN0cmluZywgc3RhdGUuaW5kZW50KVxuICAgICAgICAgICsgZHJvcEVuZGluZ05ld2xpbmUoaW5kZW50U3RyaW5nKHN0cmluZywgaW5kZW50KSk7XG4gICAgICBjYXNlIFNUWUxFX0ZPTERFRDpcbiAgICAgICAgcmV0dXJuICc+JyArIGJsb2NrSGVhZGVyKHN0cmluZywgc3RhdGUuaW5kZW50KVxuICAgICAgICAgICsgZHJvcEVuZGluZ05ld2xpbmUoaW5kZW50U3RyaW5nKGZvbGRTdHJpbmcoc3RyaW5nLCBsaW5lV2lkdGgpLCBpbmRlbnQpKTtcbiAgICAgIGNhc2UgU1RZTEVfRE9VQkxFOlxuICAgICAgICByZXR1cm4gJ1wiJyArIGVzY2FwZVN0cmluZyhzdHJpbmcpICsgJ1wiJztcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHRocm93IG5ldyBleGNlcHRpb24oJ2ltcG9zc2libGUgZXJyb3I6IGludmFsaWQgc2NhbGFyIHN0eWxlJyk7XG4gICAgfVxuICB9KCkpO1xufVxuXG4vLyBQcmUtY29uZGl0aW9uczogc3RyaW5nIGlzIHZhbGlkIGZvciBhIGJsb2NrIHNjYWxhciwgMSA8PSBpbmRlbnRQZXJMZXZlbCA8PSA5LlxuZnVuY3Rpb24gYmxvY2tIZWFkZXIoc3RyaW5nLCBpbmRlbnRQZXJMZXZlbCkge1xuICB2YXIgaW5kZW50SW5kaWNhdG9yID0gbmVlZEluZGVudEluZGljYXRvcihzdHJpbmcpID8gU3RyaW5nKGluZGVudFBlckxldmVsKSA6ICcnO1xuXG4gIC8vIG5vdGUgdGhlIHNwZWNpYWwgY2FzZTogdGhlIHN0cmluZyAnXFxuJyBjb3VudHMgYXMgYSBcInRyYWlsaW5nXCIgZW1wdHkgbGluZS5cbiAgdmFyIGNsaXAgPSAgICAgICAgICBzdHJpbmdbc3RyaW5nLmxlbmd0aCAtIDFdID09PSAnXFxuJztcbiAgdmFyIGtlZXAgPSBjbGlwICYmIChzdHJpbmdbc3RyaW5nLmxlbmd0aCAtIDJdID09PSAnXFxuJyB8fCBzdHJpbmcgPT09ICdcXG4nKTtcbiAgdmFyIGNob21wID0ga2VlcCA/ICcrJyA6IChjbGlwID8gJycgOiAnLScpO1xuXG4gIHJldHVybiBpbmRlbnRJbmRpY2F0b3IgKyBjaG9tcCArICdcXG4nO1xufVxuXG4vLyAoU2VlIHRoZSBub3RlIGZvciB3cml0ZVNjYWxhci4pXG5mdW5jdGlvbiBkcm9wRW5kaW5nTmV3bGluZShzdHJpbmcpIHtcbiAgcmV0dXJuIHN0cmluZ1tzdHJpbmcubGVuZ3RoIC0gMV0gPT09ICdcXG4nID8gc3RyaW5nLnNsaWNlKDAsIC0xKSA6IHN0cmluZztcbn1cblxuLy8gTm90ZTogYSBsb25nIGxpbmUgd2l0aG91dCBhIHN1aXRhYmxlIGJyZWFrIHBvaW50IHdpbGwgZXhjZWVkIHRoZSB3aWR0aCBsaW1pdC5cbi8vIFByZS1jb25kaXRpb25zOiBldmVyeSBjaGFyIGluIHN0ciBpc1ByaW50YWJsZSwgc3RyLmxlbmd0aCA+IDAsIHdpZHRoID4gMC5cbmZ1bmN0aW9uIGZvbGRTdHJpbmcoc3RyaW5nLCB3aWR0aCkge1xuICAvLyBJbiBmb2xkZWQgc3R5bGUsICRrJCBjb25zZWN1dGl2ZSBuZXdsaW5lcyBvdXRwdXQgYXMgJGsrMSQgbmV3bGluZXNcdTIwMTRcbiAgLy8gdW5sZXNzIHRoZXkncmUgYmVmb3JlIG9yIGFmdGVyIGEgbW9yZS1pbmRlbnRlZCBsaW5lLCBvciBhdCB0aGUgdmVyeVxuICAvLyBiZWdpbm5pbmcgb3IgZW5kLCBpbiB3aGljaCBjYXNlICRrJCBtYXBzIHRvICRrJC5cbiAgLy8gVGhlcmVmb3JlLCBwYXJzZSBlYWNoIGNodW5rIGFzIG5ld2xpbmUocykgZm9sbG93ZWQgYnkgYSBjb250ZW50IGxpbmUuXG4gIHZhciBsaW5lUmUgPSAvKFxcbispKFteXFxuXSopL2c7XG5cbiAgLy8gZmlyc3QgbGluZSAocG9zc2libHkgYW4gZW1wdHkgbGluZSlcbiAgdmFyIHJlc3VsdCA9IChmdW5jdGlvbiAoKSB7XG4gICAgdmFyIG5leHRMRiA9IHN0cmluZy5pbmRleE9mKCdcXG4nKTtcbiAgICBuZXh0TEYgPSBuZXh0TEYgIT09IC0xID8gbmV4dExGIDogc3RyaW5nLmxlbmd0aDtcbiAgICBsaW5lUmUubGFzdEluZGV4ID0gbmV4dExGO1xuICAgIHJldHVybiBmb2xkTGluZShzdHJpbmcuc2xpY2UoMCwgbmV4dExGKSwgd2lkdGgpO1xuICB9KCkpO1xuICAvLyBJZiB3ZSBoYXZlbid0IHJlYWNoZWQgdGhlIGZpcnN0IGNvbnRlbnQgbGluZSB5ZXQsIGRvbid0IGFkZCBhbiBleHRyYSBcXG4uXG4gIHZhciBwcmV2TW9yZUluZGVudGVkID0gc3RyaW5nWzBdID09PSAnXFxuJyB8fCBzdHJpbmdbMF0gPT09ICcgJztcbiAgdmFyIG1vcmVJbmRlbnRlZDtcblxuICAvLyByZXN0IG9mIHRoZSBsaW5lc1xuICB2YXIgbWF0Y2g7XG4gIHdoaWxlICgobWF0Y2ggPSBsaW5lUmUuZXhlYyhzdHJpbmcpKSkge1xuICAgIHZhciBwcmVmaXggPSBtYXRjaFsxXSwgbGluZSA9IG1hdGNoWzJdO1xuICAgIG1vcmVJbmRlbnRlZCA9IChsaW5lWzBdID09PSAnICcpO1xuICAgIHJlc3VsdCArPSBwcmVmaXhcbiAgICAgICsgKCFwcmV2TW9yZUluZGVudGVkICYmICFtb3JlSW5kZW50ZWQgJiYgbGluZSAhPT0gJydcbiAgICAgICAgPyAnXFxuJyA6ICcnKVxuICAgICAgKyBmb2xkTGluZShsaW5lLCB3aWR0aCk7XG4gICAgcHJldk1vcmVJbmRlbnRlZCA9IG1vcmVJbmRlbnRlZDtcbiAgfVxuXG4gIHJldHVybiByZXN1bHQ7XG59XG5cbi8vIEdyZWVkeSBsaW5lIGJyZWFraW5nLlxuLy8gUGlja3MgdGhlIGxvbmdlc3QgbGluZSB1bmRlciB0aGUgbGltaXQgZWFjaCB0aW1lLFxuLy8gb3RoZXJ3aXNlIHNldHRsZXMgZm9yIHRoZSBzaG9ydGVzdCBsaW5lIG92ZXIgdGhlIGxpbWl0LlxuLy8gTkIuIE1vcmUtaW5kZW50ZWQgbGluZXMgKmNhbm5vdCogYmUgZm9sZGVkLCBhcyB0aGF0IHdvdWxkIGFkZCBhbiBleHRyYSBcXG4uXG5mdW5jdGlvbiBmb2xkTGluZShsaW5lLCB3aWR0aCkge1xuICBpZiAobGluZSA9PT0gJycgfHwgbGluZVswXSA9PT0gJyAnKSByZXR1cm4gbGluZTtcblxuICAvLyBTaW5jZSBhIG1vcmUtaW5kZW50ZWQgbGluZSBhZGRzIGEgXFxuLCBicmVha3MgY2FuJ3QgYmUgZm9sbG93ZWQgYnkgYSBzcGFjZS5cbiAgdmFyIGJyZWFrUmUgPSAvIFteIF0vZzsgLy8gbm90ZTogdGhlIG1hdGNoIGluZGV4IHdpbGwgYWx3YXlzIGJlIDw9IGxlbmd0aC0yLlxuICB2YXIgbWF0Y2g7XG4gIC8vIHN0YXJ0IGlzIGFuIGluY2x1c2l2ZSBpbmRleC4gZW5kLCBjdXJyLCBhbmQgbmV4dCBhcmUgZXhjbHVzaXZlLlxuICB2YXIgc3RhcnQgPSAwLCBlbmQsIGN1cnIgPSAwLCBuZXh0ID0gMDtcbiAgdmFyIHJlc3VsdCA9ICcnO1xuXG4gIC8vIEludmFyaWFudHM6IDAgPD0gc3RhcnQgPD0gbGVuZ3RoLTEuXG4gIC8vICAgMCA8PSBjdXJyIDw9IG5leHQgPD0gbWF4KDAsIGxlbmd0aC0yKS4gY3VyciAtIHN0YXJ0IDw9IHdpZHRoLlxuICAvLyBJbnNpZGUgdGhlIGxvb3A6XG4gIC8vICAgQSBtYXRjaCBpbXBsaWVzIGxlbmd0aCA+PSAyLCBzbyBjdXJyIGFuZCBuZXh0IGFyZSA8PSBsZW5ndGgtMi5cbiAgd2hpbGUgKChtYXRjaCA9IGJyZWFrUmUuZXhlYyhsaW5lKSkpIHtcbiAgICBuZXh0ID0gbWF0Y2guaW5kZXg7XG4gICAgLy8gbWFpbnRhaW4gaW52YXJpYW50OiBjdXJyIC0gc3RhcnQgPD0gd2lkdGhcbiAgICBpZiAobmV4dCAtIHN0YXJ0ID4gd2lkdGgpIHtcbiAgICAgIGVuZCA9IChjdXJyID4gc3RhcnQpID8gY3VyciA6IG5leHQ7IC8vIGRlcml2ZSBlbmQgPD0gbGVuZ3RoLTJcbiAgICAgIHJlc3VsdCArPSAnXFxuJyArIGxpbmUuc2xpY2Uoc3RhcnQsIGVuZCk7XG4gICAgICAvLyBza2lwIHRoZSBzcGFjZSB0aGF0IHdhcyBvdXRwdXQgYXMgXFxuXG4gICAgICBzdGFydCA9IGVuZCArIDE7ICAgICAgICAgICAgICAgICAgICAvLyBkZXJpdmUgc3RhcnQgPD0gbGVuZ3RoLTFcbiAgICB9XG4gICAgY3VyciA9IG5leHQ7XG4gIH1cblxuICAvLyBCeSB0aGUgaW52YXJpYW50cywgc3RhcnQgPD0gbGVuZ3RoLTEsIHNvIHRoZXJlIGlzIHNvbWV0aGluZyBsZWZ0IG92ZXIuXG4gIC8vIEl0IGlzIGVpdGhlciB0aGUgd2hvbGUgc3RyaW5nIG9yIGEgcGFydCBzdGFydGluZyBmcm9tIG5vbi13aGl0ZXNwYWNlLlxuICByZXN1bHQgKz0gJ1xcbic7XG4gIC8vIEluc2VydCBhIGJyZWFrIGlmIHRoZSByZW1haW5kZXIgaXMgdG9vIGxvbmcgYW5kIHRoZXJlIGlzIGEgYnJlYWsgYXZhaWxhYmxlLlxuICBpZiAobGluZS5sZW5ndGggLSBzdGFydCA+IHdpZHRoICYmIGN1cnIgPiBzdGFydCkge1xuICAgIHJlc3VsdCArPSBsaW5lLnNsaWNlKHN0YXJ0LCBjdXJyKSArICdcXG4nICsgbGluZS5zbGljZShjdXJyICsgMSk7XG4gIH0gZWxzZSB7XG4gICAgcmVzdWx0ICs9IGxpbmUuc2xpY2Uoc3RhcnQpO1xuICB9XG5cbiAgcmV0dXJuIHJlc3VsdC5zbGljZSgxKTsgLy8gZHJvcCBleHRyYSBcXG4gam9pbmVyXG59XG5cbi8vIEVzY2FwZXMgYSBkb3VibGUtcXVvdGVkIHN0cmluZy5cbmZ1bmN0aW9uIGVzY2FwZVN0cmluZyhzdHJpbmcpIHtcbiAgdmFyIHJlc3VsdCA9ICcnO1xuICB2YXIgY2hhciA9IDA7XG4gIHZhciBlc2NhcGVTZXE7XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBzdHJpbmcubGVuZ3RoOyBjaGFyID49IDB4MTAwMDAgPyBpICs9IDIgOiBpKyspIHtcbiAgICBjaGFyID0gY29kZVBvaW50QXQoc3RyaW5nLCBpKTtcbiAgICBlc2NhcGVTZXEgPSBFU0NBUEVfU0VRVUVOQ0VTW2NoYXJdO1xuXG4gICAgaWYgKCFlc2NhcGVTZXEgJiYgaXNQcmludGFibGUoY2hhcikpIHtcbiAgICAgIHJlc3VsdCArPSBzdHJpbmdbaV07XG4gICAgICBpZiAoY2hhciA+PSAweDEwMDAwKSByZXN1bHQgKz0gc3RyaW5nW2kgKyAxXTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzdWx0ICs9IGVzY2FwZVNlcSB8fCBlbmNvZGVIZXgoY2hhcik7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn1cblxuZnVuY3Rpb24gd3JpdGVGbG93U2VxdWVuY2Uoc3RhdGUsIGxldmVsLCBvYmplY3QpIHtcbiAgdmFyIF9yZXN1bHQgPSAnJyxcbiAgICAgIF90YWcgICAgPSBzdGF0ZS50YWcsXG4gICAgICBpbmRleCxcbiAgICAgIGxlbmd0aCxcbiAgICAgIHZhbHVlO1xuXG4gIGZvciAoaW5kZXggPSAwLCBsZW5ndGggPSBvYmplY3QubGVuZ3RoOyBpbmRleCA8IGxlbmd0aDsgaW5kZXggKz0gMSkge1xuICAgIHZhbHVlID0gb2JqZWN0W2luZGV4XTtcblxuICAgIGlmIChzdGF0ZS5yZXBsYWNlcikge1xuICAgICAgdmFsdWUgPSBzdGF0ZS5yZXBsYWNlci5jYWxsKG9iamVjdCwgU3RyaW5nKGluZGV4KSwgdmFsdWUpO1xuICAgIH1cblxuICAgIC8vIFdyaXRlIG9ubHkgdmFsaWQgZWxlbWVudHMsIHB1dCBudWxsIGluc3RlYWQgb2YgaW52YWxpZCBlbGVtZW50cy5cbiAgICBpZiAod3JpdGVOb2RlKHN0YXRlLCBsZXZlbCwgdmFsdWUsIGZhbHNlLCBmYWxzZSkgfHxcbiAgICAgICAgKHR5cGVvZiB2YWx1ZSA9PT0gJ3VuZGVmaW5lZCcgJiZcbiAgICAgICAgIHdyaXRlTm9kZShzdGF0ZSwgbGV2ZWwsIG51bGwsIGZhbHNlLCBmYWxzZSkpKSB7XG5cbiAgICAgIGlmIChfcmVzdWx0ICE9PSAnJykgX3Jlc3VsdCArPSAnLCcgKyAoIXN0YXRlLmNvbmRlbnNlRmxvdyA/ICcgJyA6ICcnKTtcbiAgICAgIF9yZXN1bHQgKz0gc3RhdGUuZHVtcDtcbiAgICB9XG4gIH1cblxuICBzdGF0ZS50YWcgPSBfdGFnO1xuICBzdGF0ZS5kdW1wID0gJ1snICsgX3Jlc3VsdCArICddJztcbn1cblxuZnVuY3Rpb24gd3JpdGVCbG9ja1NlcXVlbmNlKHN0YXRlLCBsZXZlbCwgb2JqZWN0LCBjb21wYWN0KSB7XG4gIHZhciBfcmVzdWx0ID0gJycsXG4gICAgICBfdGFnICAgID0gc3RhdGUudGFnLFxuICAgICAgaW5kZXgsXG4gICAgICBsZW5ndGgsXG4gICAgICB2YWx1ZTtcblxuICBmb3IgKGluZGV4ID0gMCwgbGVuZ3RoID0gb2JqZWN0Lmxlbmd0aDsgaW5kZXggPCBsZW5ndGg7IGluZGV4ICs9IDEpIHtcbiAgICB2YWx1ZSA9IG9iamVjdFtpbmRleF07XG5cbiAgICBpZiAoc3RhdGUucmVwbGFjZXIpIHtcbiAgICAgIHZhbHVlID0gc3RhdGUucmVwbGFjZXIuY2FsbChvYmplY3QsIFN0cmluZyhpbmRleCksIHZhbHVlKTtcbiAgICB9XG5cbiAgICAvLyBXcml0ZSBvbmx5IHZhbGlkIGVsZW1lbnRzLCBwdXQgbnVsbCBpbnN0ZWFkIG9mIGludmFsaWQgZWxlbWVudHMuXG4gICAgaWYgKHdyaXRlTm9kZShzdGF0ZSwgbGV2ZWwgKyAxLCB2YWx1ZSwgdHJ1ZSwgdHJ1ZSwgZmFsc2UsIHRydWUpIHx8XG4gICAgICAgICh0eXBlb2YgdmFsdWUgPT09ICd1bmRlZmluZWQnICYmXG4gICAgICAgICB3cml0ZU5vZGUoc3RhdGUsIGxldmVsICsgMSwgbnVsbCwgdHJ1ZSwgdHJ1ZSwgZmFsc2UsIHRydWUpKSkge1xuXG4gICAgICBpZiAoIWNvbXBhY3QgfHwgX3Jlc3VsdCAhPT0gJycpIHtcbiAgICAgICAgX3Jlc3VsdCArPSBnZW5lcmF0ZU5leHRMaW5lKHN0YXRlLCBsZXZlbCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChzdGF0ZS5kdW1wICYmIENIQVJfTElORV9GRUVEID09PSBzdGF0ZS5kdW1wLmNoYXJDb2RlQXQoMCkpIHtcbiAgICAgICAgX3Jlc3VsdCArPSAnLSc7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBfcmVzdWx0ICs9ICctICc7XG4gICAgICB9XG5cbiAgICAgIF9yZXN1bHQgKz0gc3RhdGUuZHVtcDtcbiAgICB9XG4gIH1cblxuICBzdGF0ZS50YWcgPSBfdGFnO1xuICBzdGF0ZS5kdW1wID0gX3Jlc3VsdCB8fCAnW10nOyAvLyBFbXB0eSBzZXF1ZW5jZSBpZiBubyB2YWxpZCB2YWx1ZXMuXG59XG5cbmZ1bmN0aW9uIHdyaXRlRmxvd01hcHBpbmcoc3RhdGUsIGxldmVsLCBvYmplY3QpIHtcbiAgdmFyIF9yZXN1bHQgICAgICAgPSAnJyxcbiAgICAgIF90YWcgICAgICAgICAgPSBzdGF0ZS50YWcsXG4gICAgICBvYmplY3RLZXlMaXN0ID0gT2JqZWN0LmtleXMob2JqZWN0KSxcbiAgICAgIGluZGV4LFxuICAgICAgbGVuZ3RoLFxuICAgICAgb2JqZWN0S2V5LFxuICAgICAgb2JqZWN0VmFsdWUsXG4gICAgICBwYWlyQnVmZmVyO1xuXG4gIGZvciAoaW5kZXggPSAwLCBsZW5ndGggPSBvYmplY3RLZXlMaXN0Lmxlbmd0aDsgaW5kZXggPCBsZW5ndGg7IGluZGV4ICs9IDEpIHtcblxuICAgIHBhaXJCdWZmZXIgPSAnJztcbiAgICBpZiAoX3Jlc3VsdCAhPT0gJycpIHBhaXJCdWZmZXIgKz0gJywgJztcblxuICAgIGlmIChzdGF0ZS5jb25kZW5zZUZsb3cpIHBhaXJCdWZmZXIgKz0gJ1wiJztcblxuICAgIG9iamVjdEtleSA9IG9iamVjdEtleUxpc3RbaW5kZXhdO1xuICAgIG9iamVjdFZhbHVlID0gb2JqZWN0W29iamVjdEtleV07XG5cbiAgICBpZiAoc3RhdGUucmVwbGFjZXIpIHtcbiAgICAgIG9iamVjdFZhbHVlID0gc3RhdGUucmVwbGFjZXIuY2FsbChvYmplY3QsIG9iamVjdEtleSwgb2JqZWN0VmFsdWUpO1xuICAgIH1cblxuICAgIGlmICghd3JpdGVOb2RlKHN0YXRlLCBsZXZlbCwgb2JqZWN0S2V5LCBmYWxzZSwgZmFsc2UpKSB7XG4gICAgICBjb250aW51ZTsgLy8gU2tpcCB0aGlzIHBhaXIgYmVjYXVzZSBvZiBpbnZhbGlkIGtleTtcbiAgICB9XG5cbiAgICBpZiAoc3RhdGUuZHVtcC5sZW5ndGggPiAxMDI0KSBwYWlyQnVmZmVyICs9ICc/ICc7XG5cbiAgICBwYWlyQnVmZmVyICs9IHN0YXRlLmR1bXAgKyAoc3RhdGUuY29uZGVuc2VGbG93ID8gJ1wiJyA6ICcnKSArICc6JyArIChzdGF0ZS5jb25kZW5zZUZsb3cgPyAnJyA6ICcgJyk7XG5cbiAgICBpZiAoIXdyaXRlTm9kZShzdGF0ZSwgbGV2ZWwsIG9iamVjdFZhbHVlLCBmYWxzZSwgZmFsc2UpKSB7XG4gICAgICBjb250aW51ZTsgLy8gU2tpcCB0aGlzIHBhaXIgYmVjYXVzZSBvZiBpbnZhbGlkIHZhbHVlLlxuICAgIH1cblxuICAgIHBhaXJCdWZmZXIgKz0gc3RhdGUuZHVtcDtcblxuICAgIC8vIEJvdGgga2V5IGFuZCB2YWx1ZSBhcmUgdmFsaWQuXG4gICAgX3Jlc3VsdCArPSBwYWlyQnVmZmVyO1xuICB9XG5cbiAgc3RhdGUudGFnID0gX3RhZztcbiAgc3RhdGUuZHVtcCA9ICd7JyArIF9yZXN1bHQgKyAnfSc7XG59XG5cbmZ1bmN0aW9uIHdyaXRlQmxvY2tNYXBwaW5nKHN0YXRlLCBsZXZlbCwgb2JqZWN0LCBjb21wYWN0KSB7XG4gIHZhciBfcmVzdWx0ICAgICAgID0gJycsXG4gICAgICBfdGFnICAgICAgICAgID0gc3RhdGUudGFnLFxuICAgICAgb2JqZWN0S2V5TGlzdCA9IE9iamVjdC5rZXlzKG9iamVjdCksXG4gICAgICBpbmRleCxcbiAgICAgIGxlbmd0aCxcbiAgICAgIG9iamVjdEtleSxcbiAgICAgIG9iamVjdFZhbHVlLFxuICAgICAgZXhwbGljaXRQYWlyLFxuICAgICAgcGFpckJ1ZmZlcjtcblxuICAvLyBBbGxvdyBzb3J0aW5nIGtleXMgc28gdGhhdCB0aGUgb3V0cHV0IGZpbGUgaXMgZGV0ZXJtaW5pc3RpY1xuICBpZiAoc3RhdGUuc29ydEtleXMgPT09IHRydWUpIHtcbiAgICAvLyBEZWZhdWx0IHNvcnRpbmdcbiAgICBvYmplY3RLZXlMaXN0LnNvcnQoKTtcbiAgfSBlbHNlIGlmICh0eXBlb2Ygc3RhdGUuc29ydEtleXMgPT09ICdmdW5jdGlvbicpIHtcbiAgICAvLyBDdXN0b20gc29ydCBmdW5jdGlvblxuICAgIG9iamVjdEtleUxpc3Quc29ydChzdGF0ZS5zb3J0S2V5cyk7XG4gIH0gZWxzZSBpZiAoc3RhdGUuc29ydEtleXMpIHtcbiAgICAvLyBTb21ldGhpbmcgaXMgd3JvbmdcbiAgICB0aHJvdyBuZXcgZXhjZXB0aW9uKCdzb3J0S2V5cyBtdXN0IGJlIGEgYm9vbGVhbiBvciBhIGZ1bmN0aW9uJyk7XG4gIH1cblxuICBmb3IgKGluZGV4ID0gMCwgbGVuZ3RoID0gb2JqZWN0S2V5TGlzdC5sZW5ndGg7IGluZGV4IDwgbGVuZ3RoOyBpbmRleCArPSAxKSB7XG4gICAgcGFpckJ1ZmZlciA9ICcnO1xuXG4gICAgaWYgKCFjb21wYWN0IHx8IF9yZXN1bHQgIT09ICcnKSB7XG4gICAgICBwYWlyQnVmZmVyICs9IGdlbmVyYXRlTmV4dExpbmUoc3RhdGUsIGxldmVsKTtcbiAgICB9XG5cbiAgICBvYmplY3RLZXkgPSBvYmplY3RLZXlMaXN0W2luZGV4XTtcbiAgICBvYmplY3RWYWx1ZSA9IG9iamVjdFtvYmplY3RLZXldO1xuXG4gICAgaWYgKHN0YXRlLnJlcGxhY2VyKSB7XG4gICAgICBvYmplY3RWYWx1ZSA9IHN0YXRlLnJlcGxhY2VyLmNhbGwob2JqZWN0LCBvYmplY3RLZXksIG9iamVjdFZhbHVlKTtcbiAgICB9XG5cbiAgICBpZiAoIXdyaXRlTm9kZShzdGF0ZSwgbGV2ZWwgKyAxLCBvYmplY3RLZXksIHRydWUsIHRydWUsIHRydWUpKSB7XG4gICAgICBjb250aW51ZTsgLy8gU2tpcCB0aGlzIHBhaXIgYmVjYXVzZSBvZiBpbnZhbGlkIGtleS5cbiAgICB9XG5cbiAgICBleHBsaWNpdFBhaXIgPSAoc3RhdGUudGFnICE9PSBudWxsICYmIHN0YXRlLnRhZyAhPT0gJz8nKSB8fFxuICAgICAgICAgICAgICAgICAgIChzdGF0ZS5kdW1wICYmIHN0YXRlLmR1bXAubGVuZ3RoID4gMTAyNCk7XG5cbiAgICBpZiAoZXhwbGljaXRQYWlyKSB7XG4gICAgICBpZiAoc3RhdGUuZHVtcCAmJiBDSEFSX0xJTkVfRkVFRCA9PT0gc3RhdGUuZHVtcC5jaGFyQ29kZUF0KDApKSB7XG4gICAgICAgIHBhaXJCdWZmZXIgKz0gJz8nO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcGFpckJ1ZmZlciArPSAnPyAnO1xuICAgICAgfVxuICAgIH1cblxuICAgIHBhaXJCdWZmZXIgKz0gc3RhdGUuZHVtcDtcblxuICAgIGlmIChleHBsaWNpdFBhaXIpIHtcbiAgICAgIHBhaXJCdWZmZXIgKz0gZ2VuZXJhdGVOZXh0TGluZShzdGF0ZSwgbGV2ZWwpO1xuICAgIH1cblxuICAgIGlmICghd3JpdGVOb2RlKHN0YXRlLCBsZXZlbCArIDEsIG9iamVjdFZhbHVlLCB0cnVlLCBleHBsaWNpdFBhaXIpKSB7XG4gICAgICBjb250aW51ZTsgLy8gU2tpcCB0aGlzIHBhaXIgYmVjYXVzZSBvZiBpbnZhbGlkIHZhbHVlLlxuICAgIH1cblxuICAgIGlmIChzdGF0ZS5kdW1wICYmIENIQVJfTElORV9GRUVEID09PSBzdGF0ZS5kdW1wLmNoYXJDb2RlQXQoMCkpIHtcbiAgICAgIHBhaXJCdWZmZXIgKz0gJzonO1xuICAgIH0gZWxzZSB7XG4gICAgICBwYWlyQnVmZmVyICs9ICc6ICc7XG4gICAgfVxuXG4gICAgcGFpckJ1ZmZlciArPSBzdGF0ZS5kdW1wO1xuXG4gICAgLy8gQm90aCBrZXkgYW5kIHZhbHVlIGFyZSB2YWxpZC5cbiAgICBfcmVzdWx0ICs9IHBhaXJCdWZmZXI7XG4gIH1cblxuICBzdGF0ZS50YWcgPSBfdGFnO1xuICBzdGF0ZS5kdW1wID0gX3Jlc3VsdCB8fCAne30nOyAvLyBFbXB0eSBtYXBwaW5nIGlmIG5vIHZhbGlkIHBhaXJzLlxufVxuXG5mdW5jdGlvbiBkZXRlY3RUeXBlKHN0YXRlLCBvYmplY3QsIGV4cGxpY2l0KSB7XG4gIHZhciBfcmVzdWx0LCB0eXBlTGlzdCwgaW5kZXgsIGxlbmd0aCwgdHlwZSwgc3R5bGU7XG5cbiAgdHlwZUxpc3QgPSBleHBsaWNpdCA/IHN0YXRlLmV4cGxpY2l0VHlwZXMgOiBzdGF0ZS5pbXBsaWNpdFR5cGVzO1xuXG4gIGZvciAoaW5kZXggPSAwLCBsZW5ndGggPSB0eXBlTGlzdC5sZW5ndGg7IGluZGV4IDwgbGVuZ3RoOyBpbmRleCArPSAxKSB7XG4gICAgdHlwZSA9IHR5cGVMaXN0W2luZGV4XTtcblxuICAgIGlmICgodHlwZS5pbnN0YW5jZU9mICB8fCB0eXBlLnByZWRpY2F0ZSkgJiZcbiAgICAgICAgKCF0eXBlLmluc3RhbmNlT2YgfHwgKCh0eXBlb2Ygb2JqZWN0ID09PSAnb2JqZWN0JykgJiYgKG9iamVjdCBpbnN0YW5jZW9mIHR5cGUuaW5zdGFuY2VPZikpKSAmJlxuICAgICAgICAoIXR5cGUucHJlZGljYXRlICB8fCB0eXBlLnByZWRpY2F0ZShvYmplY3QpKSkge1xuXG4gICAgICBpZiAoZXhwbGljaXQpIHtcbiAgICAgICAgaWYgKHR5cGUubXVsdGkgJiYgdHlwZS5yZXByZXNlbnROYW1lKSB7XG4gICAgICAgICAgc3RhdGUudGFnID0gdHlwZS5yZXByZXNlbnROYW1lKG9iamVjdCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgc3RhdGUudGFnID0gdHlwZS50YWc7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHN0YXRlLnRhZyA9ICc/JztcbiAgICAgIH1cblxuICAgICAgaWYgKHR5cGUucmVwcmVzZW50KSB7XG4gICAgICAgIHN0eWxlID0gc3RhdGUuc3R5bGVNYXBbdHlwZS50YWddIHx8IHR5cGUuZGVmYXVsdFN0eWxlO1xuXG4gICAgICAgIGlmIChfdG9TdHJpbmcuY2FsbCh0eXBlLnJlcHJlc2VudCkgPT09ICdbb2JqZWN0IEZ1bmN0aW9uXScpIHtcbiAgICAgICAgICBfcmVzdWx0ID0gdHlwZS5yZXByZXNlbnQob2JqZWN0LCBzdHlsZSk7XG4gICAgICAgIH0gZWxzZSBpZiAoX2hhc093blByb3BlcnR5LmNhbGwodHlwZS5yZXByZXNlbnQsIHN0eWxlKSkge1xuICAgICAgICAgIF9yZXN1bHQgPSB0eXBlLnJlcHJlc2VudFtzdHlsZV0ob2JqZWN0LCBzdHlsZSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdGhyb3cgbmV3IGV4Y2VwdGlvbignITwnICsgdHlwZS50YWcgKyAnPiB0YWcgcmVzb2x2ZXIgYWNjZXB0cyBub3QgXCInICsgc3R5bGUgKyAnXCIgc3R5bGUnKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHN0YXRlLmR1bXAgPSBfcmVzdWx0O1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gZmFsc2U7XG59XG5cbi8vIFNlcmlhbGl6ZXMgYG9iamVjdGAgYW5kIHdyaXRlcyBpdCB0byBnbG9iYWwgYHJlc3VsdGAuXG4vLyBSZXR1cm5zIHRydWUgb24gc3VjY2Vzcywgb3IgZmFsc2Ugb24gaW52YWxpZCBvYmplY3QuXG4vL1xuZnVuY3Rpb24gd3JpdGVOb2RlKHN0YXRlLCBsZXZlbCwgb2JqZWN0LCBibG9jaywgY29tcGFjdCwgaXNrZXksIGlzYmxvY2tzZXEpIHtcbiAgc3RhdGUudGFnID0gbnVsbDtcbiAgc3RhdGUuZHVtcCA9IG9iamVjdDtcblxuICBpZiAoIWRldGVjdFR5cGUoc3RhdGUsIG9iamVjdCwgZmFsc2UpKSB7XG4gICAgZGV0ZWN0VHlwZShzdGF0ZSwgb2JqZWN0LCB0cnVlKTtcbiAgfVxuXG4gIHZhciB0eXBlID0gX3RvU3RyaW5nLmNhbGwoc3RhdGUuZHVtcCk7XG4gIHZhciBpbmJsb2NrID0gYmxvY2s7XG4gIHZhciB0YWdTdHI7XG5cbiAgaWYgKGJsb2NrKSB7XG4gICAgYmxvY2sgPSAoc3RhdGUuZmxvd0xldmVsIDwgMCB8fCBzdGF0ZS5mbG93TGV2ZWwgPiBsZXZlbCk7XG4gIH1cblxuICB2YXIgb2JqZWN0T3JBcnJheSA9IHR5cGUgPT09ICdbb2JqZWN0IE9iamVjdF0nIHx8IHR5cGUgPT09ICdbb2JqZWN0IEFycmF5XScsXG4gICAgICBkdXBsaWNhdGVJbmRleCxcbiAgICAgIGR1cGxpY2F0ZTtcblxuICBpZiAob2JqZWN0T3JBcnJheSkge1xuICAgIGR1cGxpY2F0ZUluZGV4ID0gc3RhdGUuZHVwbGljYXRlcy5pbmRleE9mKG9iamVjdCk7XG4gICAgZHVwbGljYXRlID0gZHVwbGljYXRlSW5kZXggIT09IC0xO1xuICB9XG5cbiAgaWYgKChzdGF0ZS50YWcgIT09IG51bGwgJiYgc3RhdGUudGFnICE9PSAnPycpIHx8IGR1cGxpY2F0ZSB8fCAoc3RhdGUuaW5kZW50ICE9PSAyICYmIGxldmVsID4gMCkpIHtcbiAgICBjb21wYWN0ID0gZmFsc2U7XG4gIH1cblxuICBpZiAoZHVwbGljYXRlICYmIHN0YXRlLnVzZWREdXBsaWNhdGVzW2R1cGxpY2F0ZUluZGV4XSkge1xuICAgIHN0YXRlLmR1bXAgPSAnKnJlZl8nICsgZHVwbGljYXRlSW5kZXg7XG4gIH0gZWxzZSB7XG4gICAgaWYgKG9iamVjdE9yQXJyYXkgJiYgZHVwbGljYXRlICYmICFzdGF0ZS51c2VkRHVwbGljYXRlc1tkdXBsaWNhdGVJbmRleF0pIHtcbiAgICAgIHN0YXRlLnVzZWREdXBsaWNhdGVzW2R1cGxpY2F0ZUluZGV4XSA9IHRydWU7XG4gICAgfVxuICAgIGlmICh0eXBlID09PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgICAgaWYgKGJsb2NrICYmIChPYmplY3Qua2V5cyhzdGF0ZS5kdW1wKS5sZW5ndGggIT09IDApKSB7XG4gICAgICAgIHdyaXRlQmxvY2tNYXBwaW5nKHN0YXRlLCBsZXZlbCwgc3RhdGUuZHVtcCwgY29tcGFjdCk7XG4gICAgICAgIGlmIChkdXBsaWNhdGUpIHtcbiAgICAgICAgICBzdGF0ZS5kdW1wID0gJyZyZWZfJyArIGR1cGxpY2F0ZUluZGV4ICsgc3RhdGUuZHVtcDtcbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgd3JpdGVGbG93TWFwcGluZyhzdGF0ZSwgbGV2ZWwsIHN0YXRlLmR1bXApO1xuICAgICAgICBpZiAoZHVwbGljYXRlKSB7XG4gICAgICAgICAgc3RhdGUuZHVtcCA9ICcmcmVmXycgKyBkdXBsaWNhdGVJbmRleCArICcgJyArIHN0YXRlLmR1bXA7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKHR5cGUgPT09ICdbb2JqZWN0IEFycmF5XScpIHtcbiAgICAgIGlmIChibG9jayAmJiAoc3RhdGUuZHVtcC5sZW5ndGggIT09IDApKSB7XG4gICAgICAgIGlmIChzdGF0ZS5ub0FycmF5SW5kZW50ICYmICFpc2Jsb2Nrc2VxICYmIGxldmVsID4gMCkge1xuICAgICAgICAgIHdyaXRlQmxvY2tTZXF1ZW5jZShzdGF0ZSwgbGV2ZWwgLSAxLCBzdGF0ZS5kdW1wLCBjb21wYWN0KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB3cml0ZUJsb2NrU2VxdWVuY2Uoc3RhdGUsIGxldmVsLCBzdGF0ZS5kdW1wLCBjb21wYWN0KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZHVwbGljYXRlKSB7XG4gICAgICAgICAgc3RhdGUuZHVtcCA9ICcmcmVmXycgKyBkdXBsaWNhdGVJbmRleCArIHN0YXRlLmR1bXA7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdyaXRlRmxvd1NlcXVlbmNlKHN0YXRlLCBsZXZlbCwgc3RhdGUuZHVtcCk7XG4gICAgICAgIGlmIChkdXBsaWNhdGUpIHtcbiAgICAgICAgICBzdGF0ZS5kdW1wID0gJyZyZWZfJyArIGR1cGxpY2F0ZUluZGV4ICsgJyAnICsgc3RhdGUuZHVtcDtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gZWxzZSBpZiAodHlwZSA9PT0gJ1tvYmplY3QgU3RyaW5nXScpIHtcbiAgICAgIGlmIChzdGF0ZS50YWcgIT09ICc/Jykge1xuICAgICAgICB3cml0ZVNjYWxhcihzdGF0ZSwgc3RhdGUuZHVtcCwgbGV2ZWwsIGlza2V5LCBpbmJsb2NrKTtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKHR5cGUgPT09ICdbb2JqZWN0IFVuZGVmaW5lZF0nKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChzdGF0ZS5za2lwSW52YWxpZCkgcmV0dXJuIGZhbHNlO1xuICAgICAgdGhyb3cgbmV3IGV4Y2VwdGlvbigndW5hY2NlcHRhYmxlIGtpbmQgb2YgYW4gb2JqZWN0IHRvIGR1bXAgJyArIHR5cGUpO1xuICAgIH1cblxuICAgIGlmIChzdGF0ZS50YWcgIT09IG51bGwgJiYgc3RhdGUudGFnICE9PSAnPycpIHtcbiAgICAgIC8vIE5lZWQgdG8gZW5jb2RlIGFsbCBjaGFyYWN0ZXJzIGV4Y2VwdCB0aG9zZSBhbGxvd2VkIGJ5IHRoZSBzcGVjOlxuICAgICAgLy9cbiAgICAgIC8vIFszNV0gbnMtZGVjLWRpZ2l0ICAgIDo6PSAgWyN4MzAtI3gzOV0gLyogMC05ICovXG4gICAgICAvLyBbMzZdIG5zLWhleC1kaWdpdCAgICA6Oj0gIG5zLWRlYy1kaWdpdFxuICAgICAgLy8gICAgICAgICAgICAgICAgICAgICAgICAgfCBbI3g0MS0jeDQ2XSAvKiBBLUYgKi8gfCBbI3g2MS0jeDY2XSAvKiBhLWYgKi9cbiAgICAgIC8vIFszN10gbnMtYXNjaWktbGV0dGVyIDo6PSAgWyN4NDEtI3g1QV0gLyogQS1aICovIHwgWyN4NjEtI3g3QV0gLyogYS16ICovXG4gICAgICAvLyBbMzhdIG5zLXdvcmQtY2hhciAgICA6Oj0gIG5zLWRlYy1kaWdpdCB8IG5zLWFzY2lpLWxldHRlciB8IFx1MjAxQy1cdTIwMURcbiAgICAgIC8vIFszOV0gbnMtdXJpLWNoYXIgICAgIDo6PSAgXHUyMDFDJVx1MjAxRCBucy1oZXgtZGlnaXQgbnMtaGV4LWRpZ2l0IHwgbnMtd29yZC1jaGFyIHwgXHUyMDFDI1x1MjAxRFxuICAgICAgLy8gICAgICAgICAgICAgICAgICAgICAgICAgfCBcdTIwMUM7XHUyMDFEIHwgXHUyMDFDL1x1MjAxRCB8IFx1MjAxQz9cdTIwMUQgfCBcdTIwMUM6XHUyMDFEIHwgXHUyMDFDQFx1MjAxRCB8IFx1MjAxQyZcdTIwMUQgfCBcdTIwMUM9XHUyMDFEIHwgXHUyMDFDK1x1MjAxRCB8IFx1MjAxQyRcdTIwMUQgfCBcdTIwMUMsXHUyMDFEXG4gICAgICAvLyAgICAgICAgICAgICAgICAgICAgICAgICB8IFx1MjAxQ19cdTIwMUQgfCBcdTIwMUMuXHUyMDFEIHwgXHUyMDFDIVx1MjAxRCB8IFx1MjAxQ35cdTIwMUQgfCBcdTIwMUMqXHUyMDFEIHwgXHUyMDFDJ1x1MjAxRCB8IFx1MjAxQyhcdTIwMUQgfCBcdTIwMUMpXHUyMDFEIHwgXHUyMDFDW1x1MjAxRCB8IFx1MjAxQ11cdTIwMURcbiAgICAgIC8vXG4gICAgICAvLyBBbHNvIG5lZWQgdG8gZW5jb2RlICchJyBiZWNhdXNlIGl0IGhhcyBzcGVjaWFsIG1lYW5pbmcgKGVuZCBvZiB0YWcgcHJlZml4KS5cbiAgICAgIC8vXG4gICAgICB0YWdTdHIgPSBlbmNvZGVVUkkoXG4gICAgICAgIHN0YXRlLnRhZ1swXSA9PT0gJyEnID8gc3RhdGUudGFnLnNsaWNlKDEpIDogc3RhdGUudGFnXG4gICAgICApLnJlcGxhY2UoLyEvZywgJyUyMScpO1xuXG4gICAgICBpZiAoc3RhdGUudGFnWzBdID09PSAnIScpIHtcbiAgICAgICAgdGFnU3RyID0gJyEnICsgdGFnU3RyO1xuICAgICAgfSBlbHNlIGlmICh0YWdTdHIuc2xpY2UoMCwgMTgpID09PSAndGFnOnlhbWwub3JnLDIwMDI6Jykge1xuICAgICAgICB0YWdTdHIgPSAnISEnICsgdGFnU3RyLnNsaWNlKDE4KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRhZ1N0ciA9ICchPCcgKyB0YWdTdHIgKyAnPic7XG4gICAgICB9XG5cbiAgICAgIHN0YXRlLmR1bXAgPSB0YWdTdHIgKyAnICcgKyBzdGF0ZS5kdW1wO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiB0cnVlO1xufVxuXG5mdW5jdGlvbiBnZXREdXBsaWNhdGVSZWZlcmVuY2VzKG9iamVjdCwgc3RhdGUpIHtcbiAgdmFyIG9iamVjdHMgPSBbXSxcbiAgICAgIGR1cGxpY2F0ZXNJbmRleGVzID0gW10sXG4gICAgICBpbmRleCxcbiAgICAgIGxlbmd0aDtcblxuICBpbnNwZWN0Tm9kZShvYmplY3QsIG9iamVjdHMsIGR1cGxpY2F0ZXNJbmRleGVzKTtcblxuICBmb3IgKGluZGV4ID0gMCwgbGVuZ3RoID0gZHVwbGljYXRlc0luZGV4ZXMubGVuZ3RoOyBpbmRleCA8IGxlbmd0aDsgaW5kZXggKz0gMSkge1xuICAgIHN0YXRlLmR1cGxpY2F0ZXMucHVzaChvYmplY3RzW2R1cGxpY2F0ZXNJbmRleGVzW2luZGV4XV0pO1xuICB9XG4gIHN0YXRlLnVzZWREdXBsaWNhdGVzID0gbmV3IEFycmF5KGxlbmd0aCk7XG59XG5cbmZ1bmN0aW9uIGluc3BlY3ROb2RlKG9iamVjdCwgb2JqZWN0cywgZHVwbGljYXRlc0luZGV4ZXMpIHtcbiAgdmFyIG9iamVjdEtleUxpc3QsXG4gICAgICBpbmRleCxcbiAgICAgIGxlbmd0aDtcblxuICBpZiAob2JqZWN0ICE9PSBudWxsICYmIHR5cGVvZiBvYmplY3QgPT09ICdvYmplY3QnKSB7XG4gICAgaW5kZXggPSBvYmplY3RzLmluZGV4T2Yob2JqZWN0KTtcbiAgICBpZiAoaW5kZXggIT09IC0xKSB7XG4gICAgICBpZiAoZHVwbGljYXRlc0luZGV4ZXMuaW5kZXhPZihpbmRleCkgPT09IC0xKSB7XG4gICAgICAgIGR1cGxpY2F0ZXNJbmRleGVzLnB1c2goaW5kZXgpO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICBvYmplY3RzLnB1c2gob2JqZWN0KTtcblxuICAgICAgaWYgKEFycmF5LmlzQXJyYXkob2JqZWN0KSkge1xuICAgICAgICBmb3IgKGluZGV4ID0gMCwgbGVuZ3RoID0gb2JqZWN0Lmxlbmd0aDsgaW5kZXggPCBsZW5ndGg7IGluZGV4ICs9IDEpIHtcbiAgICAgICAgICBpbnNwZWN0Tm9kZShvYmplY3RbaW5kZXhdLCBvYmplY3RzLCBkdXBsaWNhdGVzSW5kZXhlcyk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG9iamVjdEtleUxpc3QgPSBPYmplY3Qua2V5cyhvYmplY3QpO1xuXG4gICAgICAgIGZvciAoaW5kZXggPSAwLCBsZW5ndGggPSBvYmplY3RLZXlMaXN0Lmxlbmd0aDsgaW5kZXggPCBsZW5ndGg7IGluZGV4ICs9IDEpIHtcbiAgICAgICAgICBpbnNwZWN0Tm9kZShvYmplY3Rbb2JqZWN0S2V5TGlzdFtpbmRleF1dLCBvYmplY3RzLCBkdXBsaWNhdGVzSW5kZXhlcyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuZnVuY3Rpb24gZHVtcCQxKGlucHV0LCBvcHRpb25zKSB7XG4gIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gIHZhciBzdGF0ZSA9IG5ldyBTdGF0ZShvcHRpb25zKTtcblxuICBpZiAoIXN0YXRlLm5vUmVmcykgZ2V0RHVwbGljYXRlUmVmZXJlbmNlcyhpbnB1dCwgc3RhdGUpO1xuXG4gIHZhciB2YWx1ZSA9IGlucHV0O1xuXG4gIGlmIChzdGF0ZS5yZXBsYWNlcikge1xuICAgIHZhbHVlID0gc3RhdGUucmVwbGFjZXIuY2FsbCh7ICcnOiB2YWx1ZSB9LCAnJywgdmFsdWUpO1xuICB9XG5cbiAgaWYgKHdyaXRlTm9kZShzdGF0ZSwgMCwgdmFsdWUsIHRydWUsIHRydWUpKSByZXR1cm4gc3RhdGUuZHVtcCArICdcXG4nO1xuXG4gIHJldHVybiAnJztcbn1cblxudmFyIGR1bXBfMSA9IGR1bXAkMTtcblxudmFyIGR1bXBlciA9IHtcblx0ZHVtcDogZHVtcF8xXG59O1xuXG5mdW5jdGlvbiByZW5hbWVkKGZyb20sIHRvKSB7XG4gIHJldHVybiBmdW5jdGlvbiAoKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdGdW5jdGlvbiB5YW1sLicgKyBmcm9tICsgJyBpcyByZW1vdmVkIGluIGpzLXlhbWwgNC4gJyArXG4gICAgICAnVXNlIHlhbWwuJyArIHRvICsgJyBpbnN0ZWFkLCB3aGljaCBpcyBub3cgc2FmZSBieSBkZWZhdWx0LicpO1xuICB9O1xufVxuXG5cbnZhciBUeXBlICAgICAgICAgICAgICAgID0gdHlwZTtcbnZhciBTY2hlbWEgICAgICAgICAgICAgID0gc2NoZW1hO1xudmFyIEZBSUxTQUZFX1NDSEVNQSAgICAgPSBmYWlsc2FmZTtcbnZhciBKU09OX1NDSEVNQSAgICAgICAgID0ganNvbjtcbnZhciBDT1JFX1NDSEVNQSAgICAgICAgID0gY29yZTtcbnZhciBERUZBVUxUX1NDSEVNQSAgICAgID0gX2RlZmF1bHQ7XG52YXIgbG9hZCAgICAgICAgICAgICAgICA9IGxvYWRlci5sb2FkO1xudmFyIGxvYWRBbGwgICAgICAgICAgICAgPSBsb2FkZXIubG9hZEFsbDtcbnZhciBkdW1wICAgICAgICAgICAgICAgID0gZHVtcGVyLmR1bXA7XG52YXIgWUFNTEV4Y2VwdGlvbiAgICAgICA9IGV4Y2VwdGlvbjtcblxuLy8gUmUtZXhwb3J0IGFsbCB0eXBlcyBpbiBjYXNlIHVzZXIgd2FudHMgdG8gY3JlYXRlIGN1c3RvbSBzY2hlbWFcbnZhciB0eXBlcyA9IHtcbiAgYmluYXJ5OiAgICBiaW5hcnksXG4gIGZsb2F0OiAgICAgZmxvYXQsXG4gIG1hcDogICAgICAgbWFwLFxuICBudWxsOiAgICAgIF9udWxsLFxuICBwYWlyczogICAgIHBhaXJzLFxuICBzZXQ6ICAgICAgIHNldCxcbiAgdGltZXN0YW1wOiB0aW1lc3RhbXAsXG4gIGJvb2w6ICAgICAgYm9vbCxcbiAgaW50OiAgICAgICBpbnQsXG4gIG1lcmdlOiAgICAgbWVyZ2UsXG4gIG9tYXA6ICAgICAgb21hcCxcbiAgc2VxOiAgICAgICBzZXEsXG4gIHN0cjogICAgICAgc3RyXG59O1xuXG4vLyBSZW1vdmVkIGZ1bmN0aW9ucyBmcm9tIEpTLVlBTUwgMy4wLnhcbnZhciBzYWZlTG9hZCAgICAgICAgICAgID0gcmVuYW1lZCgnc2FmZUxvYWQnLCAnbG9hZCcpO1xudmFyIHNhZmVMb2FkQWxsICAgICAgICAgPSByZW5hbWVkKCdzYWZlTG9hZEFsbCcsICdsb2FkQWxsJyk7XG52YXIgc2FmZUR1bXAgICAgICAgICAgICA9IHJlbmFtZWQoJ3NhZmVEdW1wJywgJ2R1bXAnKTtcblxudmFyIGpzWWFtbCA9IHtcblx0VHlwZTogVHlwZSxcblx0U2NoZW1hOiBTY2hlbWEsXG5cdEZBSUxTQUZFX1NDSEVNQTogRkFJTFNBRkVfU0NIRU1BLFxuXHRKU09OX1NDSEVNQTogSlNPTl9TQ0hFTUEsXG5cdENPUkVfU0NIRU1BOiBDT1JFX1NDSEVNQSxcblx0REVGQVVMVF9TQ0hFTUE6IERFRkFVTFRfU0NIRU1BLFxuXHRsb2FkOiBsb2FkLFxuXHRsb2FkQWxsOiBsb2FkQWxsLFxuXHRkdW1wOiBkdW1wLFxuXHRZQU1MRXhjZXB0aW9uOiBZQU1MRXhjZXB0aW9uLFxuXHR0eXBlczogdHlwZXMsXG5cdHNhZmVMb2FkOiBzYWZlTG9hZCxcblx0c2FmZUxvYWRBbGw6IHNhZmVMb2FkQWxsLFxuXHRzYWZlRHVtcDogc2FmZUR1bXBcbn07XG5cbmV4cG9ydCBkZWZhdWx0IGpzWWFtbDtcbmV4cG9ydCB7IENPUkVfU0NIRU1BLCBERUZBVUxUX1NDSEVNQSwgRkFJTFNBRkVfU0NIRU1BLCBKU09OX1NDSEVNQSwgU2NoZW1hLCBUeXBlLCBZQU1MRXhjZXB0aW9uLCBkdW1wLCBsb2FkLCBsb2FkQWxsLCBzYWZlRHVtcCwgc2FmZUxvYWQsIHNhZmVMb2FkQWxsLCB0eXBlcyB9O1xuIiwgImltcG9ydCBnZXRDb25maWcgZnJvbSAnLi9jb25maWcnO1xuXG5jb25zdCBjb25maWcgPSBnZXRDb25maWcoKTtcbiJdLAogICJtYXBwaW5ncyI6ICI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFVQSxhQUFnQixlQUFlLE9BQVU7QUFDdkMsVUFBSSxVQUFVLFFBQVEsVUFBVSxRQUFXO0FBQ3pDLGVBQU87aUJBQ0UsT0FBTyxVQUFVLFlBQVksaUJBQWlCLFFBQVE7QUFDL0QsZUFBTzs7QUFFVCxhQUFPLEtBQUssVUFBVSxLQUFLO0lBQzdCO0FBUEEsWUFBQSxpQkFBQTtBQWVBLGFBQWdCLG9CQUNkLHNCQUEwQztBQUUxQyxVQUFJLENBQUMsT0FBTyxLQUFLLG9CQUFvQixFQUFFLFFBQVE7QUFDN0MsZUFBTyxDQUFBOztBQUdULGFBQU87UUFDTCxPQUFPLHFCQUFxQjtRQUM1QixNQUFNLHFCQUFxQjtRQUMzQixNQUFNLHFCQUFxQjtRQUMzQixTQUFTLHFCQUFxQjtRQUM5QixLQUFLLHFCQUFxQjtRQUMxQixXQUFXLHFCQUFxQjs7SUFFcEM7QUFmQSxZQUFBLHNCQUFBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ3pCQSxRQUFBLEtBQUEsYUFBQSxRQUFBLElBQUEs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aUJBQVEsTUFBTTtBQUNqQixRQUFNQSxVQUFTLFNBQUssc0JBQVMsUUFBUSxDQUFDO0FBQ3RDLE1BQUksQ0FBQ0EsV0FBVSxPQUFPQSxZQUFXLFlBQVksTUFBTSxRQUFRQSxPQUFNLEdBQUc7QUFDaEUsMkJBQU0sa0VBQWtFO0FBQUEsRUFDNUU7QUFDQSx3QkFBSztBQUFBLEVBQW1CLEtBQUtBLE9BQU0sR0FBRztBQUN0QyxRQUFNLGVBQWUsZ0JBQWdCO0FBQ3JDLHdCQUFLO0FBQUEsRUFBMEIsS0FBSyxZQUFZLEdBQUc7QUFDbkQsNkJBQTJCQSxTQUErQixZQUFZO0FBQ3RFLHdCQUFLO0FBQUEsRUFBd0IsS0FBS0EsT0FBTSxHQUFHO0FBQzNDLFNBQU9BO0FBQ1g7OztBRTdDQSxJQUFNLFNBQVMsZUFBVTsiLAogICJuYW1lcyI6IFsiY3J5cHRvIiwgInN0ciIsICJ2ZXJzaW9uIiwgIlVSTCIsICJjcnlwdG8iLCAiaW1wb3J0X2NyeXB0byIsICJjcnlwdG8iLCAiaW1wb3J0X2NyeXB0byIsICJvcHRpb25zIiwgImVycm9yIiwgInNvY2tldCIsICJyZXF1aXJlX3R1bm5lbCIsICJtb2R1bGUiLCAiSHR0cENvZGVzIiwgIkhlYWRlcnMiLCAiTWVkaWFUeXBlcyIsICJpbmZvIiwgIl9kZWZhdWx0IiwgImVycm9yIiwgIkV4aXRDb2RlIiwgImdldElucHV0IiwgImVycm9yIiwgImluZm8iLCAiZXhjZXB0aW9uIiwgIm1hcCIsICJzY2hlbWEiLCAidHlwZSIsICJleHRlbmQiLCAic3RyIiwgInN0cmluZyIsICJzdHIiLCAiY29uZmlnIl0KfQo=