local socket = require("socket")

--------------------------------------------------------------------------------

local function printf(...)
  io.write(string.format(...))
end

local function hexdump(payload)
  local t = { string.byte(payload, 1, #payload) }
  for k, v in ipairs(t) do
    printf("%.2x ", v)
    if (k % 16) == 0 then
      io.write("\n")
    elseif (k % 8) == 0 then
      io.write(" ")
    end
  end
  print()
end

--------------------------------------------------------------------------------

local response_codes = {
  [0] = "success",
  [1] = "operationsError",
  [2] = "protocolError",
  [3] = "timeLimitExceeded",
  [4] = "sizeLimitExceeded",
  [5] = "compareFalse",
  [6] = "compareTrue",
  [7] = "authMethodNotSupported",
  [8] = "strongerAuthRequired",
  -- 9 reserved --
  [10] = "referral",
  [11] = "adminLimitExceeded",
  [12] = "unavailableCriticalExtension",
  [13] = "confidentialityRequired",
  [14] = "saslBindInProgress",
  -- 15 ??? --
  [16] = "noSuchAttribute",
  [17] = "undefinedAttributeType",
  [18] = "inappropriateMatching",
  [19] = "constraintViolation",
  [20] = "attributeOrValueExists",
  [21] = "invalidAttributeSyntax",
  -- 22-31 unused --
  [32] = "noSuchObject",
  [33] = "aliasProblem",
  [34] = "invalidDNSyntax",
  -- 35 reserved for undefined isLeaf --
  [36] = "aliasDereferencingProblem",
  -- 37-47 unused --
  [48] = "inappropriateAuthentication",
  [49] = "invalidCredentials",
  [50] = "insufficientAccessRights",
  [51] = "busy",
  [52] = "unavailable",
  [53] = "unwillingToPerform",
  [54] = "loopDetect",
  -- 55-63 unused --
  [64] = "namingViolation",
  [65] = "objectClassViolation",
  [66] = "notAllowedOnNonLeaf",
  [67] = "notAllowedOnRDN",
  [68] = "entryAlreadyExists",
  [69] = "objectClassModsProhibited",
  -- 70 reserved for CLDAP --
  [71] = "affectsMultipleDSAs",
  -- 72-79 unused --
  [80] = "other",
}

--------------------------------------------------------------------------------

local meta = {}

function meta:peek()
  return string.byte(self._str, self._i, self._i)
end

function meta:byte()
  local b = string.byte(self._str, self._i, self._i)
  self._i = self._i + 1
  return b
end

function meta:string(n)
  local b = self:byte()
  local n = self:size()
  if n == 0 then
    return nil
  end
  local str = string.sub(self._str, self._i, self._i+n-1)
  self._i = self._i + n
  return str
end

function meta:integer()
  local b = self:byte()
  local n = self:byte()
  -- null?
  local v = string.unpack(">i"..n, self._str, self._i)
  self._i = self._i + n
  return v
end

function meta:enum()
  return self:integer()
end

function meta:boolean()
  local b = self:byte()
  local n = self:byte()
  return (self:byte() == 0xff)
end

function meta:size()
  local size = self:byte()
  if (size & 0x80) == 0 then
    return size
  end
  local n = size & 0x7F
  if n > 4 then
    error("size not supported")
  end
  size = string.unpack(">i"..n, self._str, self._i)
  self._i = self._i + n
  return size
end

function newbuffer(str)
  local buf = {
    _str = str,
    _i   = 1,
    _n   = #str,
  }
  return setmetatable(buf, { __index = meta })
end

--------------------------------------------------------------------------------

local function next_byte(s)
  local b, err = s:receive(1)
  if err then
    error(err)
  end
  return string.byte(b)
end

--------------------------------------------------------------------------------

local function next_size(s)
  local size = next_byte(s)
  if (size & 0x80) == 0 then
    return size
  end
  size = size & 0x7F
  if size > 4 then
    error("size not supported")
  end
  local n, err = s:receive(size)
  if err then
    error(err)
  end
  local fmt = ">i" .. size
  return string.unpack(fmt, n)
end

--------------------------------------------------------------------------------

local function packet_recv(s)
  local code = next_byte(s)
  assert(code == 0x30, "invalid code")
  local size = next_size(s)
  local payload, err = s:receive(size)
  if err then
    error(err)
  end
  return newbuffer(payload)
end

--------------------------------------------------------------------------------

local function next_id(self)
  local id = self._id
  self._id = self._id + 1
  if self._id == 2147483647 then
    self._id = 1
  end
  return id
end

--------------------------------------------------------------------------------

local function bind_response(sock, sid)
  local buf = packet_recv(sock)

  -- Message ID
  local id = buf:integer()
  assert(id == sid, "invalid message ID")
  -- Bind response: 0x61
  local code = buf:byte()
  assert(code == 0x61, "invalid code")
  -- Message size
  local size = buf:size()
  -- Enumerate
  local enum = buf:enum()
  -- Extra
  local dn  = buf:string()
  local msg = buf:string()

  if enum == 0 then
    return true
  end

  return false, (response_codes[enum] or "unknown")
end

--------------------------------------------------------------------------------

local function bind(self, name, pwd)
  if type(name) ~= "string" or type(pwd) ~= "string" then
    return nil, "invalid parameters"
  end

  local msg
  local id = self:next_id()
  msg = string.pack(">BBs4", 0x80, 0x84, pwd)
  msg = string.pack(">BBs4", 0x04, 0x84, name) .. msg
  -- version 3
  msg = string.pack(">BBB",  0x02, 0x01, 0x03) .. msg
  -- bind
  msg = string.pack(">BBs4", 0x60, 0x84, msg)
  -- message id
  msg = string.pack(">BBi4",  0x02, 0x04, id) .. msg
  -- package
  msg = string.pack(">BBs4", 0x30, 0x84, msg)

  self._sock:send(msg)

  local succ, resp, msg = pcall(bind_response, self._sock, id)
  if not succ then
    return false, resp
  end
  return resp, msg
end

--------------------------------------------------------------------------------

local function unbind(self)
  local msg
  local id = self:next_id()
  -- unbind
  msg = string.pack(">BB", 0x42, 0x00)
  -- message id
  msg = string.pack(">BBi4",  0x02, 0x04, id) .. msg
  -- package
  msg = string.pack(">BBs4", 0x30, 0x84, msg)

  self._sock:send(msg)
end

--------------------------------------------------------------------------------

local operations = {
  __index = {
    bind    = bind,
    unbind  = unbind,
    next_id = next_id
  }
}

--------------------------------------------------------------------------------

local function parse_server(server)
  local host, port = string.match(server, "^([^:]+):(d+)$")
  if host then
    return host, port
  end
  host, port = string.match(server, "^([^:]+):?$")
  if host then
    return host, 389
  end
  return nil, nil
end

--------------------------------------------------------------------------------

local function open_simple(server, who, pwd)
  local host, port = parse_server(server)
  if not host then
    return nil, "invalid server"
  end

  local s = socket.tcp()
  local succ, msg = s:connect(host, port)
  if not succ then
    return nil, msg
  end

  s:setoption('tcp-nodelay', true)
  s:setoption('keepalive', true)

  local ld = {
    _sock = s,
    _id = 1
  }

  ld = setmetatable(ld, operations)

  succ, msg = ld:bind(who, pwd)
  if not succ then
    return nil, msg
  end

  return ld
end

return {
  open_simple = open_simple
}