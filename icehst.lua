-- icehst.lua
-- minimal CC:Tweaked Rednet client/server protocol module

local expect = require("cc.expect").expect
local field = require("cc.expect").field
local icehst = {}

icehst.terminal = 1
icehst.monitor = 2

local PROTOCOL = "icehst"
local DEFAULT_SITE = "default"

local siteName = DEFAULT_SITE
local routes = {}
local requestCounter = 0
local sessions = {}
local encryptedEnabled = true
local pendingTasks = {}

local function scheduleTask(fn)
    local co = coroutine.create(fn)
    table.insert(pendingTasks, co)
    return co
end

local function runPendingTasks()
    local i = 1
    while i <= #pendingTasks do
        local co = pendingTasks[i]
        if coroutine.status(co) == "dead" then
            table.remove(pendingTasks, i)
        else
            local ok, err = coroutine.resume(co)
            if not ok then
                table.remove(pendingTasks, i)
            elseif coroutine.status(co) == "dead" then
                table.remove(pendingTasks, i)
            else
                i = i + 1
            end
        end
    end
end

math.randomseed(os.epoch())

icehst.status = {
    OK = 200,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
    TIMEOUT = 408,
    SERVER_ERROR = 500
}

local function hash(str)
    local h = 0
    for i = 1, #str do
        h = (h * 31 + string.byte(str, i)) % 2^32
    end
    return h
end

local function deriveSessionKey(a, b)
    local combined = a < b and a .. ":" .. b or b .. ":" .. a
    local keyBytes = {}
    for i = 1, 16 do
        keyBytes[i] = hash(combined .. ":" .. i) % 256
    end
    return string.char(table.unpack(keyBytes))
end

local function ensureSession(sender)
    if sessions[sender] then
        return
    end
    local localId = tostring(os.getComputerID())
    sessions[sender] = {
        key = deriveSessionKey(localId, tostring(sender))
    }
end

local function ensureRednetOpen(side)
    if side and rednet.isOpen(side) then
        return
    end

    if side then
        pcall(rednet.open, side)
        if rednet.isOpen(side) then
            return
        end
    end

    for _, name in ipairs(peripheral.getNames()) do
        local ptype = peripheral.getType(name)
        if ptype == "wireless_modem" or ptype == "modem" then
            if not rednet.isOpen(name) then
                pcall(rednet.open, name)
            end
            return
        end
    end
end

local function serialize(value)
    return textutils.serialize(value)
end

local function deserialize(value)
    if type(value) ~= "string" then
        return nil
    end
    local ok, result = pcall(textutils.unserialize, value)
    return ok and result or nil
end

local AES_BLOCK_SIZE = 16
local aesSbox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
}
local aesRcon = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36}

local function bytesToWord(b1, b2, b3, b4)
    return bit32.lshift(b1, 24) + bit32.lshift(b2, 16) + bit32.lshift(b3, 8) + b4
end

local function wordToBytes(w)
    return bit32.band(bit32.rshift(w, 24), 0xFF), bit32.band(bit32.rshift(w, 16), 0xFF), bit32.band(bit32.rshift(w, 8), 0xFF), bit32.band(w, 0xFF)
end

local function rotWord(w)
    local b1, b2, b3, b4 = wordToBytes(w)
    return bytesToWord(b2, b3, b4, b1)
end

local function subWord(w)
    local b1, b2, b3, b4 = wordToBytes(w)
    return bytesToWord(aesSbox[b1 + 1], aesSbox[b2 + 1], aesSbox[b3 + 1], aesSbox[b4 + 1])
end

local function aesKeySchedule(key)
    local schedule = {}
    for i = 0, 3 do
        local idx = i * 4
        schedule[i] = bytesToWord(string.byte(key, idx + 1), string.byte(key, idx + 2), string.byte(key, idx + 3), string.byte(key, idx + 4))
    end
    for i = 4, 43 do
        local temp = schedule[i - 1]
        if i % 4 == 0 then
            temp = bit32.bxor(subWord(rotWord(temp)), bit32.lshift(aesRcon[i / 4], 24))
        end
        schedule[i] = bit32.bxor(schedule[i - 4], temp)
    end
    return schedule
end

local function addRoundKey(state, schedule, round)
    for i = 0, 3 do
        state[i] = bit32.bxor(state[i], schedule[round * 4 + i])
    end
end

local function subBytes(state)
    for i = 0, 3 do
        local b1, b2, b3, b4 = wordToBytes(state[i])
        state[i] = bytesToWord(aesSbox[b1 + 1], aesSbox[b2 + 1], aesSbox[b3 + 1], aesSbox[b4 + 1])
    end
end

local function shiftRows(state)
    local cols = {}
    for c = 1, 4 do
        cols[c] = {wordToBytes(state[c - 1])}
    end
    local newState = {}
    for c = 1, 4 do
        local a = cols[c][1]
        local b = cols[((c + 1 - 1) % 4) + 1][2]
        local c2 = cols[((c + 2 - 1) % 4) + 1][3]
        local d = cols[((c + 3 - 1) % 4) + 1][4]
        newState[c - 1] = bytesToWord(a, b, c2, d)
    end
    for i = 0, 3 do
        state[i] = newState[i]
    end
end

local function xtime(x)
    local v = bit32.lshift(x, 1)
    if x >= 0x80 then
        v = bit32.bxor(v, 0x11B)
    end
    return bit32.band(v, 0xFF)
end

local function mixColumn(a, b, c, d)
    local a2 = xtime(a)
    local b2 = xtime(b)
    local c2 = xtime(c)
    local d2 = xtime(d)
    return bit32.bxor(bit32.bxor(a2, bit32.bxor(b2, b)), c, d), bit32.bxor(a, bit32.bxor(b2, bit32.bxor(c2, c)), d), bit32.bxor(a, b, bit32.bxor(c2, bit32.bxor(d2, d))), bit32.bxor(bit32.bxor(a, a2), b, bit32.bxor(c, d2))
end

local function mixColumns(state)
    for i = 0, 3 do
        local b1, b2, b3, b4 = wordToBytes(state[i])
        local c1, c2, c3, c4 = mixColumn(b1, b2, b3, b4)
        state[i] = bytesToWord(c1, c2, c3, c4)
    end
end

local function aesEncryptBlock(block, schedule)
    local state = {}
    for i = 0, 3 do
        local idx = i * 4
        state[i] = bytesToWord(string.byte(block, idx + 1), string.byte(block, idx + 2), string.byte(block, idx + 3), string.byte(block, idx + 4))
    end
    addRoundKey(state, schedule, 0)
    for round = 1, 9 do
        subBytes(state)
        shiftRows(state)
        mixColumns(state)
        addRoundKey(state, schedule, round)
    end
    subBytes(state)
    shiftRows(state)
    addRoundKey(state, schedule, 10)
    local out = {}
    for i = 0, 3 do
        local b1, b2, b3, b4 = wordToBytes(state[i])
        out[i * 4 + 1] = string.char(b1)
        out[i * 4 + 2] = string.char(b2)
        out[i * 4 + 3] = string.char(b3)
        out[i * 4 + 4] = string.char(b4)
    end
    return table.concat(out)
end

local function incrementCounter(counter)
    for i = AES_BLOCK_SIZE, 1, -1 do
        counter[i] = counter[i] + 1
        if counter[i] < 256 then
            break
        end
        counter[i] = 0
    end
end

local function aesCtrCrypt(str, key, iv)
    if type(key) ~= "string" or #key ~= AES_BLOCK_SIZE then
        return str
    end
    if type(iv) ~= "string" or #iv ~= AES_BLOCK_SIZE then
        return str
    end
    local schedule = aesKeySchedule(key)
    local counter = {string.byte(iv, 1, AES_BLOCK_SIZE)}
    local out = {}
    for i = 1, #str, AES_BLOCK_SIZE do
        local keystream = aesEncryptBlock(string.char(table.unpack(counter)), schedule)
        for j = 1, AES_BLOCK_SIZE do
            local idx = i + j - 1
            if idx > #str then
                break
            end
            out[idx] = string.char(bit32.bxor(string.byte(str, idx), string.byte(keystream, j)))
        end
        incrementCounter(counter)
    end
    return table.concat(out)
end

local function randomBytes(length)
    local out = {}
    for i = 1, length do
        out[i] = string.char(math.random(0, 255))
    end
    return table.concat(out)
end

local function encryptPayload(str, key)
    local iv = randomBytes(AES_BLOCK_SIZE)
    return iv .. aesCtrCrypt(str, key, iv)
end

local function decryptPayload(str, key)
    if type(str) ~= "string" or #str <= AES_BLOCK_SIZE then
        return nil
    end
    local iv = string.sub(str, 1, AES_BLOCK_SIZE)
    local ciphertext = string.sub(str, AES_BLOCK_SIZE + 1)
    return aesCtrCrypt(ciphertext, key, iv)
end

local function makePacket(site, type_, id, route, data, nonce, code)
    return {
        v = 2,
        site = site,
        type = type_,
        id = id,
        route = route,
        data = data,
        nonce = nonce,
        code = code or icehst.status.OK
    }
end

local function sendRaw(id, packet)
    ensureRednetOpen()
    local payload = serialize(packet)
    if encryptedEnabled and sessions[id] and sessions[id].key then
        payload = encryptPayload(payload, sessions[id].key)
    end
    rednet.send(id, payload, PROTOCOL)
end

local function receiveRaw(sender, msg)
    if type(msg) ~= "string" then
        return nil
    end
    ensureSession(sender)
    if encryptedEnabled and sessions[sender] and sessions[sender].key then
        msg = decryptPayload(msg, sessions[sender].key)
        if not msg then
            return nil
        end
    end
    return deserialize(msg)
end

function icehst.route(path, fn)
    expect(1, path, "string")
    expect(2, fn, "function")
    if string.sub(path, 1, 1) == "/" then
        path = string.sub(path, 2)
    end
    routes[path] = fn
end

local function findRoute(route)
    if type(route) ~= "string" then
        return nil
    end
    if routes[route] then
        return routes[route]
    end
    local parts = {}
    for part in string.gmatch(route, "[^/]+") do
        table.insert(parts, part)
    end
    while #parts > 0 do
        local candidate = table.concat(parts, "/")
        if routes[candidate] then
            return routes[candidate]
        end
        table.remove(parts)
    end
    return nil
end

local function normalize(result)
    if result == nil then
        return icehst.status.OK, {}
    end
    if type(result) == "number" then
        return result, {}
    end
    if type(result) == "table" then
        if type(result[1]) == "number" and type(result[2]) == "table" then
            return result[1], result[2]
        end
        return icehst.status.OK, result
    end
    return icehst.status.SERVER_ERROR, {}
end

local function handlePacket(sender, packet)
    if not packet or packet.site ~= siteName or packet.type ~= "request" then
        return
    end
    local route = packet.route or ""
    if string.sub(route, 1, 1) == "/" then
        route = string.sub(route, 2)
    end
    local handler = findRoute(route)
    if not handler then
        sendRaw(sender, makePacket(siteName, "response", packet.id, packet.route, nil, packet.nonce, icehst.status.NOT_FOUND))
        return
    end

    scheduleTask(function()
        local ok, result = pcall(handler, sender, packet.data)
        if not ok then
            sendRaw(sender, makePacket(siteName, "response", packet.id, packet.route, nil, packet.nonce, icehst.status.SERVER_ERROR))
            return
        end
        local code, data = normalize(result)
        sendRaw(sender, makePacket(siteName, "response", packet.id, packet.route, data, packet.nonce, code))
    end)
end

function icehst.request(path, data, timeout)
    expect(1, path, "string")
    expect(3, timeout, "number", "nil")
    requestCounter = requestCounter + 1
    local id = requestCounter
    timeout = timeout or 5
    local site, route = string.match(path, "([^/]+)/(.+)")
    if not site or not route then
        return icehst.status.BAD_REQUEST, nil
    end
    ensureRednetOpen()
    local targetID = rednet.lookup(PROTOCOL, site)
    if not targetID then
        return icehst.status.NOT_FOUND, nil
    end
    ensureSession(targetID)
    sendRaw(targetID, makePacket(site, "request", id, route, data, os.epoch()))
    local start = os.clock()
    while true do
        local remaining = timeout - (os.clock() - start)
        if remaining <= 0 then
            return icehst.status.TIMEOUT, nil
        end
        local sender, msg = rednet.receive(PROTOCOL, remaining)
        if not sender then
            return icehst.status.TIMEOUT, nil
        end
        local packet = receiveRaw(sender, msg)
        if packet and packet.id == id and packet.type == "response" then
            return packet.code or icehst.status.OK, packet.data
        end
    end
end

local function renderFormat(fmt, values)
    return string.gsub(fmt, "%%([%w_]+)", function(token)
        return tostring(values[token] or "")
    end)
end

local function resolveModemSide(modem)
    if type(modem) == "string" then
        return modem
    end
    if type(modem) == "table" then
        return peripheral.getName(modem)
    end
    return nil
end

function icehst.run(site, config)
    expect(1, site, "string", "nil")
    siteName = site or DEFAULT_SITE
    encryptedEnabled = config.encrypted
    local modemSide = resolveModemSide(config.modem)
    if modemSide then
        pcall(rednet.open, modemSide)
    else
        ensureRednetOpen(config.side)
    end
    rednet.host(PROTOCOL, siteName)

    local display = config.display
    local fmt = config.fmt or {}
    local baseLog = fmt.log or ""
    local requestLog = fmt.request or ""

    local function printl(str)
        display.write(str)

        local x, y = display.getCursorPos()
        local w, h = display.getSize()

        x = 1
        y = y + 1

        if y > h then
            display.scroll(1)
            y = h
        end

        display.setCursorPos(x, y)
    end

    local function logRequest(sender, route, code)
        local now = os.date("*t")
        local values = {
            day = string.format("%02d", now.day),
            mon = string.format("%02d", now.month),
            year = tostring(now.year),
            hr = string.format("%02d", now.hour),
            min = string.format("%02d", now.min),
            sec = string.format("%02d", now.sec),
            level = "REQ",
            route = route,
            senderid = tostring(sender),
            datasent = "",
            datarecv = "",
            jsonsent = "",
            jsonrecv = "",
            code = tostring(code)
        }
        local line = renderFormat(baseLog .. requestLog, values)
        printl(line)
    end

    while true do
        local sender, msg = rednet.receive(PROTOCOL)
        if not sender then
            break
        end
        local packet = receiveRaw(sender, msg)
        handlePacket(sender, packet)
        runPendingTasks()
        if packet and packet.type == "request" then
            local route = packet.route or ""
            if string.sub(route, 1, 1) == "/" then
                route = string.sub(route, 2)
            end
            logRequest(sender, route, packet.code or icehst.status.OK)
        end
    end
end

function icehst.send(path, data)
    expect(1, path, "string")
    local site, route = string.match(path, "([^/]+)/(.+)")
    if not site or not route then
        return false
    end
    ensureRednetOpen()
    local targetID = rednet.lookup(PROTOCOL, site)
    if not targetID then
        return false
    end
    sendRaw(targetID, makePacket(site, "request", 0, route, data, os.epoch()))
    return true
end

return icehst
