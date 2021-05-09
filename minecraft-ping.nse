local nmap = require('nmap')
local stdnse = require('stdnse')
local json = require('json')

description = [[
Attempts to validate if alive host and port is a Minecraft Server.
This uses the modern Server List Ping protocol explained at https://wiki.vg
]]

-- @usage
-- nmap --script minecraft-ping.nse <host> -p <ports>
---
-- @output
-- |_minecraft-ping: host:port (online/max) [version]

author = 'Saker'

license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'

categories = {'version', 'safe'}

portrule = function(host, port)
	return port.protocol == 'tcp' and port.state == 'open'
end

action = function (host, port)
	local timeout_ms = stdnse.get_script_args('timeout')
	
	if timeout_ms ~= nil then
		timeout_ms = stdnse.parse_timespec(timeout_ms) * 1000
	else
		timeout_ms = 500
	end

    local socket = nmap.new_socket()
	local try = nmap.new_try(function() socket:close() return end)
	
	socket:set_timeout(timeout_ms)	
	try(socket:connect(host.ip, port.number))
	
	local request = string.char(0x00)
	request = request .. string.char(0x47)
	request = request .. (write_varint(#host.ip) .. host.ip)
	request = request .. string.pack('>HB', port.number, 0x01)
	request = write_varint(#request) .. request
	request = request .. string.pack('>BB', 0x01, 0x00)
	
	try(socket:send(request))
	
	--at least 11 bytes guaranteed -> length varint (5) + id (1) + json_length varint (5)--
	--ensures we get all needed bytes, even if there is extra data--
	local data = try_read_n(socket, 11)
	
	if data == nil then
		socket:close()
		return
	end
		
	local size_of_packet = read_varint(data)
	data = data:sub(size_of_packet + 2) --id (1) skipped--
	
	local size_of_json_len, json_len = read_varint(data)
	data = data:sub(size_of_json_len + 1)
	
	local json_raw = data
	while json_len - #json_raw > 0 do
		local _, json_data = socket:receive()
		json_raw = json_raw .. json_data
		json_len = json_len - #json_data
	end
	
	local status, response = json.parse(json_raw)
	socket:close()
	
	if not status then
		return
	end
	
	--either invalid or something unexpected happened (disconnected, for example)--
	if response['players'] == nil or response['version'] == nil then
		return string.format("%s:%d ?", host.ip, port.number)
	else
		return string.format("%s:%d (%d/%d) [%s]", 
							host.ip, port.number, 
							response['players']['online'], response['players']['max'],
							response['version']['name'])
	end
end

function write_varint(value)
	local buf = ''
	repeat
		local temp = value & 0x7F
        value = value >> 7
        if value ~= 0 then
            temp = temp | 0x80
		end
		buf = buf .. string.char(temp)
	until value == 0
	return buf
end

function read_varint(data)
	local num_read = 0
    local result = 0
    repeat
        local byte_read = string.byte(data:sub(num_read + 1, num_read + 1))
        result = result | ((byte_read & 0x7F) << (7 * num_read))
		
        num_read = num_read + 1
        if num_read > 5 then
            return nil
		end
    until ((byte_read & 0x80) == 0)
    return num_read, result
end

function try_read_n(socket, n)
	local status, data = socket:receive_bytes(n)
	if not status then
		socket:close()
		return nil
	end	
	return data
end