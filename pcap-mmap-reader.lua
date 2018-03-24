-- MIT License
-- 
-- Copyright (c) 2018 Alexander Nasonov
-- 
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
-- 
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
-- 
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

local syscall = require "syscall"
local ffi = require "ffi"

local pagesize = syscall.getpagesize()
local mapsize = pagesize * 2 -- Map at least 2 pages.

ffi.cdef[[
	struct global_header {
		uint32_t magic;
		uint16_t major;
		uint16_t minor;
		int32_t  thiszone;
		uint32_t sigfigs;
		uint32_t snaplen;
		uint32_t network;
	};
]]

local global_header_size = ffi.sizeof "struct global_header"

ffi.cdef[[
	struct packet_header {
		uint32_t ts_sec;
		uint32_t ts_sub;
		uint32_t snaplen;
		uint32_t pktlen;
	};
]]

local packet_header_size = ffi.sizeof "struct packet_header"
local max_snaplen = bit.rshift(mapsize, 1) - packet_header_size

-- Object's members are stored in an array.
local _addr        = 1
local _fd          = 2
local _off         = 3
local _fileoff     = 4
local _filesize    = 5
local _prevsize    = 6
local _interrupted = 7

local function mapfrom(fd, fileoff)
	local addr, err = syscall.mmap(nil,
	    mapsize, "read", "file", fd, fileoff)
	if not addr then return nil, tostring(err), err end
	return ffi.cast("const uint8_t *", addr)
end

local function unmap(addr)
	assert(syscall.munmap(ffi.cast("void *", addr), mapsize))
end

local function stat(fd, minsize)
	local st, err = syscall.fstat(fd)
	if not st then return nil, tostring(err) end
	if st.size < minsize then
		return nil, "File is too short", st.size
	end
	return st
end

local function close(obj)
	local addr = obj[_addr]
	if addr then
		obj[_addr] = nil
		unmap(addr)
	end

	local fd = obj[_fd]
	if fd then
		obj[_fd] = nil
		fd:close()
	end
end

local function next_packet(obj)
	local off = obj[_off]
	local fileoff = obj[_fileoff]
	local filesize = obj[_filesize]
	local hdroff = fileoff + off

	if not obj[_addr] then
		local fd = obj[_fd]
		if filesize == 0 then
			local minsize = hdroff + packet_header_size
			local st, err, smallsz = stat(fd, minsize)
			if smallsz and smallsz < obj[_prevsize] then
				obj[_interrupted] = true
			end
			if not st then return nil, err end
			filesize = st.size
			hdroff = fileoff + off
			obj[_filesize] = filesize
			obj[_prevsize] = filesize
		end
		local addr, err = mapfrom(fd, fileoff)
		if not addr then return nil, err end
		obj[_addr] = addr
	end

	if hdroff == filesize then
		return nil, "EOF"
	elseif hdroff + packet_header_size > filesize then
		return nil, "File is truncated"
	end

	local half = bit.rshift(mapsize, 1)
	if off >= half then
		local addr, err = obj[_addr]
		off = off - half
		fileoff = fileoff + half
		obj[_off] = off
		obj[_fileoff] = fileoff
		obj[_addr] = nil
		unmap(addr)
		addr, err = mapfrom(obj[_fd], fileoff)
		if not addr then return nil, err end
		obj[_addr] = addr
	end

	local hdraddr = obj[_addr] + off
	local hdr = ffi.cast("struct packet_header *", hdraddr)
	local snaplen = hdr.snaplen

	if snaplen > max_snaplen then
		obj[_interrupted] = true
		return nil, "Packet is too big"
	elseif snaplen > hdr.pktlen then -- XXX or hdr.ts_sub > 999999 then
		obj[_interrupted] = true
		return nil, "Packet is corrupted"
	end

	off = off + packet_header_size + snaplen
	if fileoff + off > filesize then return nil, "File is truncated" end

	obj[_off] = off
	return hdraddr + packet_header_size, snaplen, hdr.ts_sec, hdr.ts_sub
end

local function refresh(obj)
	local addr = obj[_addr]
	if addr then
		obj[_addr] = nil
		unmap(addr)
	end
	obj[_filesize] = 0 -- To call stat() inside the next_packet() call.
end

local function packets(obj)
	refresh(obj)
	return next_packet, obj
end

local function interrupted(obj)
	return obj[_interrupted]
end

local mt_index = {
	close   = close,
	refresh = refresh,
	packets = packets,
	next_packet = next_packet,
	interrupted = interrupted
}

local _M = {}

function _M.open(filename)
	local fd, err = syscall.open(filename, "rdonly")
	if not fd then return nil, tostring(err) end

	-- Check that fd can be mmaped.
	local addr, err = mapfrom(fd, 0)
	if not addr then return nil, err end

	-- This syscall can go before mmap but mmap returns a nice
	-- "Invalid argument" error instead of "File is too short"
	-- for files like /dev/null.
	local st, err = stat(fd, global_header_size)
	if not st then return nil, err end

	-- XXX Check magic, major and minor versions.

	local obj = { addr, fd, global_header_size, 0, st.size, st.size, false }
	return setmetatable(obj, { __gc = close, __index = mt_index })
end

return _M
