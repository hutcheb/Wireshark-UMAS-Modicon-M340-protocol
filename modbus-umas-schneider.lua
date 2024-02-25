--[[
    Wireshark dissector for UMAS protocol used in Schneider Electric Modicon PLC
    Made by biero-el-corridor
    Modified by Yanis Wang
--]]

-- Mapping of function code to name
-- Source: http://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html
local function_code_to_name = {
    [1] = "0x01 - INIT_COMM: Initialize UMAS communication",
    [2] = "0x02 - READ_ID: Read PLC ID",
    [3] = "0x03 - READ_PROJECT_INFO: Read project information",
    [4] = "0x04 - READ_PLC_INFO: Read internal PLC information",
    [6] = "0x06 - READ_CARD_INFO: Read internal SD card information",
    [10] = "0x0A - REPEAT: Send back data sent to the PLC (used for synchronization)",
    [16] = "0x10 - TAKE_PLC_RESERVATION: Assign an owner to the PLC",
    [17] = "0x11 - RELEASE_PLC_RESERVATION: Release reservation of the PLC",
    [18] = "0x12 - KEEP_ALIVE: Keep alive message",
    [32] = "0x20 - READ_MEMORY_BLOCK: Read a memory block of the PLC",
    [34] = "0x22 - READ_VARIABLES: Read system bits, system words and strategy variables",
    [35] = "0x23 - WRITE_VARIABLES: Write system bits, system words and strategy variables",
    [36] = "0x24 - READ_COILS_REGISTERS: Read coils and holding registers",
    [37] = "0x25 - WRITE_COILS_REGISTERS: Write coils and holding registers",
    [38] = "0x26 - READ DATA DICTIONARY: Read information about the data dictionary",
    [48] = "0x30 - INITIALIZE_UPLOAD: Initialize strategy upload (from engineering station to PLC)",
    [49] = "0x31 - UPLOAD_BLOCK: Upload a strategy block to the PLC (from engineering station to PLC)",
    [50] = "0x32 - END_STRATEGY_UPLOAD: Finish strategy upload (from engineering station to PLC)",
    [51] = "0x33 - INITIALIZE_DOWNLOAD: Initialize strategy download (from PLC to engineering station)",
    [52] = "0x34 - DOWNLOAD_BLOCK: Download a strategy block (from PLC to engineering station)",
    [53] = "0x35 - END_STRATEGY_DOWNLOAD: Finish strategy download (from PLC to engineering station)",
    [57] = "0x39 - READ_ETH_MASTER_DATA: Read Ethernet master data",
    [58] = "0x40 - START_PLC: Start the PLC",
    [59] = "0x41 - STOP_PLC: Stop the PLC",
    [80] = "0x50 - MONITOR_PLC: Monitor variables, systems bits and words",
    [88] = "0x58 - CHECK_PLC: Check PLC connection status",
    [112] = "0x70 - READ_IO_OBJECT: Read IO object",
    [113] = "0x71 - WRITE_IO_OBJECT: Write IO object",
    [115] = "0x73 - GET_STATUS_MODULE: Get module status",
    [254] = "0xfe - Response (Success)",
    [253] = "0xfd - Response (Error)"
}

--- Map function code to name
-- @param code UMAS function code
local function get_umas_function_name(code)
    local name = function_code_to_name[code]

    if name ~= nil then
        return name
    else
        return "Unknown"
    end
end

-- Modbus
local p_modbus = Proto("mbumas", "Modbus (UMAS)")

local f_trans_id = ProtoField.uint16("mbumas.trans_id", "Transaction Identifier", base.DEC)
local f_proto_id = ProtoField.uint16("mbumas.proto_id", "Protocol Identifier", base.DEC)
local f_length = ProtoField.uint16("mbumas.length", "Length", base.DEC)
local f_unit_id = ProtoField.uint8("mbumas.unit_id", "Unit Identifier", base.DEC)
local f_func_code = ProtoField.uint8("mbumas.func_code", "Function Code", base.DEC)

p_modbus.fields = { f_trans_id, f_proto_id, f_length, f_unit_id, f_func_code }

-- UMAS
local p_umas = Proto("umas", "UMAS")

local f_session_key = ProtoField.uint8("umas.session", "Session Key", base.HEX)
local f_umas_func_code = ProtoField.uint8("umas.func_code", "Function Code", base.DEC)
local f_umas_data = ProtoField.string("umas.data", "Data", base.ASCII)

p_umas.fields = { f_session_key, f_umas_func_code, f_umas_data }

-- Original Modbus dissector
local modbus_dis = Dissector.get("mbtcp")

--- UMAS packet dissector
function p_umas.dissector(buf, pkt, tree)
    -- Get packet size
    local length = buf:len()

    -- Check packet size
    if length < 10 then
        modbus_dis:call(buf, pkt, tree)
        return
    end

    local func_code = buf(7, 1)

    -- Check function code
    if buf(7, 1):uint() ~= 90 then
        modbus_dis:call(buf, pkt, tree)
        return
    end

    -- Modbus subtree
    local t_modbus = tree:add(p_modbus, buf(), "Modbus")
    t_modbus:add(f_trans_id, buf(0, 2))
    t_modbus:add(f_proto_id, buf(2, 2))
    t_modbus:add(f_length, buf(4, 2))
    t_modbus:add(f_unit_id, buf(6, 1))
    t_modbus:add(f_func_code, func_code)

    -- UMAS subtree
    local umas_func_code = buf(9, 1)
    local umas_func_name = get_umas_function_name(umas_func_code:uint())
    local umas_data = buf(10):bytes():tohex()

    local t_umas = tree:add(p_umas, buf(8), "UMAS")
    t_umas:add(f_session_key, buf(8, 1))
    t_umas:add(f_umas_func_code, umas_func_code):append_text(" (" .. umas_func_name .. ")")
    t_umas:add(f_umas_data, umas_data)

    -- Set protocol and info in the packet list
    pkt.cols.protocol = "UMAS"
    pkt.cols.info = umas_func_name
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(502, p_umas)