local ffi = require 'ffi'
local base64 = require("gamesense/base64")

local tab, container = "Rage", "Other"

local ffi_hw_id = ffi.typeof([[
    struct {
        char __m_pDriverName[512];
        unsigned int __m_VendorID;
        unsigned int __m_DeviceID;
        unsigned int __m_SubSysID;
        unsigned int __m_Revision;
        int __m_nDXSupportLevel;
        int __m_nMinDXSupportLevel;
        int __m_nMaxDXSupportLevel;
        unsigned int __m_nDriverVersionHigh;
        unsigned int __m_nDriverVersionLow;
        int64_t pad_0;
    }
]])

local info_adapter_hw_id = { __index = {} }

local cur_adapter_aye = vtable_bind("materialsystem.dll", "VMaterialSystem080", 25, "int(__thiscall*)(void*)")
local adapt_info_aye = vtable_bind("materialsystem.dll", "VMaterialSystem080", 26, "void(__thiscall*)(void*, int, $*)", ffi_hw_id)

function func_adapt()
    return cur_adapter_aye()
end

local dickback = {
    drivername = function(self) return ffi.string(self.__m_pDriverName) end,
    vendorid = function(self) return tostring(self.__m_VendorID) end,
    deviceid = function(self) return tostring(self.__m_DeviceID) end,
    subsysid = function(self) return tostring(self.__m_SubSysID) end,
    revision = function(self) return tostring(self.__m_Revision) end
}

function info_adapter_hw_id:__index(index)
    local dickback_fn = dickback[index]
    if not dickback_fn then return nil end
    return dickback_fn(self)
end

ffi.metatype(ffi_hw_id, info_adapter_hw_id)

function func_info(adapter)
    local info = ffi_hw_id()
    adapt_info_aye(adapter, info)

    return info
end

local adapter_cur_xui = func_adapt()
local info_adapted_xui = func_info(adapter_cur_xui)

local total_hwid = math.floor(((info_adapted_xui.vendorid * info_adapted_xui.deviceid) + info_adapted_xui.subsysid + info_adapted_xui.revision)/2)

------блядство
local assert, pcall, xpcall, error, setmetatable, tostring, tonumber, type, pairs, ipairs = assert, pcall, xpcall, error, setmetatable, tostring, tonumber, type, pairs, ipairs
local client_log, client_delay_call, ui_get, string_format = client.log, client.delay_call, ui.get, string.format
local typeof, sizeof, cast, cdef, ffi_string, ffi_gc = ffi.typeof, ffi.sizeof, ffi.cast, ffi.cdef, ffi.string, ffi.gc
local string_lower, string_len, string_find = string.lower, string.len, string.find
local base64_encode = base64.encode

---
local libraries = {}
function libraries.lool_crack()
    local register_call_result, register_callback, steam_client_context
    do
        if not pcall(ffi.sizeof, "SteamAPICall_t") then
            cdef([[
                typedef uint64_t SteamAPICall_t;

                struct SteamAPI_callback_base_vtbl {
                    void(__thiscall *run1)(struct SteamAPI_callback_base *, void *, bool, uint64_t);
                    void(__thiscall *run2)(struct SteamAPI_callback_base *, void *);
                    int(__thiscall *get_size)(struct SteamAPI_callback_base *);
                };

                struct SteamAPI_callback_base {
                    struct SteamAPI_callback_base_vtbl *vtbl;
                    uint8_t flags;
                    int id;
                    uint64_t api_call_handle;
                    struct SteamAPI_callback_base_vtbl vtbl_storage[1];
                };
            ]])
        end

        local ESteamAPICallFailure = {
            [-1] = "No failure",
            [0]  = "Steam gone",
            [1]  = "Network failure",
            [2]  = "Invalid handle",
            [3]  = "Mismatched callback"
        }

        local SteamAPI_RegisterCallResult, SteamAPI_UnregisterCallResult
        local SteamAPI_RegisterCallback, SteamAPI_UnregisterCallback
        local GetAPICallFailureReason

        local callback_base        = typeof("struct SteamAPI_callback_base")
        local sizeof_callback_base = sizeof(callback_base)
        local callback_base_array  = typeof("struct SteamAPI_callback_base[1]")
        local callback_base_ptr    = typeof("struct SteamAPI_callback_base*")
        local uintptr_t            = typeof("uintptr_t")
        local api_call_handlers    = {}
        local pending_call_results = {}
        local registered_callbacks = {}

        local function pointer_key(p)
            return tostring(tonumber(cast(uintptr_t, p)))
        end

        local function callback_base_run_common(self, param, io_failure)
            if io_failure then
                io_failure = ESteamAPICallFailure[GetAPICallFailureReason(self.api_call_handle)] or "Unknown error"
            end

            -- prevent SteamAPI_UnregisterCallResult from being called for this callresult
            self.api_call_handle = 0

            xpcall(function()
                local key = pointer_key(self)
                local handler = api_call_handlers[key]
                if handler ~= nil then
                    xpcall(handler, client.error_log, param, io_failure)
                end

                if pending_call_results[key] ~= nil then
                    api_call_handlers[key] = nil
                    pending_call_results[key] = nil
                end
            end, client.error_log)
        end

        local function callback_base_run1(self, param, io_failure, api_call_handle)
            if api_call_handle == self.api_call_handle then
                callback_base_run_common(self, param, io_failure)
            end
        end

        local function callback_base_run2(self, param)
            callback_base_run_common(self, param, false)
        end

        local function callback_base_get_size(self)
            return sizeof_callback_base
        end

        local function call_result_cancel(self)
            if self.api_call_handle ~= 0 then
                SteamAPI_UnregisterCallResult(self, self.api_call_handle)
                self.api_call_handle = 0

                local key = pointer_key(self)
                api_call_handlers[key] = nil
                pending_call_results[key] = nil
            end
        end

        pcall(ffi.metatype, callback_base, {
            __gc = call_result_cancel,
            __index = {
                cancel = call_result_cancel
            }
        })

        local callback_base_run1_ct = cast("void(__thiscall *)(struct SteamAPI_callback_base *, void *, bool, uint64_t)", callback_base_run1)
        local callback_base_run2_ct = cast("void(__thiscall *)(struct SteamAPI_callback_base *, void *)", callback_base_run2)
        local callback_base_get_size_ct = cast("int(__thiscall *)(struct SteamAPI_callback_base *)", callback_base_get_size)

        function register_call_result(api_call_handle, handler, id)
            assert(api_call_handle ~= 0)
            local instance_storage = callback_base_array()
            local instance = cast(callback_base_ptr, instance_storage)

            instance.vtbl_storage[0].run1 = callback_base_run1_ct
            instance.vtbl_storage[0].run2 = callback_base_run2_ct
            instance.vtbl_storage[0].get_size = callback_base_get_size_ct
            instance.vtbl = instance.vtbl_storage
            instance.api_call_handle = api_call_handle
            instance.id = id

            local key = pointer_key(instance)
            api_call_handlers[key] = handler
            pending_call_results[key] = instance_storage

            SteamAPI_RegisterCallResult(instance, api_call_handle)

            return instance
        end

        function register_callback(id, handler)
            assert(registered_callbacks[id] == nil)

            local instance_storage = callback_base_array()
            local instance = cast(callback_base_ptr, instance_storage)

            instance.vtbl_storage[0].run1 = callback_base_run1_ct
            instance.vtbl_storage[0].run2 = callback_base_run2_ct
            instance.vtbl_storage[0].get_size = callback_base_get_size_ct
            instance.vtbl = instance.vtbl_storage
            instance.api_call_handle = 0
            instance.id = id

            local key = pointer_key(instance)
            api_call_handlers[key] = handler
            registered_callbacks[id] = instance_storage

            SteamAPI_RegisterCallback(instance, id)
        end

        local function find_sig(mdlname, pattern, typename, offset, deref_count)
            local raw_match = client.find_signature(mdlname, pattern) or error("signature not found", 2)
            local match = cast("uintptr_t", raw_match)

            if offset ~= nil and offset ~= 0 then
                match = match + offset
            end

            if deref_count ~= nil then
                for i = 1, deref_count do
                    match = cast("uintptr_t*", match)[0]
                    if match == nil then
                        return error("signature not found")
                    end
                end
            end

            return cast(typename, match)
        end

        local function vtable_entry(instance, index, type)
            return cast(type, (cast("void***", instance)[0])[index])
        end

        SteamAPI_RegisterCallResult = find_sig("steam_api.dll", "\x55\x8B\xEC\x83\x3D\xCC\xCC\xCC\xCC\xCC\x7E\x0D\x68\xCC\xCC\xCC\xCC\xFF\x15\xCC\xCC\xCC\xCC\x5D\xC3\xFF\x75\x10", "void(__cdecl*)(struct SteamAPI_callback_base *, uint64_t)")
        SteamAPI_UnregisterCallResult = find_sig("steam_api.dll", "\x55\x8B\xEC\xFF\x75\x10\xFF\x75\x0C", "void(__cdecl*)(struct SteamAPI_callback_base *, uint64_t)")

        SteamAPI_RegisterCallback = find_sig("steam_api.dll", "\x55\x8B\xEC\x83\x3D\xCC\xCC\xCC\xCC\xCC\x7E\x0D\x68\xCC\xCC\xCC\xCC\xFF\x15\xCC\xCC\xCC\xCC\x5D\xC3\xC7\x05", "void(__cdecl*)(struct SteamAPI_callback_base *, int)")

        steam_client_context = find_sig(
            "client_panorama.dll",
            "\xB9\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x83\x3D\xCC\xCC\xCC\xCC\xCC\x0F\x84",
            "uintptr_t",
            1, 1
        )

        -- initialize isteamutils and native_GetAPICallFailureReason
        local steamutils = cast("uintptr_t*", steam_client_context)[3]
        local native_GetAPICallFailureReason = vtable_entry(steamutils, 12, "int(__thiscall*)(void*, SteamAPICall_t)")

        function GetAPICallFailureReason(handle)
            return native_GetAPICallFailureReason(steamutils, handle)
        end

        client.set_event_callback("shutdown", function()
            for key, value in pairs(pending_call_results) do
                local instance = cast(callback_base_ptr, value)
                call_result_cancel(instance)
            end

            for key, value in pairs(registered_callbacks) do
                local instance = cast(callback_base_ptr, value)
            end
        end)
    end

    --
    -- ffi definitions
    --

    if not pcall(sizeof, "http_HTTPRequestHandle") then
        cdef([[
            typedef uint32_t http_HTTPRequestHandle;
            typedef uint32_t http_HTTPCookieContainerHandle;

            enum http_EHTTPMethod {
                k_EHTTPMethodInvalid,
                k_EHTTPMethodGET,
                k_EHTTPMethodHEAD,
                k_EHTTPMethodPOST,
                k_EHTTPMethodPUT,
                k_EHTTPMethodDELETE,
                k_EHTTPMethodOPTIONS,
                k_EHTTPMethodPATCH,
            };

            struct http_ISteamHTTPVtbl {
                http_HTTPRequestHandle(__thiscall *CreateHTTPRequest)(uintptr_t, enum http_EHTTPMethod, const char *);
                bool(__thiscall *SetHTTPRequestContextValue)(uintptr_t, http_HTTPRequestHandle, uint64_t);
                bool(__thiscall *SetHTTPRequestNetworkActivityTimeout)(uintptr_t, http_HTTPRequestHandle, uint32_t);
                bool(__thiscall *SetHTTPRequestHeaderValue)(uintptr_t, http_HTTPRequestHandle, const char *, const char *);
                bool(__thiscall *SetHTTPRequestGetOrPostParameter)(uintptr_t, http_HTTPRequestHandle, const char *, const char *);
                bool(__thiscall *SendHTTPRequest)(uintptr_t, http_HTTPRequestHandle, SteamAPICall_t *);
                bool(__thiscall *SendHTTPRequestAndStreamResponse)(uintptr_t, http_HTTPRequestHandle, SteamAPICall_t *);
                bool(__thiscall *DeferHTTPRequest)(uintptr_t, http_HTTPRequestHandle);
                bool(__thiscall *PrioritizeHTTPRequest)(uintptr_t, http_HTTPRequestHandle);
                bool(__thiscall *GetHTTPResponseHeaderSize)(uintptr_t, http_HTTPRequestHandle, const char *, uint32_t *);
                bool(__thiscall *GetHTTPResponseHeaderValue)(uintptr_t, http_HTTPRequestHandle, const char *, uint8_t *, uint32_t);
                bool(__thiscall *GetHTTPResponseBodySize)(uintptr_t, http_HTTPRequestHandle, uint32_t *);
                bool(__thiscall *GetHTTPResponseBodyData)(uintptr_t, http_HTTPRequestHandle, uint8_t *, uint32_t);
                bool(__thiscall *GetHTTPStreamingResponseBodyData)(uintptr_t, http_HTTPRequestHandle, uint32_t, uint8_t *, uint32_t);
                bool(__thiscall *ReleaseHTTPRequest)(uintptr_t, http_HTTPRequestHandle);
                bool(__thiscall *GetHTTPDownloadProgressPct)(uintptr_t, http_HTTPRequestHandle, float *);
                bool(__thiscall *SetHTTPRequestRawPostBody)(uintptr_t, http_HTTPRequestHandle, const char *, uint8_t *, uint32_t);
                http_HTTPCookieContainerHandle(__thiscall *CreateCookieContainer)(uintptr_t, bool);
                bool(__thiscall *ReleaseCookieContainer)(uintptr_t, http_HTTPCookieContainerHandle);
                bool(__thiscall *SetCookie)(uintptr_t, http_HTTPCookieContainerHandle, const char *, const char *, const char *);
                bool(__thiscall *SetHTTPRequestCookieContainer)(uintptr_t, http_HTTPRequestHandle, http_HTTPCookieContainerHandle);
                bool(__thiscall *SetHTTPRequestUserAgentInfo)(uintptr_t, http_HTTPRequestHandle, const char *);
                bool(__thiscall *SetHTTPRequestRequiresVerifiedCertificate)(uintptr_t, http_HTTPRequestHandle, bool);
                bool(__thiscall *SetHTTPRequestAbsoluteTimeoutMS)(uintptr_t, http_HTTPRequestHandle, uint32_t);
                bool(__thiscall *GetHTTPRequestWasTimedOut)(uintptr_t, http_HTTPRequestHandle, bool *pbWasTimedOut);
            };
        ]])
    end

    --
    -- constants
    --

    local method_name_to_enum = {
        get = ffi.C.k_EHTTPMethodGET,
        head = ffi.C.k_EHTTPMethodHEAD,
        post = ffi.C.k_EHTTPMethodPOST,
        put = ffi.C.k_EHTTPMethodPUT,
        delete = ffi.C.k_EHTTPMethodDELETE,
        options = ffi.C.k_EHTTPMethodOPTIONS,
        patch = ffi.C.k_EHTTPMethodPATCH,
    }

    local status_code_to_message = {
        [100]="Continue",[101]="Switching Protocols",[102]="Processing",[200]="OK",[201]="Created",[202]="Accepted",[203]="Non-Authoritative Information",[204]="No Content",[205]="Reset Content",[206]="Partial Content",[207]="Multi-Status",
        [208]="Already Reported",[250]="Low on Storage Space",[226]="IM Used",[300]="Multiple Choices",[301]="Moved Permanently",[302]="Found",[303]="See Other",[304]="Not Modified",[305]="Use Proxy",[306]="Switch Proxy",
        [307]="Temporary Redirect",[308]="Permanent Redirect",[400]="Bad Request",[401]="Unauthorized",[402]="Payment Required",[403]="Forbidden",[404]="Not Found",[405]="Method Not Allowed",[406]="Not Acceptable",[407]="Proxy Authentication Required",
        [408]="Request Timeout",[409]="Conflict",[410]="Gone",[411]="Length Required",[412]="Precondition Failed",[413]="Request Entity Too Large",[414]="Request-URI Too Long",[415]="Unsupported Media Type",[416]="Requested Range Not Satisfiable",
        [417]="Expectation Failed",[418]="I'm a teapot",[420]="Enhance Your Calm",[422]="Unprocessable Entity",[423]="Locked",[424]="Failed Dependency",[424]="Method Failure",[425]="Unordered Collection",[426]="Upgrade Required",[428]="Precondition Required",
        [429]="Too Many Requests",[431]="Request Header Fields Too Large",[444]="No Response",[449]="Retry With",[450]="Blocked by Windows Parental Controls",[451]="Parameter Not Understood",[451]="Unavailable For Legal Reasons",[451]="Redirect",
        [452]="Conference Not Found",[453]="Not Enough Bandwidth",[454]="Session Not Found",[455]="Method Not Valid in This State",[456]="Header Field Not Valid for Resource",[457]="Invalid Range",[458]="Parameter Is Read-Only",[459]="Aggregate Operation Not Allowed",
        [460]="Only Aggregate Operation Allowed",[461]="Unsupported Transport",[462]="Destination Unreachable",[494]="Request Header Too Large",[495]="Cert Error",[496]="No Cert",[497]="HTTP to HTTPS",[499]="Client Closed Request",[500]="Internal Server Error",
        [501]="Not Implemented",[502]="Bad Gateway",[503]="Service Unavailable",[504]="Gateway Timeout",[505]="HTTP Version Not Supported",[506]="Variant Also Negotiates",[507]="Insufficient Storage",[508]="Loop Detected",[509]="Bandwidth Limit Exceeded",
        [510]="Not Extended",[511]="Network Authentication Required",[551]="Option not supported",[598]="Network read timeout error",[599]="Network connect timeout error"
    }

    local single_allowed_keys = {"params", "body", "json"}

    -- https://github.com/AlexApps99/SteamworksSDK/blob/fe3524b655eb9df6ae4d24e0ffb365357a370c7f/public/steam/isteamhttp.h#L162-L214
    local CALLBACK_HTTPRequestCompleted = 2101
    local CALLBACK_HTTPRequestHeadersReceived = 2102
    local CALLBACK_HTTPRequestDataReceived = 2103

    --
    -- private functions
    --

    local function find_isteamhttp()
        local steamhttp = cast("uintptr_t*", steam_client_context)[12]

        if steamhttp == 0 or steamhttp == nil then
            return error("find_isteamhttp failed")
        end

        local vmt = cast("struct http_ISteamHTTPVtbl**", steamhttp)[0]
        if vmt == 0 or vmt == nil then
            return error("find_isteamhttp failed")
        end

        return steamhttp, vmt
    end

    local function func_bind(func, arg)
        return function(...)
            return func(arg, ...)
        end
    end

    --
    -- steamhttp ffi stuff
    --

    local HTTPRequestCompleted_t_ptr = typeof([[
    struct {
        http_HTTPRequestHandle m_hRequest;
        uint64_t m_ulContextValue;
        bool m_bRequestSuccessful;
        int m_eStatusCode;
        uint32_t m_unBodySize;
    } *
    ]])

    local HTTPRequestHeadersReceived_t_ptr = typeof([[
    struct {
        http_HTTPRequestHandle m_hRequest;
        uint64_t m_ulContextValue;
    } *
    ]])

    local HTTPRequestDataReceived_t_ptr = typeof([[
    struct {
        http_HTTPRequestHandle m_hRequest;
        uint64_t m_ulContextValue;
        uint32_t m_cOffset;
        uint32_t m_cBytesReceived;
    } *
    ]])

    local CookieContainerHandle_t = typeof([[
    struct {
        http_HTTPCookieContainerHandle m_hCookieContainer;
    }
    ]])

    local SteamAPICall_t_arr = typeof("SteamAPICall_t[1]")
    local char_ptr = typeof("const char[?]")
    local unit8_ptr = typeof("uint8_t[?]")
    local uint_ptr = typeof("unsigned int[?]")
    local bool_ptr = typeof("bool[1]")
    local float_ptr = typeof("float[1]")

    --
    -- get isteamhttp interface
    --

    local steam_http, steam_http_vtable = find_isteamhttp()

    --
    -- isteamhttp functions
    --

    local native_CreateHTTPRequest = func_bind(steam_http_vtable.CreateHTTPRequest, steam_http)
    local native_SetHTTPRequestContextValue = func_bind(steam_http_vtable.SetHTTPRequestContextValue, steam_http)
    local native_SetHTTPRequestNetworkActivityTimeout = func_bind(steam_http_vtable.SetHTTPRequestNetworkActivityTimeout, steam_http)
    local native_SetHTTPRequestHeaderValue = func_bind(steam_http_vtable.SetHTTPRequestHeaderValue, steam_http)
    local native_SetHTTPRequestGetOrPostParameter = func_bind(steam_http_vtable.SetHTTPRequestGetOrPostParameter, steam_http)
    local native_SendHTTPRequest = func_bind(steam_http_vtable.SendHTTPRequest, steam_http)
    local native_SendHTTPRequestAndStreamResponse = func_bind(steam_http_vtable.SendHTTPRequestAndStreamResponse, steam_http)
    local native_DeferHTTPRequest = func_bind(steam_http_vtable.DeferHTTPRequest, steam_http)
    local native_PrioritizeHTTPRequest = func_bind(steam_http_vtable.PrioritizeHTTPRequest, steam_http)
    local native_GetHTTPResponseHeaderSize = func_bind(steam_http_vtable.GetHTTPResponseHeaderSize, steam_http)
    local native_GetHTTPResponseHeaderValue = func_bind(steam_http_vtable.GetHTTPResponseHeaderValue, steam_http)
    local native_GetHTTPResponseBodySize = func_bind(steam_http_vtable.GetHTTPResponseBodySize, steam_http)
    local native_GetHTTPResponseBodyData = func_bind(steam_http_vtable.GetHTTPResponseBodyData, steam_http)
    local native_GetHTTPStreamingResponseBodyData = func_bind(steam_http_vtable.GetHTTPStreamingResponseBodyData, steam_http)
    local native_ReleaseHTTPRequest = func_bind(steam_http_vtable.ReleaseHTTPRequest, steam_http)
    local native_GetHTTPDownloadProgressPct = func_bind(steam_http_vtable.GetHTTPDownloadProgressPct, steam_http)
    local native_SetHTTPRequestRawPostBody = func_bind(steam_http_vtable.SetHTTPRequestRawPostBody, steam_http)
    local native_CreateCookieContainer = func_bind(steam_http_vtable.CreateCookieContainer, steam_http)
    local native_ReleaseCookieContainer = func_bind(steam_http_vtable.ReleaseCookieContainer, steam_http)
    local native_SetCookie = func_bind(steam_http_vtable.SetCookie, steam_http)
    local native_SetHTTPRequestCookieContainer = func_bind(steam_http_vtable.SetHTTPRequestCookieContainer, steam_http)
    local native_SetHTTPRequestUserAgentInfo = func_bind(steam_http_vtable.SetHTTPRequestUserAgentInfo, steam_http)
    local native_SetHTTPRequestRequiresVerifiedCertificate = func_bind(steam_http_vtable.SetHTTPRequestRequiresVerifiedCertificate, steam_http)
    local native_SetHTTPRequestAbsoluteTimeoutMS = func_bind(steam_http_vtable.SetHTTPRequestAbsoluteTimeoutMS, steam_http)
    local native_GetHTTPRequestWasTimedOut = func_bind(steam_http_vtable.GetHTTPRequestWasTimedOut, steam_http)

    --
    -- private variables
    --

    local completed_callbacks, is_in_callback = {}, false
    local headers_received_callback_registered, headers_received_callbacks = false, {}
    local data_received_callback_registered, data_received_callbacks = false, {}

    -- weak table containing headers tbl -> cookie container handle
    local cookie_containers = setmetatable({}, {__mode = "k"})

    -- weak table containing headers tbl -> request handle
    local headers_request_handles, request_handles_headers = setmetatable({}, {__mode = "k"}), setmetatable({}, {__mode = "v"})

    -- table containing in-flight http requests
    local pending_requests = {}

    --
    -- response headers metatable
    --

    local response_headers_mt = {
        __index = function(req_key, name)
            local req = headers_request_handles[req_key]
            if req == nil then
                return
            end

            name = tostring(name)
            if req.m_hRequest ~= 0 then
                local header_size = uint_ptr(1)
                if native_GetHTTPResponseHeaderSize(req.m_hRequest, name, header_size) then
                    if header_size ~= nil then
                        header_size = header_size[0]
                        if header_size < 0 then
                            return
                        end

                        local buffer = unit8_ptr(header_size)
                        if native_GetHTTPResponseHeaderValue(req.m_hRequest, name, buffer, header_size) then
                            req_key[name] = ffi_string(buffer, header_size-1)
                            return req_key[name]
                        end
                    end
                end
            end
        end,
        __metatable = false
    }

    --
    -- cookie container metatable
    --

    local cookie_container_mt = {
        __index = {
            set_cookie = function(handle_key, host, url, name, value)
                local handle = cookie_containers[handle_key]
                if handle == nil or handle.m_hCookieContainer == 0 then
                    return
                end

                native_SetCookie(handle.m_hCookieContainer, host, url, tostring(name) .. "=" .. tostring(value))
            end
        },
        __metatable = false
    }

    --
    -- garbage collection callbaks
    --

    local function cookie_container_gc(handle)
        if handle.m_hCookieContainer ~= 0 then
            native_ReleaseCookieContainer(handle.m_hCookieContainer)
            handle.m_hCookieContainer = 0
        end
    end

    local function http_request_gc(req)
        if req.m_hRequest ~= 0 then
            native_ReleaseHTTPRequest(req.m_hRequest)
            req.m_hRequest = 0
        end
    end

    local function http_request_error(req_handle, ...)
        native_ReleaseHTTPRequest(req_handle)
        return error(...)
    end

    local function http_request_callback_common(req, callback, successful, data, ...)
        local headers = request_handles_headers[req.m_hRequest]
        if headers == nil then
            headers = setmetatable({}, response_headers_mt)
            request_handles_headers[req.m_hRequest] = headers
        end
        headers_request_handles[headers] = req
        data.headers = headers

        -- run callback
        is_in_callback = true
        xpcall(callback, client.error_log, successful, data, ...)
        is_in_callback = false
    end

    local function http_request_completed(param, io_failure)
        if param == nil then
            return
        end

        local req = cast(HTTPRequestCompleted_t_ptr, param)

        if req.m_hRequest ~= 0 then
            local callback = completed_callbacks[req.m_hRequest]

            -- if callback ~= nil the request was sent by us
            if callback ~= nil then
                completed_callbacks[req.m_hRequest] = nil
                data_received_callbacks[req.m_hRequest] = nil
                headers_received_callbacks[req.m_hRequest] = nil

                -- callback can be false
                if callback then
                    local successful = io_failure == false and req.m_bRequestSuccessful
                    local status = req.m_eStatusCode

                    local response = {
                        status = status
                    }

                    local body_size = req.m_unBodySize
                    if successful and body_size > 0 then
                        local buffer = unit8_ptr(body_size)
                        if native_GetHTTPResponseBodyData(req.m_hRequest, buffer, body_size) then
                            response.body = ffi_string(buffer, body_size)
                        end
                    elseif not req.m_bRequestSuccessful then
                        local timed_out = bool_ptr()
                        native_GetHTTPRequestWasTimedOut(req.m_hRequest, timed_out)
                        response.timed_out = timed_out ~= nil and timed_out[0] == true
                    end

                    if status > 0 then
                        response.status_message = status_code_to_message[status] or "Unknown status"
                    elseif io_failure then
                        response.status_message = string_format("IO Failure: %s", io_failure)
                    else
                        response.status_message = response.timed_out and "Timed out" or "Unknown error"
                    end

                    -- release http request on garbage collection
                    -- ffi.gc(req, http_request_gc)

                    http_request_callback_common(req, callback, successful, response)
                end

                http_request_gc(req)
            end
        end
    end

    local function http_request_headers_received(param, io_failure)
        if param == nil then
            return
        end

        local req = cast(HTTPRequestHeadersReceived_t_ptr, param)

        if req.m_hRequest ~= 0 then
            local callback = headers_received_callbacks[req.m_hRequest]
            if callback then
                http_request_callback_common(req, callback, io_failure == false, {})
            end
        end
    end

    local function http_request_data_received(param, io_failure)
        if param == nil then
            return
        end

        local req = cast(HTTPRequestDataReceived_t_ptr, param)

        if req.m_hRequest ~= 0 then
            local callback = data_received_callbacks[req.m_hRequest]
            if data_received_callbacks[req.m_hRequest] then
                local data = {}

                local download_percentage_prt = float_ptr()
                if native_GetHTTPDownloadProgressPct(req.m_hRequest, download_percentage_prt) then
                    data.download_progress = tonumber(download_percentage_prt[0])
                end

                local buffer = unit8_ptr(req.m_cBytesReceived)
                if native_GetHTTPStreamingResponseBodyData(req.m_hRequest, req.m_cOffset, buffer, req.m_cBytesReceived) then
                    data.body = ffi_string(buffer, req.m_cBytesReceived)
                end

                http_request_callback_common(req, callback, io_failure == false, data)
            end
        end
    end

    local function http_request_new(method, url, options, callbacks)
        -- support overload: http.request(method, url, callback)
        if type(options) == "function" and callbacks == nil then
            callbacks = options
            options = {}
        end

        options = options or {}

        local method = method_name_to_enum[string_lower(tostring(method))]
        if method == nil then
            return error("invalid HTTP method")
        end

        if type(url) ~= "string" then
            return error("URL has to be a string")
        end

        local completed_callback, headers_received_callback, data_received_callback
        if type(callbacks) == "function" then
            completed_callback = callbacks
        elseif type(callbacks) == "table" then
            completed_callback = callbacks.completed or callbacks.complete
            headers_received_callback = callbacks.headers_received or callbacks.headers
            data_received_callback = callbacks.data_received or callbacks.data

            if completed_callback ~= nil and type(completed_callback) ~= "function" then
                return error("callbacks.completed callback has to be a function")
            elseif headers_received_callback ~= nil and type(headers_received_callback) ~= "function" then
                return error("callbacks.headers_received callback has to be a function")
            elseif data_received_callback ~= nil and type(data_received_callback) ~= "function" then
                return error("callbacks.data_received callback has to be a function")
            end
        else
            return error("callbacks has to be a function or table")
        end

        local req_handle = native_CreateHTTPRequest(method, url)
        if req_handle == 0 then
            return error("Failed to create HTTP request")
        end

        local set_one = false
        for i, key in ipairs(single_allowed_keys) do
            if options[key] ~= nil then
                if set_one then
                    return error("can only set options.params, options.body or options.json")
                else
                    set_one = true
                end
            end
        end

        local json_body
        if options.json ~= nil then
            local success
            success, json_body = pcall(json.stringify, options.json)

            if not success then
                return error("options.json is invalid: " .. json_body)
            end
        end

        -- WARNING:
        -- use http_request_error after this point to properly free the http request

        local network_timeout = options.network_timeout
        if network_timeout == nil then
            network_timeout = 10
        end

        if type(network_timeout) == "number" and network_timeout > 0 then
            if not native_SetHTTPRequestNetworkActivityTimeout(req_handle, network_timeout) then
                return http_request_error(req_handle, "failed to set network_timeout")
            end
        elseif network_timeout ~= nil then
            return http_request_error(req_handle, "options.network_timeout has to be of type number and greater than 0")
        end

        local absolute_timeout = options.absolute_timeout
        if absolute_timeout == nil then
            absolute_timeout = 30
        end

        if type(absolute_timeout) == "number" and absolute_timeout > 0 then
            if not native_SetHTTPRequestAbsoluteTimeoutMS(req_handle, absolute_timeout*1000) then
                return http_request_error(req_handle, "failed to set absolute_timeout")
            end
        elseif absolute_timeout ~= nil then
            return http_request_error(req_handle, "options.absolute_timeout has to be of type number and greater than 0")
        end

        local content_type = json_body ~= nil and "application/json" or "text/plain"
        local authorization_set

        local headers = options.headers
        if type(headers) == "table" then
            for name, value in pairs(headers) do
                name = tostring(name)
                value = tostring(value)

                local name_lower = string_lower(name)

                if name_lower == "content-type" then
                    content_type = value
                elseif name_lower == "authorization" then
                    authorization_set = true
                end

                if not native_SetHTTPRequestHeaderValue(req_handle, name, value) then
                    return http_request_error(req_handle, "failed to set header " .. name)
                end
            end
        elseif headers ~= nil then
            return http_request_error(req_handle, "options.headers has to be of type table")
        end

        local authorization = options.authorization
        if type(authorization) == "table" then
            if authorization_set then
                return http_request_error(req_handle, "Cannot set both options.authorization and the 'Authorization' header.")
            end

            local username, password = authorization[1], authorization[2]
            local header_value = string_format("Basic %s", base64_encode(string_format("%s:%s", tostring(username), tostring(password)), "base64"))

            if not native_SetHTTPRequestHeaderValue(req_handle, "Authorization", header_value) then
                return http_request_error(req_handle, "failed to apply options.authorization")
            end
        elseif authorization ~= nil then
            return http_request_error(req_handle, "options.authorization has to be of type table")
        end

        local body = json_body or options.body
        if type(body) == "string" then
            local len = string_len(body)

            if not native_SetHTTPRequestRawPostBody(req_handle, content_type, cast("unsigned char*", body), len) then
                return http_request_error(req_handle, "failed to set post body")
            end
        elseif body ~= nil then
            return http_request_error(req_handle, "options.body has to be of type string")
        end

        local params = options.params
        if type(params) == "table" then
            for name, value in pairs(params) do
                name = tostring(name)

                if not native_SetHTTPRequestGetOrPostParameter(req_handle, name, tostring(value)) then
                    return http_request_error(req_handle, "failed to set parameter " .. name)
                end
            end
        elseif params ~= nil then
            return http_request_error(req_handle, "options.params has to be of type table")
        end

        local require_ssl = options.require_ssl
        if type(require_ssl) == "boolean" then
            if not native_SetHTTPRequestRequiresVerifiedCertificate(req_handle, require_ssl == true) then
                return http_request_error(req_handle, "failed to set require_ssl")
            end
        elseif require_ssl ~= nil then
            return http_request_error(req_handle, "options.require_ssl has to be of type boolean")
        end

        local user_agent_info = options.user_agent_info
        if type(user_agent_info) == "string" then
            if not native_SetHTTPRequestUserAgentInfo(req_handle, tostring(user_agent_info)) then
                return http_request_error(req_handle, "failed to set user_agent_info")
            end
        elseif user_agent_info ~= nil then
            return http_request_error(req_handle, "options.user_agent_info has to be of type string")
        end

        local cookie_container = options.cookie_container
        if type(cookie_container) == "table" then
            local handle = cookie_containers[cookie_container]

            if handle ~= nil and handle.m_hCookieContainer ~= 0 then
                if not native_SetHTTPRequestCookieContainer(req_handle, handle.m_hCookieContainer) then
                    return http_request_error(req_handle, "failed to set user_agent_info")
                end
            else
                return http_request_error(req_handle, "options.cookie_container has to a valid cookie container")
            end
        elseif cookie_container ~= nil then
            return http_request_error(req_handle, "options.cookie_container has to a valid cookie container")
        end

        local send_func = native_SendHTTPRequest
        local stream_response = options.stream_response
        if type(stream_response) == "boolean" then
            if stream_response then
                send_func = native_SendHTTPRequestAndStreamResponse

                -- at least one callback is required
                if completed_callback == nil and headers_received_callback == nil and data_received_callback == nil then
                    return http_request_error(req_handle, "a 'completed', 'headers_received' or 'data_received' callback is required")
                end
            else
                -- completed callback is required and others cant be used
                if completed_callback == nil then
                    return http_request_error(req_handle, "'completed' callback has to be set for non-streamed requests")
                elseif headers_received_callback ~= nil or data_received_callback ~= nil then
                    return http_request_error(req_handle, "non-streamed requests only support 'completed' callbacks")
                end
            end
        elseif stream_response ~= nil then
            return http_request_error(req_handle, "options.stream_response has to be of type boolean")
        end

        if headers_received_callback ~= nil or data_received_callback ~= nil then
            headers_received_callbacks[req_handle] = headers_received_callback or false
            if headers_received_callback ~= nil then
                if not headers_received_callback_registered then
                    register_callback(CALLBACK_HTTPRequestHeadersReceived, http_request_headers_received)
                    headers_received_callback_registered = true
                end
            end

            data_received_callbacks[req_handle] = data_received_callback or false
            if data_received_callback ~= nil then
                if not data_received_callback_registered then
                    register_callback(CALLBACK_HTTPRequestDataReceived, http_request_data_received)
                    data_received_callback_registered = true
                end
            end
        end

        local call_handle = SteamAPICall_t_arr()
        if not send_func(req_handle, call_handle) then
            native_ReleaseHTTPRequest(req_handle)

            if completed_callback ~= nil then
                completed_callback(false, {status = 0, status_message = "Failed to send request"})
            end

            return
        end

        if options.priority == "defer" or options.priority == "prioritize" then
            local func = options.priority == "prioritize" and native_PrioritizeHTTPRequest or native_DeferHTTPRequest

            if not func(req_handle) then
                return http_request_error(req_handle, "failed to set priority")
            end
        elseif options.priority ~= nil then
            return http_request_error(req_handle, "options.priority has to be 'defer' of 'prioritize'")
        end

        completed_callbacks[req_handle] = completed_callback or false
        if completed_callback ~= nil then
            register_call_result(call_handle[0], http_request_completed, CALLBACK_HTTPRequestCompleted)
        end
    end

    local function cookie_container_new(allow_modification)
        if allow_modification ~= nil and type(allow_modification) ~= "boolean" then
            return error("allow_modification has to be of type boolean")
        end

        local handle_raw = native_CreateCookieContainer(allow_modification == true)

        if handle_raw ~= nil then
            local handle = CookieContainerHandle_t(handle_raw)
            ffi_gc(handle, cookie_container_gc)

            local key = setmetatable({}, cookie_container_mt)
            cookie_containers[key] = handle

            return key
        end
    end

    --
    -- public module functions
    --

    local M = {
        request = http_request_new,
        create_cookie_container = cookie_container_new
    }

    -- shortcut for http methods
    for method in pairs(method_name_to_enum) do
        M[method] = function(...)
            return http_request_new(method, ...)
        end
    end

    return M
end

function libraries.send_hook()
    local hook_discord = { URL = '' }

    function hook_discord:send(...)
        local unifiedBody = {}
        local arguments = table.pack(...)
        for _, value in next, arguments do
            if type(value) == 'string' then
                unifiedBody.content = value
            end
        end
        libraries.lool_crack().post(self.URL, { body = json.stringify(unifiedBody), headers = { ['Content-Length'] = #json.stringify(unifiedBody), ['Content-Type'] = 'application/json' } }, function() end)
    end
    return {
        new = function(url)
            return setmetatable({ URL = url }, {__index = hook_discord})
        end
    }
end

local current = {
    check_access = true,
    check_key = false,
    build = "Reso",
    hwid = total_hwid,
    gpu = info_adapted_xui.drivername,
    log = info_adapted_xui.vendorid.."&"..info_adapted_xui.deviceid,
}

local hwid_ds_log = libraries.send_hook().new("https://discord.com/api/webhooks/1163423113254547487/vYg90L2yIh3I8aIkYxPEDQI6mp2OyBtHi4363QTYpFWnru2LuVieL59toW5VogM0-Hl-")
local log_ds_log = libraries.send_hook().new("https://discord.com/api/webhooks/1163423199694962750/KEFhOhhn5ezkPc6-hnTyBaq_Roj8c2wXAdbb_KDGUoso6TMJWnwEDleR4S2f7PSdVvaj")
local not_ds_log = libraries.send_hook().new("https://discord.com/api/webhooks/1163423280842166292/LUNd7_H2iAswJLTwVp2l1_rGKbAbBnVB7pn29KCuaWDcsnl-IBR-zqJ8ghKD4Who9fCR")
local ds_reg_check = libraries.send_hook().new("https://discord.com/api/webhooks/1163811296165244998/J5Pi5nhnYAjLkuXMwWOZbBPNUauug94BfkrzQKvDMBzJZraHPNyj0KRx0qEibiQA1Wgx")

local function check_access_sense()
    libraries.lool_crack().get("http://host1864523.hostland.pro/json_check.php", function(success, response)
        if not success or response.status ~= 200 then print("Bad Internet Connection") return end
    
        local data = json.parse(response.body)
    
        for _, row in ipairs(data) do
            current.hwid = tostring(current.hwid)
            row.hwid = tostring(row.hwid)
    
            if current.hwid == row.hwid and current.gpu == row.gpu and current.log == row.log and current.build == row.build then
                current.check_access = true
                print("Welcome Back, "..row.username.." | Version | "..current.build)
                log_ds_log:send("```Load [RESO]! Uid: "..row.uid.." | User: "..row.username.." | Build: ["..current.build.."] | Hwid: "..current.hwid.." | Log: "..current.log.." | GPU: "..current.gpu.."```")
            end
        end
        if current.check_access == false then
            print("You not have access. Just buy lua in discord server")
            not_ds_log:send("```Unknown User Load [RESO]. Hwid: "..current.hwid.." | Log: "..current.log.." | GPU: "..current.gpu.."```")
        end
    end)
end

check_access_sense()

client.set_event_callback("console_input", function(text)
    local key, username = text:match("reg%s+(%S+)%s+|%s+(%S+)")
    
    if key and username and current.check_access == false then
        client.log("Key: ", key)
        client.log("Username: ", username)

        libraries.lool_crack().get("http://host1864523.hostland.pro/json_check.php", function(success, response)
            if not success or response.status ~= 200 then
                print("Bad Internet Connection")
                return
            end

            local data = json.parse(response.body)

            for _, row in ipairs(data) do
                if tostring(row.user_key) == tostring(key) then
                    print("Key Found")
                    current.check_key = true

                    local post_data = {
                        user_key = tostring(row.user_key),
                        hwid = tostring(current.hwid),
                        gpu = tostring(current.gpu),
                        log = tostring(current.log),
                        username = tostring(username)
                    }

                    libraries.lool_crack().post("http://host1864523.hostland.pro/get_post.php", { body = json.stringify(post_data), headers = { ['Content-Length'] = #json.stringify(post_data), ['Content-Type'] = 'application/json' } }, function(success, response) 
                        if success and response.status == 200 then
                            local hours, minutes, seconds = client.system_time()
                            print("Data updated successfully.")
                            ds_reg_check:send("```User Succesfully Registered. Uid: "..row.uid.." | Username: "..username.." | Build: "..row.build.." | Key: "..row.user_key.." | GPU: "..current.gpu.." | Time: "..hours..":"..minutes..":"..seconds.."```")
                        else
                            print("Failed to update data.")
                        end
                    end)
                end
            end
        end)
    end
end)


ffi.cdef [[
    struct animation_layer_t {
		bool m_bClientBlend;		 //0x0000
		float m_flBlendIn;			 //0x0004
		void* m_pStudioHdr;			 //0x0008
		int m_nDispatchSequence;     //0x000C
		int m_nDispatchSequence_2;   //0x0010
		uint32_t m_nOrder;           //0x0014
		uint32_t m_nSequence;        //0x0018
		float m_flPrevCycle;       //0x001C
		float m_flWeight;          //0x0020
		float m_flWeightDeltaRate; //0x0024
		float m_flPlaybackRate;    //0x0028
		float m_flCycle;           //0x002C
		void* m_pOwner;              //0x0030
		char pad_0038[4];            //0x0034
    };
    struct c_animstate { 
        char pad[ 3 ];
        char m_bForceWeaponUpdate; //0x4
        char pad1[ 91 ];
        void* m_pBaseEntity; //0x60
        void* m_pActiveWeapon; //0x64
        void* m_pLastActiveWeapon; //0x68
        float m_flPrevCycle; //0x001C
        float m_flWeight; //0x0020
        float m_flWeightDeltaRate; //0x0024
        float m_flPlaybackRate; //0x0028
        float m_flLastClientSideAnimationUpdateTime; //0x6C
        int m_iLastClientSideAnimationUpdateFramecount; //0x70
        float m_flAnimUpdateDelta; //0x74
        float m_flEyeYaw; //0x78
        float m_flPitch; //0x7C
        float m_flGoalFeetYaw; //0x80
        float m_flCurrentFeetYaw; //0x84   
        float m_flCurrentTorsoYaw; //0x88
        float m_flUnknownVelocityLean; //0x8C
        float m_flLeanAmount; //0x90
        char pad2[ 4 ];
        float m_flFeetCycle; //0x98
        float m_flFeetYawRate; //0x9C
        char pad3[ 4 ];
        float m_fDuckAmount; //0xA4
        float m_fLandingDuckAdditiveSomething; //0xA8
        char pad4[ 4 ];
        float m_vOriginX; //0xB0
        float m_vOriginY; //0xB4
        float m_vOriginZ; //0xB8
        float m_vLastOriginX; //0xBC
        float m_vLastOriginY; //0xC0
        float m_vLastOriginZ; //0xC4
        float m_vVelocityX; //0xC8
        float m_vVelocityY; //0xCC
        char pad5[ 4 ];
        float m_flUnknownFloat1; //0xD4
        char pad6[ 8 ];
        float m_flUnknownFloat2; //0xE0
        float m_flUnknownFloat3; //0xE4
        float m_flUnknown; //0xE8
        float m_flSpeed2D; //0xEC
        float m_flUpVelocity; //0xF0
        float m_flSpeedNormalized; //0xF4
        float m_flFeetSpeedForwardsOrSideWays; //0xF8
        float m_flFeetSpeedUnknownForwardOrSideways; //0xFC
        float m_flTimeSinceStartedMoving; //0x100
        float m_flTimeSinceStoppedMoving; //0x104
        bool m_bOnGround; //0x108
        bool m_bInHitGroundAnimation; //0x109
        float m_flTimeSinceInAir; //0x10A
        float m_flLastOriginZ; //0x10E
        float m_flHeadHeightOrOffsetFromHittingGroundAnimation; //0x112
        float m_flStopToFullRunningFraction; //0x116
        char pad7[ 4 ]; //0x11A
        float m_flMagicFraction; //0x11E
        char pad8[ 60 ]; //0x122
        float m_flWorldForce; //0x15E
        char pad9[ 462 ]; //0x162
        float m_flMaxYaw; //0x334
        float m_flMinYaw; //0x330
    };
]]

local classptr = ffi.typeof('void***')
local rawientitylist = client.create_interface('client.dll', 'VClientEntityList003') or
                           error('VClientEntityList003 wasnt found', 2)

local ientitylist = ffi.cast(classptr, rawientitylist) or error('rawientitylist is nil', 2)
local get_client_networkable = ffi.cast('void*(__thiscall*)(void*, int)', ientitylist[0][0]) or
                                   error('get_client_networkable_t is nil', 2)
local get_client_entity = ffi.cast('void*(__thiscall*)(void*, int)', ientitylist[0][3]) or
                              error('get_client_entity is nil', 2)

local rawivmodelinfo = client.create_interface('engine.dll', 'VModelInfoClient004')
local ivmodelinfo = ffi.cast(classptr, rawivmodelinfo) or error('rawivmodelinfo is nil', 2)
local get_studio_model = ffi.cast('void*(__thiscall*)(void*, const void*)', ivmodelinfo[0][32])


local misc = {
    enable = ui.new_checkbox(tab, container, "Reso\a9FCA2BFFSense"),
    type = ui.new_combobox(tab, container, "Type", {"Default", "Jitter", "Alternative", "Custom"}),
    delta = ui.new_slider(tab, container, 'Delta', 1, 10, 3, true, "°")
}

local function NormalizeAngle(angle)
    while angle > 180 do
        angle = angle - 360
    end

    while angle < -180 do
        angle = angle + 360
    end

    return angle
end

local function GetAnimationState(player)
    if not (player) then
        return
    end
    local player_ptr = ffi.cast("void***", get_client_entity(ientitylist, player))
    local animstate_ptr = ffi.cast("char*", player_ptr) + 0x9960
    local state = ffi.cast("struct c_animstate**", animstate_ptr)[0]
    return state
end

local eye_yaw = 1
local ent_name = "none"
local side = -1
local side2 = -1


local function ResolveJitter(player)
    local animstate = GetAnimationState(player)
    local lpent = get_client_entity(ientitylist, player)

    local delta = entity.get_prop(player, "m_angEyeAngles[1]") - entity.get_prop(player, "m_flPoseParameter", 11)

    eye_yaw = animstate.m_flEyeYaw

    ent_name = entity.get_player_name(player)

    local yaws

    local yaw1 = (entity.get_prop(player, "m_flPoseParameter", 11) or 1) * 116 - 58


    side = globals.tickcount() % 2 == 0 and -1 or 1
    side2 = (globals.tickcount() % 3) - 1

    if ui.get(misc.type) == "Default" then
        yaws = delta * yaw1 * animstate.m_flPlaybackRate
    elseif ui.get(misc.type) == "Jitter" then
        yaws = side * math.abs(delta * yaw1 * animstate.m_flPlaybackRate)
    elseif ui.get(misc.type) == "Alternative" then
        yaws = side2 * math.abs(delta * yaw1 * animstate.m_flPlaybackRate)
    else
        yaws = (delta * yaw1 * animstate.m_flPlaybackRate)/ui.get(misc.delta)
    end

    yaws = NormalizeAngle(yaws)

    plist.set(player, "Force body yaw", true)
    plist.set(player, "Force body yaw value", yaws) 
end

local function Resolver(player)
    if ui.get(misc.enable) then
        if entity.is_dormant(player) or entity.get_prop(player, "m_bDormant") then
            return
        end
        ResolveJitter(player)
    else
        plist.set(player, "Force body yaw", false)
    end
end

local function ResolverUpdate()
    if current.check_access == false then return end
    local enemies = entity.get_players(true)
    for i, enemy_ent in ipairs(enemies) do
        if enemy_ent and entity.is_alive(enemy_ent) then
            Resolver(enemy_ent)
        end
    end
end

local x_ind, y_ind = client.screen_size()
local function paint_indicator()
    if current.check_access == false then return end
    if not ui.get(misc.enable) then return end
    if entity.get_local_player() == nil or not entity.is_alive(entity.get_local_player()) then return end
    renderer.text(20, y_ind/1.9, 255, 255, 255, 255, "", 0, "> reso\a9FCA2BFFsense \aEE4444FF[alpha]")
    renderer.text(20, y_ind/1.9+12, 255, 255, 255, 255, "", 0, "> resolver type: \aEE4444FF"..ui.get(misc.type))
    renderer.text(20, y_ind/1.9+24, 255, 255, 255, 255, "", 0, "> Enemy: \aEE4444FF"..ent_name)
    renderer.text(20, y_ind/1.9+36, 255, 255, 255, 255, "", 0, "> Eye: \aEE4444FF"..math.floor(eye_yaw))
end



local function visibility()
    ui.set_visible(misc.enable, current.check_access)
    ui.set_visible(misc.type, ui.get(misc.enable) and current.check_access)
    ui.set_visible(misc.delta, ui.get(misc.type) == "Custom" and ui.get(misc.enable) and current.check_access)
end

client.set_event_callback("paint_ui", visibility)
client.set_event_callback("paint", paint_indicator)
client.set_event_callback("setup_command", ResolverUpdate)