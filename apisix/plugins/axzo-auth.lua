--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core = require("apisix.core")
local http = require("resty.http")
local ngx = ngx
local ngx_re = require("ngx.re")
local ipairs = ipairs
local consumer = require("apisix.consumer")
local base64_encode = require("base64").encode
local tostring = tostring

local lrucache = core.lrucache.new({
    ttl = 300, count = 512
})

local schema = {
    type = "object",
    title = "work with route or service object",
    properties = {
        discovery = {type = "string", minLength = 1, maxLength = 4096},
        authurl = {type = "string", minLength = 1, maxLength = 4096},
        hide_credentials = {
            type = "boolean",
            default = false,
        }
    },
}

local plugin_name = "axzo-auth"

local _M = {
    version = 0.1,
    priority = 2521,
    name = plugin_name,
    schema = schema
}

function _M.check_schema(conf, schema_type)
    local ok, err = core.schema.check(schema, conf)

    if not ok then
        return false, err
    end

    return true
end

local function extract_auth_header(authorization, conf)
    local function do_extract(auth)
        local decoded = auth
        if not decoded then
            return nil, "axzo-auth: Failed to decode authentication header: "
        end

        local httpc = http.new()
        httpc:set_timeout(timeout)


        local authurl = conf.authurl

        if not authurl then
            ngx.log(ngx.WARN,"failed to read authurl from conf ")
            authurl = core.config.local_conf().authurl
        end
        ngx.log(ngx.WARN," read authurl from conf ", authurl)

        if not authurl then
            return nil, "axzo-auth: config authurl first "
        end

        local res, err = httpc:request_uri(authurl, {
            method = "GET",
            headers = {
                ["Authorization"] = decoded,
                ["content-type"] = "application/json;charset=UTF-8",
            }
        })
        httpc:set_keepalive(5000, 100)

        if not res then
            ngx.log(ngx.WARN,"failed to request: ", err)
            return nil, "axzo-auth: failed to request: " .. url .. "; errmsg : " .. err .. " ; auth : " .. decoded
        end
        --请求之后，状态码
        ngx.status = res.status
        if ngx.status ~= 200 then
            ngx.log(ngx.WARN,"非200状态，ngx.status:"..ngx.status)
            return nil, "axzo-auth: response : " .. res
        end

        --local jsonbody = core.json.decode(res.body);
        --ngx.log(ngx.WARN, "jsonbody ... " .. jsonbody)

        local encoded_body = base64_encode(res.body)
        ngx.log(ngx.WARN, "encoded_body ... " .. encoded_body)
        return encoded_body, nil
    end

    local matcher, err = lrucache(authorization, nil, do_extract, authorization)
    if matcher then
        return matcher, err
    else
        return "none user",  err
    end

end


function _M.rewrite(conf, ctx)
    core.log.info("plugin access phase, conf: ", core.json.delay_encode(conf))

    -- 1. extract authorization from header
    local auth_header = core.request.header(ctx, "Authorization")
    if not auth_header then
        core.response.set_header("WWW-Authenticate", "Basic realm='.'")
        return 401, { message = "Missing authorization in request" }
    end

    local encoded_body, err = extract_auth_header(auth_header, conf)
    if err then
        return 401, { message = err }
    end

    --core.request.charset = "UTF-8"
    core.request.set_header(ctx, "userinfo", encoded_body)
    ngx.log(ngx.WARN, "set header ... " .. encoded_body)
    core.log.info("hit axzo-auth access")
end

return _M
