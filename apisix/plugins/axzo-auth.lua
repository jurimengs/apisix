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
local http = require("apisix.core.resty.http")
local ngx = ngx
local ngx_re = require("ngx.re")
local ipairs = ipairs
local consumer = require("apisix.consumer")
local base64_encode = require("base64").encode
local tostring = tostring

local lrucache = core.lrucache.new({
    ttl = 300, count = 512
})
local consumers_lrucache = core.lrucache.new({
    type = "plugin",
})

local schema = {
    type = "object",
    title = "work with route or service object",
    properties = {
        hide_credentials = {
            type = "boolean",
            default = false,
        }
    },
}

local consumer_schema = {
    type = "object",
    title = "work with consumer object",
    properties = {
        username = { type = "string" },
        password = { type = "string" },
    },
    required = {"username", "password"},
}

local plugin_name = "axzo-auth"

local _M = {
    version = 0.1,
    priority = 2520,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema
}

function _M.check_schema(conf, schema_type)
    local ok, err
    if schema_type == core.schema.TYPE_CONSUMER then
        ok, err = core.schema.check(consumer_schema, conf)
    else
        ok, err = core.schema.check(schema, conf)
    end

    if not ok then
        return false, err
    end

    return true
end

local function extract_auth_header(authorization)
    local function do_extract(auth)
        local decoded = auth
        if not decoded then
            return nil, "axzo-auth: Failed to decode authentication header: "
        end

        local httpc = http.new()
        httpc:set_timeout(timeout)


        local authurl = core.config.local_conf().authurl
        if not authurl then
            return nil, "axzo-auth: config authurl first "
        end
        --local authurl = "http://test-api.axzo.cn/pudge/webApi/cms/user/info"

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

        local jsonbody = core.json.decode(res.body);
        -- 可以拿到 user 信息了
        --return nil, "axzo-auth: userinfo : " .. jsonbody.data.nickname // 中文会报错
        --return nil, "axzo-auth: userinfo : " .. jsonbody.data.acctId
        --return nil, "axzo-auth: userinfo : " .. jsonbody.data.id

        local obj = { username = "" }
        --obj.username = base64_encode(jsonbody.data.nickname)
        obj.username = base64_encode("中")
        return obj, nil
    end

    local obj, err = do_extract(authorization)
    if obj then
        return obj.username, err
        --return nil, obj.username
    else
        return "none user", err
        --return nil, "none user"
    end

    --local matcher, err = lrucache(authorization, nil, do_extract, authorization)
    --if matcher then
    --    return matcher.username, err
    --else
    --    return "",  err
    --end

end

local create_consume_cache
do
    local consumer_names = {}

    function create_consume_cache(consumers)
        core.table.clear(consumer_names)

        for _, cur_consumer in ipairs(consumers.nodes) do
            core.log.info("consumer node: ",
                    core.json.delay_encode(cur_consumer))
            consumer_names[cur_consumer.auth_conf.username] = cur_consumer
        end

        return consumer_names
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

    local username, err = extract_auth_header(auth_header)
    if err then
        return 401, { message = err }
    end

    --core.request.charset = "UTF-8"
    core.request.set_header(ctx, "username", username)
    core.log.info("hit axzo-auth access")
end


-- 支持 https
-- endpoint_addr: http://xxx/path or https://

local function send_http_data(conf, log_message)
    local err_msg
    local res = true
    local url_decoded = url.parse(conf.endpoint_addr)
    local host = url_decoded.host
    local port = url_decoded.port

    core.log.info("sending a batch logs to ", conf.endpoint_addr)

    if not port then
        if url_decoded.scheme == "https" then
            port = 443
        else
            port = 80
        end
    end

    local httpc = http.new()
    httpc:set_timeout(conf.timeout * 1000)
    local ok, err = httpc:connect(host, port)

    if not ok then
        return false, "failed to connect to host[" .. host .. "] port["
                .. tostring(port) .. "] " .. err
    end

    if url_decoded.scheme == "https" then
        ok, err = httpc:ssl_handshake(true, host, conf.ssl_verify)
        if not ok then
            return false, "failed to perform SSL with host[" .. host .. "] "
                    .. "port[" .. tostring(port) .. "] " .. err
        end
    end

    local httpc_res, httpc_err = httpc:request({
        method = "POST",
        path = url_decoded.path,
        query = url_decoded.query,
        body = "INSERT INTO " .. conf.logtable .." FORMAT JSONEachRow " .. log_message,
        headers = {
            ["Host"] = url_decoded.host,
            ["Content-Type"] = "application/json;charset=UTF-8",
        }
    })

    if not httpc_res then
        return false, "error while sending data to [" .. host .. "] port["
                .. tostring(port) .. "] " .. httpc_err
    end

    -- some error occurred in the server
    if httpc_res.status >= 400 then
        res =  false
        err_msg = "server returned status code[" .. httpc_res.status .. "] host["
                .. host .. "] port[" .. tostring(port) .. "] "
                .. "body[" .. httpc_res:read_body() .. "]"
    end

    return res, err_msg
end

return _M
