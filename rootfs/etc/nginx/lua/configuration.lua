local cjson = require("cjson.safe")

-- this is the Lua representation of Configuration struct in internal/ingress/types.go
local configuration_data = ngx.shared.configuration_data
local certificate_data = ngx.shared.certificate_data
local metrics_data = ngx.shared.metrics_data

local _M = {}

function _M.get_backends_data()
  return configuration_data:get("backends")
end

function _M.get_general_data()
  return configuration_data:get("general")
end

local function fetch_request_body()
  ngx.req.read_body()
  local body = ngx.req.get_body_data()

  if not body then
    -- request body might've been written to tmp file if body > client_body_buffer_size
    local file_name = ngx.req.get_body_file()
    local file = io.open(file_name, "rb")

    if not file then
      return nil
    end

    body = file:read("*all")
    file:close()
  end

  return body
end

function _M.get_pem_cert_key(hostname)
  return certificate_data:get(hostname)
end

local function handle_servers()
  if ngx.var.request_method ~= "POST" then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.print("Only POST requests are allowed!")
    return
  end

  local raw_servers = fetch_request_body()

  if raw_servers then
    metrics_data:set("cert_last_bytes",  string.len(raw_servers))
  end

  local servers, err = cjson.decode(raw_servers)
  if not servers then
    ngx.log(ngx.ERR, "could not parse servers: ", err)
    ngx.status = ngx.HTTP_BAD_REQUEST
    return
  end

  local err_buf = {}
  local cert_count_success, cert_count_fail, cert_count_forcible = 0, 0, 0
  for _, server in ipairs(servers) do
    if server.hostname and server.sslCert.pemCertKey then
      local success, set_err, forcible = certificate_data:set(server.hostname, server.sslCert.pemCertKey)
      if not success then
        local err_msg = string.format("error setting certificate for %s: %s\n", server.hostname, tostring(set_err))
        table.insert(err_buf, err_msg)
        cert_count_fail = cert_count_fail + 1
      else
        cert_count_success = cert_count_success + 1
      end
      if forcible then
        cert_count_forcible = cert_count_forcible + 1
        metrics_data:incr("cert_overflow_total", 1, 0, 0)
        local msg = string.format("certificate_data dictionary is full, LRU entry has been removed to store %s",
          server.hostname)
        ngx.log(ngx.WARN, msg)
      end
    else
      ngx.log(ngx.WARN, "hostname or pemCertKey are not present")
    end
  end
  metrics_data:set("cert_last_success", cert_count_success - cert_count_forcible)
  metrics_data:set("cert_last_fail", cert_count_fail)
  metrics_data:set("cert_last_forcible", cert_count_forcible)

  if #err_buf > 0 then
    ngx.log(ngx.ERR, table.concat(err_buf))
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    return
  end

  ngx.status = ngx.HTTP_CREATED
end

local function handle_general()
  if ngx.var.request_method == "GET" then
    ngx.status = ngx.HTTP_OK
    ngx.print(_M.get_general_data())
    return
  end

  if ngx.var.request_method ~= "POST" then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.print("Only POST and GET requests are allowed!")
    return
  end

  local config = fetch_request_body()

  local success, err = configuration_data:safe_set("general", config)
  if not success then
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.log(ngx.ERR, "error setting general config: " .. tostring(err))
    return
  end

  ngx.status = ngx.HTTP_CREATED
end

local function handle_certs()
  if ngx.var.request_method ~= "GET" then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.print("Only GET requests are allowed!")
    return
  end

  local query = ngx.req.get_uri_args()
  if not query["hostname"] then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.print("Hostname must be specified.")
    return
  end

  local key = _M.get_pem_cert_key(query["hostname"])
  if key then
    ngx.status = ngx.HTTP_OK
    ngx.print(key)
    return
  else
    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.print("No key associated with this hostname.")
    return
  end
end

local function handle_metrics()
  ngx.status = ngx.HTTP_OK
  ngx.say("conf_free_space_bytes: ", configuration_data:free_space())
  ngx.say("conf_capacity_bytes: ", configuration_data:capacity())
  ngx.say("cert_free_space_bytes: ", certificate_data:free_space())
  ngx.say("cert_capacity_bytes: ", certificate_data:capacity())
  ngx.say("cert_last_success: ", metrics_data:get("cert_last_success") or 0)
  ngx.say("cert_last_fail: ", metrics_data:get("cert_last_fail") or 0)
  ngx.say("cert_last_forcible: ", metrics_data:get("cert_last_forcible") or 0)
  ngx.say("cert_overflow_total: ", metrics_data:get("cert_overflow_total") or 0)
  ngx.say("cert_last_bytes: ", metrics_data:get("cert_last_bytes") or 0)
end

function _M.call()
  if ngx.var.request_method ~= "POST" and ngx.var.request_method ~= "GET" then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.print("Only POST and GET requests are allowed!")
    return
  end

  if ngx.var.request_uri == "/configuration/servers" then
    handle_servers()
    return
  end

  if ngx.var.request_uri == "/configuration/general" then
    handle_general()
    return
  end

  if ngx.var.uri == "/configuration/certs" then
    handle_certs()
    return
  end

  if ngx.var.request_uri == "/configuration/metrics" then
    handle_metrics()
    return
  end

  if ngx.var.request_uri ~= "/configuration/backends" then
    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.print("Not found!")
    return
  end

  if ngx.var.request_method == "GET" then
    ngx.status = ngx.HTTP_OK
    ngx.print(_M.get_backends_data())
    return
  end

  local backends = fetch_request_body()
  if not backends then
    ngx.log(ngx.ERR, "dynamic-configuration: unable to read valid request body")
    ngx.status = ngx.HTTP_BAD_REQUEST
    return
  end

  local success, err = configuration_data:set("backends", backends)
  if not success then
    ngx.log(ngx.ERR, "dynamic-configuration: error updating configuration: " .. tostring(err))
    ngx.status = ngx.HTTP_BAD_REQUEST
    return
  end

  ngx.status = ngx.HTTP_CREATED
end

if _TEST then
  _M.handle_servers = handle_servers
end

return _M
