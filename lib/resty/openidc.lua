--[[
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

***************************************************************************
Copyright (C) 2015-2017 Ping Identity Corporation
All rights reserved.

For further information please contact:

     Ping Identity Corporation
     1099 18th St Suite 2950
     Denver, CO 80202
     303.468.2900
     http://www.pingidentity.com

DISCLAIMER OF WARRANTIES:

THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
--]]

local require = require
local cjson   = require "cjson"
local http    = require "resty.http"
local string  = string
local ipairs  = ipairs
local pairs   = pairs
local type    = type
local ngx     = ngx

local openidc = {
  _VERSION = "1.3.1"
}
openidc.__index = openidc

-- set value in server-wide cache if available
local function openidc_cache_set(type, key, value, exp)
  local dict = ngx.shared[type]
  if dict then
    local success, err, forcible = dict:set(key, value, exp)
    ngx.log(ngx.DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
  end
end

-- retrieve value from server-wide cache if available
local function openidc_cache_get(type, key)
  local dict = ngx.shared[type]
  local value
  local flags
  if dict then
    value, flags = dict:get(key)
    if value then ngx.log(ngx.DEBUG, "cache hit: type=", type, " key=", key) end
  end
  return value
end

-- validate the contents of and id_token
local function openidc_validate_id_token(opts, id_token, nonce)

  -- check issuer
  if opts.discovery.issuer ~= id_token.iss then
    ngx.log(ngx.ERR, "issuer \"", id_token.iss, " in id_token is not equal to the issuer from the discovery document \"", opts.discovery.issuer, "\"")
    return false
  end

  -- check nonce
  if nonce and nonce ~= id_token.nonce then
    ngx.log(ngx.ERR, "nonce \"", id_token.nonce, " in id_token is not equal to the nonce that was sent in the request \"", nonce, "\"")
    return false
  end

  -- check issued-at timestamp
  if not id_token.iat then
    ngx.log(ngx.ERR, "no \"iat\" claim found in id_token")
    return false
  end

  local slack=opts.iat_slack and opts.iat_slack or 120
  if id_token.iat < (ngx.time() - slack) then
    ngx.log(ngx.ERR, "token is not valid yet: id_token.iat=", id_token.iat, ", ngx.time()=", ngx.time())
    return false
  end

  -- check expiry timestamp
  if id_token.exp < ngx.time() then
    ngx.log(ngx.ERR, "token expired: id_token.exp=", id_token.exp, ", ngx.time()=", ngx.time())
    return false
  end

  -- check audience (array or string)
  if (type(id_token.aud) == "table") then
    for key, value in pairs(id_token.aud) do
      if value == opts.client_id then
        return true
      end
    end
    ngx.log(ngx.ERR, "no match found token audience array: client_id=", opts.client_id )
    return false
  elseif  (type(id_token.aud) == "string") then
    if id_token.aud ~= opts.client_id then
      ngx.log(ngx.ERR, "token audience does not match: id_token.aud=", id_token.aud, ", client_id=", opts.client_id )
      return false
    end
  end
  return true
end

-- assemble the redirect_uri
local function openidc_get_redirect_uri(opts, target_url)
  local redirect_uri = opts.redirect_uri_path
  if opts.relative_redirect ~= "yes" then
    local scheme = opts.redirect_uri_scheme or ngx.req.get_headers()['X-Forwarded-Proto'] or ngx.var.scheme
    redirect_uri = scheme.."://"..ngx.var.http_host..redirect_uri
  end
  if opts.add_target_url_to_redirect_uri == "yes" and target_url then
    redirect_uri = redirect_uri .. "?" .. ngx.encode_args({ target = target_url })
  end
  return redirect_uri
end

-- perform base64url decoding
local function openidc_base64_url_decode(input)
  local reminder = #input % 4
  if reminder > 0 then
    local padlen = 4 - reminder
    input = input .. string.rep('=', padlen)
  end
  input = input:gsub('-','+'):gsub('_','/')
  return ngx.decode_base64(input)
end

-- perform base64url encoding
local function openidc_base64_url_encode(input)
  input = ngx.encode_base64(input)
  return input:gsub('+','-'):gsub('/','_'):gsub('=','')
end

-- send the browser of to the OP's authorization endpoint
local function openidc_authorize(opts, session, target_url)
  local resty_random = require "resty.random"
  local resty_string = require "resty.string"

  -- generate state and nonce
  local state = resty_string.to_hex(resty_random.bytes(16))
  local nonce = resty_string.to_hex(resty_random.bytes(16))

  -- assemble the parameters to the authentication request
  local params = {
    client_id=opts.client_id,
    response_type="code",
    scope=opts.scope and opts.scope or "openid email profile",
    redirect_uri=openidc_get_redirect_uri(opts, target_url),
    state=state,
    nonce=nonce
  }

  -- merge any provided extra parameters
  if opts.authorization_params then
    for k,v in pairs(opts.authorization_params) do params[k] = v end
  end

  -- Safari on iOS 12 and macOS Mojave wont send cookies when SameSite cookie parameter is set to Lax and IDP is on another domain
  if session.cookie.samesite and opts.relative_redirect ~= "yes" then
    session.cookie.samesite = false
  end

  -- store state in the session
  session:start()
  session.data.original_url = target_url
  session.data.state = state
  session.data.nonce = nonce
  session:save()

  -- redirect to the /authorization endpoint
  if opts.relative_redirect ~= "yes" then
    return ngx.redirect(opts.discovery.authorization_endpoint.."?"..ngx.encode_args(params))
  else
    return ngx.redirect(opts.discovery.authorization_endpoint:gsub("^https?://[^/]+", "") .."?"..ngx.encode_args(params))
  end
end

-- parse the JSON result from a call to the OP
local function openidc_parse_json_response(response)

  local err
  local res

  -- check the response from the OP
  if response.status ~= 200 then
    err = "response indicates failure, status="..response.status..", body="..response.body
  else
    -- decode the response and extract the JSON object
    res = cjson.decode(response.body)

    if not res then
      err = "JSON decoding failed"
    end
  end

  return res, err
end

-- make a call to the token endpoint
local function openidc_call_token_endpoint(opts, endpoint, body, auth)

  local headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded"
  }

  if auth then
    if auth == "client_secret_basic" then
      headers.Authorization = "Basic "..ngx.encode_base64( opts.client_id..":"..opts.client_secret)
      ngx.log(ngx.DEBUG,"client_secret_basic: authorization header '"..headers.Authorization.."'")
    end
    if auth == "client_secret_post" then
      body.client_id=opts.client_id
      body.client_secret=opts.client_secret
      ngx.log(ngx.DEBUG, "client_secret_post: client_id and client_secret being sent in POST body")
    end
  end

  ngx.log(ngx.DEBUG, "request body for token endpoint call: ", ngx.encode_args(body))

  local httpc = http.new()
  local res, err = httpc:request_uri(endpoint, {
    method = "POST",
    body = ngx.encode_args(body),
    headers = headers,
    ssl_verify = (opts.ssl_verify ~= "no")
  })
  if not res then
    err = "accessing token endpoint ("..endpoint..") failed: "..err
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  ngx.log(ngx.DEBUG, "token endpoint response: ", res.body)

  return openidc_parse_json_response(res);
end

-- make a call to the userinfo endpoint
local function openidc_call_userinfo_endpoint(opts, access_token)
  if not opts.discovery.userinfo_endpoint then
    ngx.log(ngx.DEBUG, "no userinfo endpoint supplied")
    return nil, nil
  end

  local httpc = http.new()
  local res, err = httpc:request_uri(opts.discovery.userinfo_endpoint, {
    headers = {
      ["Authorization"] = "Bearer "..access_token,
    }
  })
  if not res then
    err = "accessing userinfo endpoint ("..opts.discovery.userinfo_endpoint..") failed: "..err
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  ngx.log(ngx.DEBUG, "userinfo response: ", res.body)

  -- parse the response from the user info endpoint
  return openidc_parse_json_response(res)
end

-- get a new token and save to session
local function openidc_get_token(opts, session, body)
  -- make the call to the token endpoint
  local json, err = openidc_call_token_endpoint(opts, opts.discovery.token_endpoint, body, opts.token_endpoint_auth_method)
  if err then
    return nil, err
  end

  -- process the token endpoint response with the id_token and access_token
  local enc_hdr, enc_pay, enc_sign = string.match(json.id_token, '^(.+)%.(.+)%.(.+)$')
  local jwt = openidc_base64_url_decode(enc_pay)
  local id_token = cjson.decode(jwt)

  -- validate the id_token contents
  if openidc_validate_id_token(opts, id_token, session.data.nonce) == false then
    err = "id_token validation failed"
    return nil, err
  end

  -- call the user info endpoint
  local user, err = openidc_call_userinfo_endpoint(opts, json.access_token)
  if err then
    return nil, err
  end

  -- ensure session_state exists in the token and set the nginx cookie/session id to match the Keycloak session id
  local oldsession = session.id
  if json.session_state then
    if opts.leave_session_id ~= true then
      session.id = json.session_state
      ngx.log(ngx.DEBUG, "set session.id = ", ngx.encode_base64(session.id))
    end
  else
    err = "unable to get session_state from token"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  -- make the session expire when the token expires
  if opts.refresh_access_token == "yes" and json.refresh_expires_in then
    if json.refresh_expires_in > 0 then
      session.cookie.lifetime = json.refresh_expires_in
    end
  elseif json.expires_in and json.expires_in > 0 then
    session.cookie.lifetime = json.expires_in
  end

  -- update the tokens in the session
  session:start()
  session.data.user = user
  session.data.id_token = id_token
  session.data.enc_id_token = json.id_token
  session.data.access_token = json.access_token
  session.data.retries = 0
  if opts.refresh_access_token == "yes" then
    session.data.refresh_token = json.refresh_token
    -- refresh again before the access token expires to avoid passing tokens that are about to expire to backends
    session.data.refresh_after = ngx.time() + json.expires_in * (opts.refresh_ttl_factor or 0.75)
    if json.refresh_expires_in == 0 then
      session.data.refresh_exp = 0
    else
      session.data.refresh_exp = ngx.time() + json.refresh_expires_in
    end
    ngx.log(ngx.DEBUG, "setting refresh time to ", session.data.refresh_after - ngx.time(), " seconds from now, access token is valid for ".. json.expires_in .." seconds and refresh token is valid for ".. json.refresh_expires_in .." seconds")
  end

  -- save the session with the obtained id_token
  session:save()

  -- destroy the old session if we changed session id
  if oldsession and oldsession ~= "" and oldsession ~= session.id then
    session.storage:destroy(oldsession)
    ngx.log(ngx.DEBUG, "removing old session with id: ", ngx.encode_base64(oldsession))
  else
    ngx.log(ngx.DEBUG, "session id unchanged or old session id unknown, not removing old session")
  end

  return json, err
end

-- handle a "code" authorization response from the OP
local function openidc_authorization_response(opts, session)
  local args = ngx.req.get_uri_args()
  local err

  if not session.present then
    err = "request to the redirect_uri_path but there's no session state found"
    ngx.log(ngx.ERR, err)
    return nil, err, nil
  end

  if not args.code or not args.state then
    err = "unhandled request to the redirect_uri: "..ngx.var.request_uri
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url
  end

  -- check that the state returned in the response against the session; prevents CSRF
  if args.state ~= session.data.state then
    err = "state from argument: "..(args.state and args.state or "nil").." does not match state restored from session: "..(session.data.state and session.data.state or "nil")
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url
  end

  -- check the iss if returned from the OP
  if args.iss and args.iss ~= opts.discovery.issuer then
    err = "iss from argument: "..args.iss.." does not match expected issuer: "..opts.discovery.issuer
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url
  end

  -- check the client_id if returned from the OP
  if args.client_id and args.client_id ~= opts.client_id then
    err = "client_id from argument: "..args.client_id.." does not match expected client_id: "..opts.client_id
    ngx.log(ngx.ERR, err)
    return nil, err, session.data.original_url
  end

  -- assemble the parameters to the token endpoint
  local body = {
    grant_type="authorization_code",
    code=args.code,
    redirect_uri=openidc_get_redirect_uri(opts, session.data.original_url),
    state = session.data.state
  }

  -- Safari on iOS 12 and macOS Mojave wont send cookies when SameSite cookie parameter is set to Lax and IDP is on another domain
  if session.cookie.samesite and opts.relative_redirect ~= "yes" then
    session.cookie.samesite = false
    session.data.initcookie = true
  end

  -- get token and setup session
  local json, err = openidc_get_token(opts, session, body)
  if err then
    return nil, err, session.data.original_url
  end

  -- redirect to the URL that was accessed originally
  return ngx.redirect(session.data.original_url)

end

-- get the Discovery metadata from the specified URL
local function openidc_discover(url, ssl_verify)
  ngx.log(ngx.DEBUG, "In openidc_discover - URL is "..url)

  local json, err
  local v = openidc_cache_get("discovery", url)
  if not v then

    ngx.log(ngx.DEBUG, "Discovery data not in cache. Making call to discovery endpoint")
    -- make the call to the discovery endpoint
    local httpc = http.new()
    local res, error = httpc:request_uri(url, {
      ssl_verify = (ssl_verify ~= "no")
    })
    if not res then
      err = "accessing discovery url ("..url..") failed: "..error
      ngx.log(ngx.ERR, err)
    else
      ngx.log(ngx.DEBUG, "Response data: "..res.body)
      json, err = openidc_parse_json_response(res)
      if json then
        if string.sub(url, 1, string.len(json['issuer'])) == json['issuer'] then
          openidc_cache_set("discovery", url, cjson.encode(json), 24 * 60 * 60)
        else
          err = "issuer field in Discovery data does not match URL"
          json = nil
        end
      else
        err = "could not decode JSON from Discovery data"
      end
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

local function openidc_jwks(url, ssl_verify)
  ngx.log(ngx.DEBUG, "In openidc_jwks - URL is "..url)

  local json, err
  local v = openidc_cache_get("jwks", url)
  if not v then

    ngx.log(ngx.DEBUG, "JWKS data not in cache. Making call to jwks endpoint")
    -- make the call to the jwks endpoint
    local httpc = http.new()
    local res, error = httpc:request_uri(url, {
      ssl_verify = (ssl_verify ~= "no")
    })
    if not res then
      err = "accessing jwks url ("..url..") failed: "..error
      ngx.log(ngx.ERR, err)
    else
      ngx.log(ngx.DEBUG, "Response data: "..res.body)
      json, err = openidc_parse_json_response(res)
      if json then
        openidc_cache_set("jwks", url, cjson.encode(json), 24 * 60 * 60)
      end
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

local function split_by_chunk(text, chunkSize)
  local s = {}
  for i=1, #text, chunkSize do
    s[#s+1] = text:sub(i,i+chunkSize - 1)
  end
  return s
end

local function get_jwk (keys, kid)
  for _, value in pairs(keys) do
    if value.kid == kid then
      return value
    end
  end

  return nil
end

local function pem_from_jwk (opts, kid)
  local cache_id = opts.discovery.jwks_uri .. '#' .. kid
  local v = openidc_cache_get("jwks", cache_id)

  if v then
    return v
  end

  local jwks, err = openidc_jwks(opts.discovery.jwks_uri, opts.ssl_verify)
  if err then
    return nil, err
  end

  local x5c = get_jwk(jwks.keys, kid).x5c
  -- TODO check x5c length
  local chunks = split_by_chunk(ngx.encode_base64(openidc_base64_url_decode(x5c[1])), 64)
  local pem = "-----BEGIN CERTIFICATE-----\n" .. table.concat(chunks, "\n") .. "\n-----END CERTIFICATE-----"
  openidc_cache_set("jwks", cache_id, pem, 24 * 60 * 60)
  return pem
end

local openidc_transparent_pixel = "\137\080\078\071\013\010\026\010\000\000\000\013\073\072\068\082" ..
                                  "\000\000\000\001\000\000\000\001\008\004\000\000\000\181\028\012" ..
                                  "\002\000\000\000\011\073\068\065\084\120\156\099\250\207\000\000" ..
                                  "\002\007\001\002\154\028\049\113\000\000\000\000\073\069\078\068" ..
                                  "\174\066\096\130"

-- handle logout
local function openidc_logout(opts, session)
  session:destroy()
  local headers = ngx.req.get_headers()
  local header =  headers['Accept']
  if header and header:find("image/png") then
    ngx.header["Cache-Control"] = "no-cache, no-store"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["P3P"] = "CAO PSA OUR"
    ngx.header["Expires"] = "0"
    ngx.header["X-Frame-Options"] = "DENY"
    ngx.header.content_type = "image/png"
    ngx.print(openidc_transparent_pixel)
    ngx.exit(ngx.OK)
    return
  elseif opts.discovery.end_session_endpoint then
    local endpoint_url = opts.discovery.end_session_endpoint
    if opts.relative_redirect == "yes" then
      endpoint_url = endpoint_url:gsub("^https?://[^/]+", "")
    end
    if opts.pass_args_to_logout_endpoint == "yes" and ngx.var.args then
      endpoint_url = endpoint_url .. ngx.var.is_args .. ngx.var.args
    end
    return ngx.redirect(endpoint_url)
  elseif opts.discovery.ping_end_session_endpoint then
    return ngx.redirect(opts.discovery.ping_end_session_endpoint)
  end

  ngx.header.content_type = "text/html"
  ngx.say("<html><body>Logged Out</body></html>")
  ngx.exit(ngx.OK)
end

-- get the token endpoint authentication method
local function openidc_get_token_auth_method(opts)

  local result
  if opts.discovery.token_endpoint_auth_methods_supported ~= nil then
    -- if set check to make sure the discovery data includes the selected client auth method
    if opts.token_endpoint_auth_method ~= nil then
      for index, value in ipairs (opts.discovery.token_endpoint_auth_methods_supported) do
        ngx.log(ngx.DEBUG, index.." => "..value)
        if value == opts.token_endpoint_auth_method then
          ngx.log(ngx.DEBUG, "configured value for token_endpoint_auth_method ("..opts.token_endpoint_auth_method..") found in token_endpoint_auth_methods_supported in metadata")
          result = opts.token_endpoint_auth_method
          break
        end
      end
      if result == nil then
        ngx.log(ngx.ERR, "configured value for token_endpoint_auth_method ("..opts.token_endpoint_auth_method..") NOT found in token_endpoint_auth_methods_supported in metadata")
        return nil
      end
    else
      result = opts.discovery.token_endpoint_auth_methods_supported[1]
      ngx.log(ngx.DEBUG, "no configuration setting for option so select the first method specified by the OP: "..result)
    end
  else
    result = opts.token_endpoint_auth_method
  end

  -- set a sane default if auto-configuration failed
  if result == nil then
    result = "client_secret_basic"
  end

  ngx.log(ngx.DEBUG, "token_endpoint_auth_method result set to "..result)

  return result
end

local function openidc_refresh_token(opts, session)
  local json, err

  -- check we have a refresh token
  if not session.data.refresh_token then
    err = "no refresh token found, unable to refresh"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  -- dont refresh if it is not necessary
  if session.data.refresh_after > ngx.time() then
    ngx.log(ngx.DEBUG, "not refreshing token yet, current time ", ngx.time(), " is less than refresh time ", session.data.refresh_after)
    return true
  end

  -- check for an expired refresh token
  if session.data.refresh_exp > 0 and session.data.refresh_exp < ngx.time() then
    err = "refresh token expired at ".. session.data.refresh_exp .." which is before the current time ".. ngx.time()
    ngx.log(ngx.DEBUG, err)
    return nil, err
  end

  -- assemble the parameters to the token endpoint
  local body = {
    grant_type = "refresh_token",
    refresh_token = session.data.refresh_token
  }

  ngx.log(ngx.DEBUG, "refreshing token for session ", session.id, " from request ", ngx.var.request_id, ": ", ngx.var.request_uri)

  -- remove nonce from session to skip validating it in token refreshes, it's only necessary during initial signin
  session.data.nonce = nil

  -- get new token and update session
  local json, err = openidc_get_token(opts, session, body)
  if err then
    return nil, err
  end

  return json, err
end

function openidc.get_token_from_basic_auth(opts, session)
  if not ngx.var.remote_user or not ngx.var.remote_passwd then
    local err = "basic authorization header is not set or not valid"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  -- assemble the parameters to the token endpoint
  local body = {
    grant_type = "password",
    username = ngx.var.remote_user,
    password = ngx.var.remote_passwd,
    scope = opts.scope and opts.scope or "openid email profile"
  }

  session.id = ngx.var.remote_user
  ngx.log(ngx.DEBUG, "fetching token using credentials from basic authorization header for user ", session.id, " from request ", ngx.var.request_id, ": ", ngx.var.request_uri)

  -- get new token and update session
  local json, err = openidc_get_token(opts, session, body)
  if err then
    return nil, err
  end

  return json, err
end

-- main routine for OpenID Connect user authentication
function openidc.authenticate(opts, target_url)

  local err

  local target_url = target_url or ngx.var.request_uri

  if type(opts.discovery) == "string" then
    --if session.data.discovery then
    --  opts.discovery = session.data.discovery
    --else
    --  session.data.discovery = opts.discovery
    --end
    opts.discovery, err = openidc_discover(opts.discovery, opts.ssl_verify)
    if err then
      return nil, err, target_url
    end
  end

  -- set the authentication method for the token endpoint
  opts.token_endpoint_auth_method = openidc_get_token_auth_method(opts)

  -- if basic_auth is enabled and standard_flow has not been explicitly enabled then disable standard_flow
  if (opts.basic_auth == true or opts.basic_auth_legacy == true) and opts.standard_flow == nil then
    opts.standard_flow = false
  end

  -- attempt authentication using basic authorization header if basic_auth has been enabled and header is present
  local session, valid
  if (opts.basic_auth == true or opts.basic_auth_legacy == true) and ngx.var.remote_user and ngx.var.remote_passwd then
    -- if basic_auth_legacy has been enabled and the username has an @ in it then attempt legacy basic auth
    if opts.basic_auth_legacy == true and ngx.var.remote_user:find("@") then
      if type(opts.basic_legacy_session_opts) == "table" then
        opts.basic_legacy_session_opts.basic = true
        opts.basic_legacy_session_opts.raw_hmac = true
        opts.basic_legacy_session_opts.check = { hmac = false }
      else
        opts.basic_legacy_session_opts = {
          basic = true,
          raw_hmac = true,
          check = {
            hmac = false
          }
        }
      end

      ngx.log(ngx.DEBUG, "attempting legacy basic auth")
      session, valid = require("resty.session").open(opts.basic_legacy_session_opts)

      local leave_session_id = opts.leave_session_id
      opts.leave_session_id = true

      -- check if we need to refresh the token
      if session and valid and opts.refresh_access_token == "yes" then
        local res, err = openidc_refresh_token(opts, session)
        if err or not res then
          valid = false
        else
          opts.refresh_access_token = "no"
        end
      end

      -- if a session isn't present or bad password (might have been changed) then attempt to setup a new session using the provided credentials (if it fails to setup a new session the old one will remain untouched)
      if not session or not valid then
        local json, err = openidc.get_token_from_basic_auth(opts, session)
        if not err then
          session, valid = require("resty.session").open(opts.basic_legacy_session_opts)
          opts.refresh_access_token = "no"
        end
      end

      opts.leave_session_id = leave_session_id
    elseif opts.basic_auth == true then
      if type(opts.basic_session_opts) == "table" then
        opts.basic_session_opts.basic = true
        opts.basic_session_opts.check = {
          ssi = false,
          ua = false,
          scheme = false,
          addr = false
        }
      else
        opts.basic_session_opts = {
          basic = true,
          check = {
            ssi = false,
            ua = false,
            scheme = false,
            addr = false
          }
        }
      end

      ngx.log(ngx.DEBUG, "attempting basic auth")
      session, valid = require("resty.session").open(opts.basic_session_opts)

      -- check if we need to refresh the token
      if session and valid then
        local res, err = openidc_refresh_token(opts, session)
        if err or not res then
          valid = false
        else
          opts.refresh_access_token = "no"
        end
      end
    end
  end

  -- if basic auth didnt succeed (or isnt even enabled) then try standard authorization code flow if standard_flow is enabled
  if not session or not valid then
    if opts.standard_flow ~= false then
      ngx.log(ngx.DEBUG, "attempting standard auth flow")
      session, valid = require("resty.session").open(opts.session_opts)
    else
      if opts.basic_auth == true or opts.basic_auth_legacy == true then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.header["Content-type"] = "text/html"
        ngx.header["WWW-Authenticate"] = 'Basic realm="' .. ngx.var.realm .. '"'
        ngx.say("No valid Authorization header found and standard flow authentication disabled")
        ngx.exit(ngx.HTTP_OK)
      else
        ngx.log(ngx.ERR, "No valid authentication method enabled: standard_flow=", opts.standard_flow, " basic_auth=", opts.basic_auth, " basic_auth_legacy=", opts.basic_auth_legacy)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
      end
    end
  end

  -- see if this is a request to the redirect_uri i.e. an authorization response
  local path = target_url:match("(.-)%?") or target_url
  if path == opts.redirect_uri_path then
    -- try openidc_authorization_response
    local resp, err, original_url = openidc_authorization_response(opts, session)

    -- if openidc_authorization_response succeeded then it would have sent an ngx.redirect, if we get this far then something went wrong
    -- if reauthenticate_on_failure isnt enabled then return the response immediately
    -- if we've retried too many times already then dont attempt reauthentication and instead reset retry count back to 0 and return an error
    local max_auth_retries = opts.max_auth_retries or 3
    if opts.reauthenticate_on_failure ~= "yes" or (session.data.retries and session.data.retries >= max_auth_retries) then
      ngx.log(ngx.ERR, "authorization response failed, returning error (retry: ", session.data.retries, "/", max_auth_retries, ")")
      session.data.retries = 0
      session:save()
      return resp, err, original_url
    end

    -- authorization failed for some reason (no session, invalid session due to state mismatch etc), retry rauthentication if target url can be determined
    if target_url ~= ngx.var.request_uri then
      err = "authorization response on redirect_uri_path failed, re-auth to target_url provided to authenticate(): " .. target_url
    elseif ngx.var.arg_target then
      target_url = ngx.unescape_uri(ngx.var.arg_target)
      err = "authorization response on redirect_uri_path failed, re-auth to target_url from target arg: " .. target_url
    elseif session.data.original_url then
      target_url = session.data.original_url
      err = "authorization response on redirect_uri_path failed, re-auth to target_url from session original_url: " .. target_url
    else
      ngx.log(ngx.ERR, "authorization response on redirect_uri_path failed, cannot re-auth as no target_url could be determined")
      return resp, err, original_url
    end

    -- if there is already a token in this session then redirect back to target url as the client may have logged in from another tab
    if session.data.id_token then
      ngx.redirect(target_url)
    end

    -- if we reach here then we're re-authing so increment retry count
    session.data.retries = (session.data.retries or 0) + 1
    ngx.log(ngx.ERR, err)
  end

  -- see if this is a request to logout
  if path == (opts.logout_path and opts.logout_path or "/logout") then
    return openidc_logout(opts, session)
  end

  -- if we have an access_token then check if we need to refresh it (if enabled)
  if opts.refresh_access_token == "yes" and session.data.access_token then
    local res, err = openidc_refresh_token(opts, session)
    if err or not res then
      -- if refreshing failed for any reason (including expired session) then regenerate and
      -- flush the session which will cause authenticate() to redirect the user for authorization
      session:regenerate(true)
    end
  end

  -- if we have no id_token then redirect to the OP for authentication
  if not session.present or not session.data.id_token then
    if opts.redirect_to_auth == "no" or opts.standard_flow == false then
      -- return a 401 instead of setting up session and redirecting to authorization endpoint
      if opts.basic_auth == true or opts.basic_auth_legacy == true then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.header["Content-type"] = "text/html"
        ngx.header["WWW-Authenticate"] = 'Basic realm="' .. ngx.var.realm .. '"'
        ngx.say("Unauthorized")
      end
      ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    return openidc_authorize(opts, session, target_url)
  end

  -- log id_token contents
  ngx.log(ngx.DEBUG, "id_token=", cjson.encode(session.data.id_token))

  -- if SameSite was disabled and this is the first time the cookie has been used after session initialization then check the request and send a new cookie
  if session.data.initcookie == true then
    -- SameSite has not been applied to this session yet so only accept GET or HEAD requests
    if ngx.var.request_method ~= "GET" and ngx.var.request_method ~= "HEAD" then
      ngx.log(ngx.ERR, "initcookie is true, denying request to request_uri (" ..ngx.var.request_uri.. ") as the request method (" ..ngx.var.request_method.. ") is not allowed for an initcookie: request_id=" ..ngx.var.request_id)
      ngx.exit(ngx.HTTP_NOT_ALLOWED)
    end

    -- if the request is to the original URL then resend the cookie
    if ngx.var.request_uri == session.data.original_url then
      ngx.log(ngx.DEBUG, "initcookie is true, resending cookie: request_method=" ..ngx.var.request_method.. " request_uri=" ..ngx.var.request_uri.. " original_url=" ..session.data.original_url.. " request_id=" ..ngx.var.request_id)
      session.data.initcookie = nil
      session:save()
    else
      ngx.log(ngx.ERR, "initcookie is true, denying request to request_uri (" ..ngx.var.request_uri.. ") as it does not match original_url in session (" ..session.data.original_url.. "): request_id=" ..ngx.var.request_id)
      ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
  end

  -- return the id_token to the caller Lua script for access control purposes
  return
    {
      id_token=session.data.id_token,
      access_token=session.data.access_token,
      user=session.data.user
    },
    err,
    target_url
end

-- get an OAuth 2.0 bearer access token from the HTTP request
local function openidc_get_bearer_access_token(opts)

  local err

  -- get the access token from the Authorization header
  local headers = ngx.req.get_headers()
  local header =  headers['Authorization']

  if header == nil or header:find(" ") == nil then
    err = "no Authorization header found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  local divider = header:find(' ')
  if string.lower(header:sub(0, divider-1)) ~= string.lower("Bearer") then
    err = "no Bearer authorization header value found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  local access_token = header:sub(divider+1)
  if access_token == nil then
    err = "no Bearer access token value found"
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  return access_token, err
end

-- main routine for OAuth 2.0 token introspection
function openidc.introspect(opts)

  -- get the access token from the request
  local access_token, err = openidc_get_bearer_access_token(opts)
  if access_token == nil then
    return nil, err
  end

  -- see if we've previously cached the introspection result for this access token
  local json
  local v = openidc_cache_get("introspection", access_token)
  if not v then

    -- assemble the parameters to the introspection (token) endpoint
    local token_param_name = opts.introspection_token_param_name and opts.introspection_token_param_name or "access_token"

    local body = {}

    body[token_param_name]= access_token

    if opts.client_id then
      body.client_id=opts.client_id
    end
    if opts.client_secret then
      body.client_secret=opts.client_secret
    end

    -- merge any provided extra parameters
    if opts.introspection_params then
      for k,v in pairs(opts.introspection_params) do body[k] = v end
    end

    -- call the introspection endpoint
    json, err = openidc_call_token_endpoint(opts, opts.introspection_endpoint, body, nil)

    -- cache the results
    if json then
      local expiry_claim = opts.expiry_claim or "expires_in"
      local ttl = json[expiry_claim]
      if expiry_claim == "exp" then --https://tools.ietf.org/html/rfc7662#section-2.2
        ttl = ttl - ngx.time()
      end
      openidc_cache_set("introspection", access_token, cjson.encode(json), ttl)
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

-- main routine for OAuth 2.0 JWT token validation
function openidc.jwt_verify(access_token, opts)
  local err
  local json

  -- see if we've previously cached the validation result for this access token
  local v = openidc_cache_get("introspection", access_token)
  if not v then

    -- do the verification first time
    local jwt = require "resty.jwt"

    -- No secret given try getting it from the jwks endpoint
    if not opts.secret and opts.discovery then
      ngx.log(ngx.DEBUG, "bearer_jwt_verify using discovery.")
      opts.discovery, err = openidc_discover(opts.discovery, opts.ssl_verify)
      if err then
        return nil, err
      end

      -- We decode the token twice, could be saved
      local jwt_obj = jwt:load_jwt(access_token, nil)

      if not jwt_obj.valid then
        return nil, "invalid jwt"
      end

      opts.secret, err = pem_from_jwk(opts, jwt_obj.header.kid)

      if opts.secret == nil then
        return nil, err
      end
    end

    json = jwt:verify(opts.secret, access_token)

    ngx.log(ngx.DEBUG, "jwt: ", cjson.encode(json))

    -- cache the results
    if json and json.valid == true and json.verified == true then
      json = json.payload
      openidc_cache_set("introspection", access_token, cjson.encode(json), json.exp - ngx.time())
    else
      err = "invalid token: ".. json.reason
    end

  else
    -- decode from the cache
    json = cjson.decode(v)
  end

  -- check the token expiry
  if json then
    if json.exp and json.exp < ngx.time() then
      ngx.log(ngx.ERR, "token expired: json.exp=", json.exp, ", ngx.time()=", ngx.time())
      err = "JWT expired"
    end
  end

  return json, err
end

function openidc.bearer_jwt_verify(opts)
  local err
  local json

  -- get the access token from the request
  local access_token, err = openidc_get_bearer_access_token(opts)
  if access_token == nil then
    return nil, err
  end

  ngx.log(ngx.DEBUG, "access_token: ", access_token)

  return openidc.jwt_verify(access_token, opts)
end

return openidc
