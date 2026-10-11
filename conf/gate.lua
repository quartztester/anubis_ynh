-- Anubis YunoHost gate (rewrite phase, i.e. BEFORE ssowat's access phase).
-- Referenced by /etc/nginx/conf.d/<domain>.d/zz-anubis.conf for each protected
-- domain. Managed file - do not edit by hand.
--
-- Calls Anubis' /api/check over a Lua cosocket rather than
-- ngx.location.capture, because capture rejects HTTP/2 requests ("http2
-- requests not supported yet") and YunoHost vhosts speak HTTP/2.

local uri = ngx.var.uri
local host = ngx.var.host

-- Never gate ACME or the YunoHost portal/admin/api.
if uri:find("^/%.well%-known/") or uri:find("^/yunohost/") then
    return
end

-- If the GUI ever ends up on a subpath, keep it reachable so admins can
-- always toggle protection back off. (At path=/ the GUI host can never be a
-- protected domain; apply.py enforces that.)
local guard_host = "__GUARD_DOMAIN__"
local guard_prefix = "__GUARD_PREFIX__"
if guard_prefix ~= "" and host == guard_host and
   (uri == guard_prefix or uri:sub(1, #guard_prefix + 1) == guard_prefix .. "/") then
    return
end

-- Header values go verbatim into the check request: strip CR/LF.
local function clean(v)
    if not v then return "" end
    return (tostring(v):gsub("[\r\n]", " "))
end

local sock = ngx.socket.tcp()
sock:settimeouts(300, 500, 1500)

local connected, cerr = sock:connect("127.0.0.1", __PORT__)
if not connected then
    -- Anubis down: fail open rather than blackhole the site.
    ngx.log(ngx.WARN, "anubis gate: connect failed (", cerr, ") - failing open")
    return
end

local sent, serr = sock:send(
    "GET /.within.website/x/cmd/anubis/api/check HTTP/1.1\r\n" ..
    "Host: " .. clean(host) .. "\r\n" ..
    "X-Real-IP: " .. clean(ngx.var.anubis_client_ip) .. "\r\n" ..
    "X-Forwarded-Proto: " .. clean(ngx.var.scheme) .. "\r\n" ..
    "User-Agent: " .. clean(ngx.var.http_user_agent) .. "\r\n" ..
    "Accept: " .. clean(ngx.var.http_accept) .. "\r\n" ..
    "Referer: " .. clean(ngx.var.http_referer) .. "\r\n" ..
    "Cookie: " .. clean(ngx.var.http_cookie) .. "\r\n" ..
    "Connection: close\r\n\r\n")
if not sent then
    ngx.log(ngx.WARN, "anubis gate: send failed (", serr, ") - failing open")
    sock:close()
    return
end

local line = sock:receive("*l")
sock:close()

if not line then
    ngx.log(ngx.WARN, "anubis gate: no response from check - failing open")
    return
end

-- status line: "HTTP/1.1 401 Unauthorized"
local status = tonumber((line:match("^HTTP/%d%.%d%s+(%d+)")))

if status == 401 then
    local target = ngx.var.scheme .. "://" .. host .. ngx.var.request_uri
    return ngx.redirect("/.within.website/?redir=" .. ngx.escape_uri(target), 307)
elseif status == 403 then
    -- An explicit DENY rule (e.g. headless browser, AI crawler): block,
    -- do NOT fall through to ssowat (that would expose the login page).
    return ngx.exit(403)
elseif status and status >= 500 then
    ngx.log(ngx.WARN, "anubis gate: check returned ", status, " - failing open")
end
