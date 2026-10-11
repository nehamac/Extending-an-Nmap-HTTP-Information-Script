description = [[
Collects HTTP response information and checks for three
selected HTTP security headers.
]]

author = "Neha"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")

  if not response then
    return "Unable to receive an HTTP response."
  end

  local headers = response.header or {}
  local output = {}

  table.insert(output, "HTTP Information - Enhancement 2")
  table.insert(output, "Port: " .. port.number .. "/" .. port.protocol)
  table.insert(output, "HTTP Status Code: " ..
    tostring(response.status or "Unavailable"))
  table.insert(output, "Server: " .. (headers.server or "Not disclosed"))
  table.insert(output, "Content-Type: " ..
    (headers["content-type"] or "Not provided"))
  table.insert(output, "Date: " .. (headers.date or "Not provided"))

  table.insert(output, "HTTP Security Header Checks:")

  local checks = {
    {"Content-Security-Policy", "content-security-policy"},
    {"X-Content-Type-Options", "x-content-type-options"},
    {"Strict-Transport-Security", "strict-transport-security"}
  }

  for _, check in ipairs(checks) do
    local result = headers[check[2]] and "Present" or "Not detected"
    table.insert(output, check[1] .. ": " .. result)
  end

  return table.concat(output, "\n")
end
