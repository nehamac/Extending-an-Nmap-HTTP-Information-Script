description = [[
Collects basic information about an HTTP server.
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

  local output = {}

  table.insert(output, "HTTP Information")
  table.insert(output, "Port: " .. port.number .. "/" .. port.protocol)

  if response.status then
    table.insert(output, "HTTP Status Code: " .. response.status)
  end

  if response.header and response.header.server then
    table.insert(output, "Server: " .. response.header.server)
  end

  if response.header and response.header["content-type"] then
    table.insert(output, "Content-Type: " ..
      response.header["content-type"])
  end

  if response.header and response.header.date then
    table.insert(output, "Date: " .. response.header.date)
  end

  return table.concat(output, "\n")

end
