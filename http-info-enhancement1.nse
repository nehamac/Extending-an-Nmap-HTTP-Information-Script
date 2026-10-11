description = [[
Collects HTTP response information and extracts the webpage title.
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
  local headers = response.header or {}

  table.insert(output, "HTTP Information - Enhancement 1")
  table.insert(output, "Port: " .. port.number .. "/" .. port.protocol)
  table.insert(output, "HTTP Status Code: " ..
    tostring(response.status or "Unavailable"))
  table.insert(output, "Server: " .. (headers.server or "Not disclosed"))
  table.insert(output, "Content-Type: " ..
    (headers["content-type"] or "Not provided"))
  table.insert(output, "Date: " .. (headers.date or "Not provided"))

  local title = "Not found"
  local body = response.body or ""
  local lower_body = string.lower(body)
  local start_pos, end_pos = string.find(lower_body, "<title[^>]*>")

  if start_pos and end_pos then
    local close_start = string.find(lower_body, "</title>", end_pos + 1, true)
    if close_start then
      title = string.sub(body, end_pos + 1, close_start - 1)
      title = string.gsub(title, "^%s+", "")
      title = string.gsub(title, "%s+$", "")
      if title == "" then
        title = "Empty title"
      end
    end
  end

  table.insert(output, "Page Title: " .. title)
  return table.concat(output, "\n")
end
