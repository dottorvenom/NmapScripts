local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
Identifica server Microsoft SharePoint cercando indicatori nel body HTML

I tag controllati all'interno del codice sono case sensitive
]]

author = "dinbar78@gmail.com - dottorvenom"
license = "https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return shortport.port_or_service({80, 443}, {"http", "https"})(host, port)
end

action = function(host, port)
  local headers = {
    ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"
  }

  local response = http.get(host, port, "/", {header = headers})
  if not response or not response.body then
    return "Errore: HTTP response non valida"
  end


  local body = response.body
  local output = {}

  if body:match("_layouts/15") then
    table.insert(output, "[+] Trovato '_layouts/15' --> possibile SharePoint")
  end
  
  if body:match("_VIEWSTATE") then
    table.insert(output, "[+] Trovato '_VIEWSTATE' --> uso ASP.NET")
  end

  if body:match('<meta%s+name=["\']GENERATOR["\']%s+content=["\']Microsoft SharePoint["\']') then
    table.insert(output, "[+] Meta tag SharePoint trovato")
  end

  if body:match("WebResource.axd") then
    table.insert(output, "[+] Trovato 'WebResource' --> possibile SharePoint")
  end


  if #output > 0 then
    return stdnse.format_output(true, output)
  else
    return "[-] SharePoint non rilevato"
  end
end
