#!/usr/bin/env ruby
require 'webrick'
include WEBrick

class DummyServlet < HTTPServlet::AbstractServlet
  def do_GET(req, res)
    res.status = 200
    res['Content-Type'] = 'text/plain'
    res.body = "Hello, WEBRick\n"
  end
end

s = HTTPServer.new(:Port => 8888)
s.mount('/', HTTPServlet::FileHandler, "/var/www/html");
Signal.trap(:INT) {
  s.shutdown
}
s.start
