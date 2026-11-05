import http.server, os, socketserver

os.chdir(os.path.dirname(os.path.abspath(__file__)))

class Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.0"   # close every connection: no idle keep-alive sockets
    timeout = 10                    # drop stalled/speculative browser connections quickly
    def do_GET(self):
        if self.path.split("?")[0].rstrip("/") == "/admin117":
            self.path = "/index.html"
        super().do_GET()
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()
    def log_message(self, *a):
        pass

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True           # worker threads never block Ctrl+C / shutdown
    allow_reuse_address = True

if __name__ == "__main__":
    srv = Server(("", 8000), Handler)
    print("Learners: http://localhost:8000/   Admin: http://localhost:8000/admin117   (Ctrl+C to stop)")
    try:
        srv.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        print("Stopped.")
