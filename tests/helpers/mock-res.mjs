// Minimal Vercel-style response mock for unit-testing serverless handlers
// without spinning up a real HTTP server.

export function createMockRes() {
  const res = {
    statusCode: 200,
    headers: {},
    body: undefined,
    ended: false,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(key, value) {
      this.headers[key.toLowerCase()] = value;
      return this;
    },
    json(obj) {
      this.headers['content-type'] = 'application/json';
      this.body = obj;
      this.ended = true;
      return this;
    },
    send(data) {
      this.body = data;
      this.ended = true;
      return this;
    },
    end(data) {
      if (data !== undefined) this.body = data;
      this.ended = true;
      return this;
    },
  };
  return res;
}

export function createMockReq({ method = 'GET', body = undefined, headers = {}, query = {} } = {}) {
  return { method, body, headers, query };
}
