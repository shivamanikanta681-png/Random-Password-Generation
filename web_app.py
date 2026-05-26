import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from src.generator import (
    PasswordGenerationError,
    calculate_entropy,
    generate_passphrase,
    generate_password,
    get_character_pool,
    load_words,
    rate_entropy,
)


HOST = "127.0.0.1"
PORT = 8000


HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Password Generator</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --ink: #16202a;
      --muted: #657181;
      --line: #d9dee8;
      --accent: #0f766e;
      --accent-dark: #115e59;
      --warn: #b45309;
      --shadow: 0 18px 50px rgba(24, 35, 52, 0.12);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
      display: grid;
      place-items: center;
      padding: 32px 16px;
    }

    main {
      width: min(880px, 100%);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    header {
      padding: 28px 32px 20px;
      border-bottom: 1px solid var(--line);
    }

    h1 {
      margin: 0 0 8px;
      font-size: clamp(28px, 4vw, 44px);
      font-weight: 760;
      line-height: 1.05;
      letter-spacing: 0;
    }

    p {
      margin: 0;
      color: var(--muted);
      line-height: 1.55;
    }

    .content {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(280px, 0.75fr);
      gap: 28px;
      padding: 28px 32px 32px;
    }

    form, .result {
      display: grid;
      gap: 18px;
      align-content: start;
    }

    label {
      display: grid;
      gap: 7px;
      color: #263241;
      font-weight: 650;
      font-size: 14px;
    }

    input[type="number"], input[type="text"], select {
      width: 100%;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 11px;
      font: inherit;
      color: var(--ink);
      background: #fff;
    }

    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }

    .checks {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }

    .check {
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      display: flex;
      gap: 8px;
      align-items: center;
      font-weight: 620;
      color: #293747;
    }

    button {
      min-height: 46px;
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: white;
      font: inherit;
      font-weight: 750;
      cursor: pointer;
    }

    button:hover { background: var(--accent-dark); }

    .output {
      min-height: 112px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      background: #fbfcfe;
      display: grid;
      align-content: center;
      gap: 10px;
    }

    .password {
      font-family: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
      overflow-wrap: anywhere;
      font-size: 19px;
      font-weight: 750;
    }

    .meter {
      height: 10px;
      border-radius: 999px;
      overflow: hidden;
      background: #e7ebf1;
    }

    .bar {
      height: 100%;
      width: 0;
      background: var(--accent);
      transition: width 180ms ease;
    }

    .meta {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      color: var(--muted);
      font-size: 14px;
    }

    .error {
      color: var(--warn);
      font-weight: 700;
    }

    @media (max-width: 720px) {
      .content, .row, .checks {
        grid-template-columns: 1fr;
      }

      header, .content {
        padding-left: 20px;
        padding-right: 20px;
      }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Secure Password Generator</h1>
      <p>Generate cryptographically secure passwords or memorable passphrases with entropy scoring.</p>
    </header>
    <section class="content">
      <form id="generatorForm">
        <label>
          Mode
          <select name="mode">
            <option value="password">Password</option>
            <option value="passphrase">Passphrase</option>
          </select>
        </label>

        <div class="row">
          <label>
            Password length
            <input name="length" type="number" min="1" value="16">
          </label>
          <label>
            Passphrase words
            <input name="words" type="number" min="1" value="4">
          </label>
        </div>

        <label>
          Separator
          <input name="separator" type="text" value="-">
        </label>

        <div class="checks">
          <label class="check"><input name="letters" type="checkbox" checked> Letters</label>
          <label class="check"><input name="digits" type="checkbox" checked> Digits</label>
          <label class="check"><input name="special" type="checkbox" checked> Symbols</label>
        </div>

        <button type="submit">Generate</button>
      </form>

      <aside class="result">
        <div class="output">
          <div id="value" class="password">Click generate</div>
          <div class="meter"><div id="bar" class="bar"></div></div>
          <div class="meta">
            <span id="entropy">Entropy: --</span>
            <span id="rating">Rating: --</span>
          </div>
          <div id="error" class="error"></div>
        </div>
      </aside>
    </section>
  </main>

  <script>
    const form = document.querySelector("#generatorForm");
    const value = document.querySelector("#value");
    const entropy = document.querySelector("#entropy");
    const rating = document.querySelector("#rating");
    const error = document.querySelector("#error");
    const bar = document.querySelector("#bar");

    async function generate(event) {
      event.preventDefault();
      const data = new FormData(form);
      const params = new URLSearchParams({
        mode: data.get("mode"),
        length: data.get("length"),
        words: data.get("words"),
        separator: data.get("separator"),
        letters: data.get("letters") === "on",
        digits: data.get("digits") === "on",
        special: data.get("special") === "on"
      });

      const response = await fetch(`/api/generate?${params}`);
      const result = await response.json();

      error.textContent = "";
      if (!response.ok) {
        error.textContent = result.error;
        value.textContent = "Could not generate";
        entropy.textContent = "Entropy: --";
        rating.textContent = "Rating: --";
        bar.style.width = "0";
        return;
      }

      value.textContent = result.value;
      entropy.textContent = `Entropy: ${result.entropy.toFixed(1)} bits`;
      rating.textContent = `Rating: ${result.rating}`;
      bar.style.width = `${Math.min(result.entropy, 140) / 140 * 100}%`;
    }

    form.addEventListener("submit", generate);
    form.requestSubmit();
  </script>
</body>
</html>
"""


class PasswordWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(HTML)
            return
        if parsed.path == "/api/generate":
            self._send_generation(parsed.query)
            return
        self.send_error(404, "Not found")

    def log_message(self, format, *args):
        return

    def _send_html(self, html):
        payload = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, payload, status=200):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_generation(self, query):
        params = parse_qs(query)
        mode = _first(params, "mode", "password")

        try:
            if mode == "passphrase":
                words = int(_first(params, "words", "4"))
                separator = _first(params, "separator", "-")
                generated = generate_passphrase(words, separator)
                entropy = calculate_entropy(words, len(load_words()))
            else:
                length = int(_first(params, "length", "16"))
                use_letters = _first(params, "letters", "true") == "true"
                use_digits = _first(params, "digits", "true") == "true"
                use_special = _first(params, "special", "true") == "true"
                generated = generate_password(
                    length=length,
                    use_letters=use_letters,
                    use_digits=use_digits,
                    use_special=use_special,
                )
                pool, _ = get_character_pool(use_letters, use_digits, use_special)
                entropy = calculate_entropy(len(generated), len(pool))

            self._send_json(
                {
                    "value": generated,
                    "entropy": entropy,
                    "rating": rate_entropy(entropy),
                }
            )
        except (PasswordGenerationError, ValueError) as error:
            self._send_json({"error": str(error)}, status=400)


def _first(params, key, default):
    return params.get(key, [default])[0]


def main():
    server = ThreadingHTTPServer((HOST, PORT), PasswordWebHandler)
    print(f"Open http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
