package gate

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

func (g *powLoginGuard) ID() string {
	return "pow-login-guard"
}

func (g *powLoginGuard) Render(w http.ResponseWriter, r *http.Request, lang string, scriptNonce string) template.HTML {
	difficulty := g.resolveDifficulty(r)
	challenge, err := g.issueChallenge(w, r, difficulty)
	if err != nil {
		return template.HTML(fmt.Sprintf(
			`<div class="notice error">%s</div>`,
			template.HTMLEscapeString(g.translator.Text(lang, "pow_failed")),
		))
	}

	statusReady := template.JSEscapeString(g.translator.Text(lang, "pow_status_ready"))
	statusSolving := template.JSEscapeString(g.translator.Text(lang, "pow_status_solving"))
	statusWaiting := template.JSEscapeString(g.translator.Text(lang, "pow_status_waiting"))
	statusFailed := template.JSEscapeString(g.translator.Text(lang, "pow_failed"))
	statusUnsupported := template.JSEscapeString(g.translator.Text(lang, "pow_unsupported"))
	noscript := template.HTMLEscapeString(g.translator.Text(lang, "pow_noscript"))
	progressAttrs := `data-pow-progress`
	if g.progressMode == "hidden" {
		progressAttrs += ` hidden aria-hidden="true"`
	}

	return template.HTML(fmt.Sprintf(`
<div class="pow-box" data-pow-box>
  <div class="pow-status" data-pow-status>%s</div>
  <div class="pow-progress" %s>
    <div class="pow-progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" data-pow-progress-track>
      <div class="pow-progress-fill" data-pow-progress-fill></div>
    </div>
  </div>
  <input type="hidden" name="pow_id" value="%s">
  <input type="hidden" name="pow_token" value="%s">
  <input type="hidden" name="pow_nonce" value="">
  <input type="hidden" name="pow_difficulty" value="%d">
  <noscript><div class="notice error">%s</div></noscript>
</div>
<script nonce="%s">
(() => {
  const script = document.currentScript;
  if (!script) return;

  function init() {
    const form = script.closest("form");
    if (!form) return;
    const submitButton = form.querySelector('button[type="submit"]');
    const tokenInput = form.querySelector('input[name="pow_token"]');
    const nonceInput = form.querySelector('input[name="pow_nonce"]');
    const difficultyInput = form.querySelector('input[name="pow_difficulty"]');
    const statusNode = form.querySelector('[data-pow-status]');
    const progressContainer = form.querySelector('[data-pow-progress]');
    const progressTrack = form.querySelector('[data-pow-progress-track]');
    const progressFill = form.querySelector('[data-pow-progress-fill]');
    if (!submitButton || !tokenInput || !nonceInput || !difficultyInput || !statusNode || !progressContainer || !progressTrack || !progressFill) return;

    const difficulty = Number(difficultyInput.value || "0");
    const zeroPrefix = "0".repeat(Math.max(0, difficulty));
    const expectedWork = difficulty <= 0 ? 1 : Math.pow(16, difficulty);
    const encoder = new TextEncoder();
    submitButton.disabled = true;
    const threadCount = Math.max(1, Math.min(8, Math.trunc(Math.max((navigator.hardwareConcurrency || 1) / 2, 1))));
    const workerBatchSize = 192;
    const progressMode = "%s";
    const minProgressUpdateMs = 100;
    const minProgressAttemptDelta = 1024;
    let lastProgressUpdateMs = 0;
    let lastProgressAttempts = 0;
    function setStatus(message, state) {
      statusNode.textContent = message;
      statusNode.dataset.state = state;
    }

    function renderProgress(percent) {
      const clamped = Math.max(0, Math.min(100, percent));
      progressFill.style.width = clamped.toFixed(1) + "%%";
      progressTrack.setAttribute("aria-valuenow", clamped.toFixed(1));
    }

    function canUseWorkers() {
      return Boolean(
        window.Worker &&
        window.Blob &&
        window.URL &&
        typeof window.URL.createObjectURL === "function"
      );
    }

    function revealSolvedProgress() {
      if (progressMode !== "hidden") {
        renderProgress(100);
        return;
      }

      progressContainer.hidden = false;
      progressContainer.removeAttribute("aria-hidden");
      renderProgress(0);
      progressFill.getBoundingClientRect();
      requestAnimationFrame(() => {
        renderProgress(100);
      });
    }

    setStatus("%s", "waiting");
    updateProgress(0, 0, false);

    function estimatedProgressPercent(attempts) {
      if (difficulty <= 0) return 100;
      const value = (1 - Math.exp(-attempts / expectedWork)) * 100;
      return Math.min(99.9, Math.max(0, value));
    }

    function fakeProgressPercent(elapsedSeconds) {
      const seed = tokenInput.value.length + difficulty * 17;
      const ramp = 16 + 72 * (1 - Math.exp(-(elapsedSeconds + 0.4) / 1.8));
      const wobble = (Math.sin(elapsedSeconds * 1.7 + seed) + 1) * 2.4;
      return Math.min(98.9, Math.max(2, ramp + wobble));
    }

    function shouldRenderProgress(attempts, elapsedSeconds, solved) {
      if (solved || progressMode !== "estimated") {
        lastProgressUpdateMs = elapsedSeconds * 1000;
        lastProgressAttempts = attempts;
        return true;
      }

      const elapsedMs = elapsedSeconds * 1000;
      const attemptsDelta = attempts - lastProgressAttempts;
      const elapsedDeltaMs = elapsedMs - lastProgressUpdateMs;
      if (attemptsDelta < minProgressAttemptDelta || elapsedDeltaMs < minProgressUpdateMs) {
        return false;
      }

      lastProgressUpdateMs = elapsedMs;
      lastProgressAttempts = attempts;
      return true;
    }

    function updateProgress(attempts, elapsedSeconds, solved) {
      if (progressMode === "hidden") {
        if (solved) {
          revealSolvedProgress();
        }
        return;
      }
      if (!shouldRenderProgress(attempts, elapsedSeconds, solved)) {
        return;
      }

      let percent = 100;
      if (!solved) {
        percent = progressMode === "fake" ? fakeProgressPercent(elapsedSeconds) : estimatedProgressPercent(attempts);
      }
      renderProgress(percent);
    }

    async function sha256Hex(text) {
      const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
      return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    }

    async function solveSingleThread() {
      let nonce = 0;
      const startedAt = performance.now();
      while (true) {
        for (let i = 0; i < 200; i += 1, nonce += 1) {
          const hash = await sha256Hex(tokenInput.value + ":" + nonce);
          if (hash.startsWith(zeroPrefix)) {
            return { nonce, elapsedSeconds: (performance.now() - startedAt) / 1000 };
          }
        }
        updateProgress(nonce, (performance.now() - startedAt) / 1000, false);
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    async function solveWithWorkers() {
      const workerSource = [
        'const encoder = new TextEncoder();',
        'function toHex(bytes) {',
        '  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");',
        '}',
        'function hasLeadingZeroNibbles(bytes, difficulty) {',
        '  if (difficulty <= 0) return true;',
        '  const fullBytes = Math.floor(difficulty / 2);',
        '  for (let i = 0; i < fullBytes; i += 1) {',
        '    if (bytes[i] !== 0) return false;',
        '  }',
        '  if ((difficulty & 1) === 1) {',
        '    return (bytes[fullBytes] >> 4) === 0;',
        '  }',
        '  return true;',
        '}',
        'async function sha256Bytes(text) {',
        '  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));',
        '}',
        'self.onmessage = async (event) => {',
        '  const { token, difficulty, startNonce, step, batchSize, reportProgress } = event.data;',
        '  let nonce = startNonce;',
        '  let iterations = 0;',
        '  for (;;) {',
        '    for (let i = 0; i < batchSize; i += 1, nonce += step) {',
        '      const hashBytes = await sha256Bytes(token + ":" + nonce);',
        '      if (hasLeadingZeroNibbles(hashBytes, difficulty)) {',
        '        self.postMessage({ type: "solved", nonce, hash: toHex(hashBytes) });',
        '        return;',
        '      }',
        '      iterations += 1;',
        '      if (reportProgress && (iterations & 1023) === 0) {',
        '        self.postMessage({ type: "progress", attempts: nonce + step });',
        '      }',
        '    }',
        '  }',
        '};',
      ].join("\n");

      const workerURL = URL.createObjectURL(new Blob([workerSource], { type: "text/javascript" }));
      const startedAt = performance.now();

      return await new Promise((resolve, reject) => {
        const workers = [];
        let settled = false;

        function cleanup() {
          if (settled) {
            return;
          }
          settled = true;
          for (const worker of workers) {
            worker.terminate();
          }
          URL.revokeObjectURL(workerURL);
        }

        for (let index = 0; index < threadCount; index += 1) {
          const worker = new Worker(workerURL);
          worker.onmessage = (event) => {
            if (settled) {
              return;
            }
            const data = event.data || {};
            if (data.type === "progress") {
              updateProgress(Number(data.attempts || 0), (performance.now() - startedAt) / 1000, false);
              return;
            }
            if (data.type === "solved") {
              cleanup();
              resolve({ nonce: Number(data.nonce || 0), elapsedSeconds: (performance.now() - startedAt) / 1000 });
            }
          };
          worker.onerror = () => {
            if (settled) {
              return;
            }
            cleanup();
            reject(new Error("pow_worker_failed"));
          };
          worker.postMessage({
            token: tokenInput.value,
            difficulty,
            startNonce: index,
            step: threadCount,
            batchSize: workerBatchSize,
            reportProgress: index === 0,
          });
          workers.push(worker);
        }
      });
    }

    async function solve() {
      setStatus("%s", "running");
      let result = null;
      if (canUseWorkers() && threadCount > 1) {
        try {
          result = await solveWithWorkers();
        } catch (error) {
          console.warn("PoW worker path failed, falling back to single thread", error);
        }
      }
      if (!result) {
        result = await solveSingleThread();
      }

      nonceInput.value = String(result.nonce);
      submitButton.disabled = false;
      updateProgress(result.nonce + 1, result.elapsedSeconds, true);
      setStatus("%s", "ready");
    }

    form.addEventListener("submit", (event) => {
      if (!nonceInput.value) {
        event.preventDefault();
        setStatus("%s", "waiting");
      }
    });

    if (!window.crypto || !window.crypto.subtle || !window.TextEncoder) {
      setStatus("%s", "unsupported");
      return;
    }

    solve().catch(() => {
      setStatus("%s", "failed");
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
</script>`,
		template.HTMLEscapeString(g.translator.Text(lang, "pow_status_waiting")),
		progressAttrs,
		template.HTMLEscapeString(challenge.id),
		template.HTMLEscapeString(challenge.token),
		difficulty,
		noscript,
		template.HTMLEscapeString(scriptNonce),
		template.JSEscapeString(g.progressMode),
		statusWaiting,
		statusSolving,
		statusReady,
		statusWaiting,
		statusUnsupported,
		statusFailed,
	))
}

func (g *powLoginGuard) Validate(r *http.Request, lang string) error {
	challengeID := strings.TrimSpace(r.FormValue("pow_id"))
	token := strings.TrimSpace(r.FormValue("pow_token"))
	nonce := strings.TrimSpace(r.FormValue("pow_nonce"))
	if challengeID == "" || token == "" || nonce == "" {
		return localizedUserError{key: "pow_missing", status: http.StatusForbidden}
	}
	if len(challengeID) > 128 {
		return localizedUserError{key: "pow_invalid", status: http.StatusForbidden}
	}
	if len(nonce) > 128 {
		return localizedUserError{key: "pow_invalid", status: http.StatusForbidden}
	}

	browserSessionKey, err := g.browserSessionKeyFromRequest(r)
	if err != nil {
		return err
	}
	return g.store.Consume(browserSessionKey, challengeID, token, nonce)
}

func (g *powLoginGuard) OnLoginSuccess(r *http.Request) {}

func (g *powLoginGuard) OnLoginFailure(r *http.Request, lang string) error {
	return nil
}

func (g *powLoginGuard) issueChallenge(w http.ResponseWriter, r *http.Request, difficulty int) (powChallenge, error) {
	browserSessionKey, err := g.ensureBrowserSession(w, r)
	if err != nil {
		return powChallenge{}, err
	}
	return g.store.Issue(browserSessionKey, difficulty, g.ttl)
}

func (g *powLoginGuard) resolveDifficulty(r *http.Request) int {
	difficulty := g.baseDifficulty
	if g.autoDifficulty {
		difficulty += powDifficultyDelta(r, g.autoRules, g.suspiciousUATokens)
		difficulty = clampInt(difficulty, g.minDifficulty, g.maxDifficulty)
	}
	if difficulty < 0 {
		return 0
	}
	return difficulty
}

func (g *powLoginGuard) ensureBrowserSession(w http.ResponseWriter, r *http.Request) (string, error) {
	if cookie, err := r.Cookie(g.cookieName); err == nil && g.signer.Verify(cookie.Value) {
		return g.browserSessionKey(cookie.Value), nil
	}

	token, err := g.signer.Issue(g.ttl)
	if err != nil {
		return "", fmt.Errorf("issue pow browser session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     g.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   g.secureDecider(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(g.ttl.Seconds()),
		Expires:  g.now().Add(g.ttl),
	})
	return g.browserSessionKey(token), nil
}

func (g *powLoginGuard) browserSessionKeyFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(g.cookieName)
	if err != nil {
		return "", localizedUserError{key: "pow_missing", status: http.StatusForbidden}
	}
	if !g.signer.Verify(cookie.Value) {
		return "", localizedUserError{key: "pow_invalid", status: http.StatusForbidden}
	}
	return g.browserSessionKey(cookie.Value), nil
}

func (g *powLoginGuard) browserSessionKey(token string) string {
	sum := sha256.Sum256([]byte("pow-browser:" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
