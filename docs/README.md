# Documentation and site assets

The files in this folder are the GitHub Pages site. `index.html` and
`styles.css` are plain static files, so there is no build step and nothing to
pay for. `.github/workflows/pages.yml` publishes this folder on every push to
`main`.

## 1. Logo image

The expected file is **`docs/logo.png`**. That exact name is used in two places:

- the root `README.md` as `docs/logo.png`
- `docs/index.html` as `src="logo.png"` (relative to this folder)

The HTML uses the alt text `MILAN logo for Monitored Incident & Log Audit Node`
and falls back to a plain `MILAN` wordmark if the image cannot load.

To replace the logo, drop a PNG at `docs/logo.png`. If you want a different
filename, update both references above. A square image around 512 × 512 px is
a good fit for the header; the site renders it at 44 × 44 px.

## 2. Banner and screenshot assets

Keep visual assets in this folder so the site and README can reference them
with relative paths. The expected names are:

| File | Used by | Notes |
| --- | --- | --- |
| `docs/logo.png` | Root `README.md`, `docs/index.html` | Header mark. See section 1. |
| `docs/demo.png` | Root `README.md` | Streamlit screenshot. Optional. |
| `docs/banner.png` | Not referenced yet | Drop a wide banner here if you want one. |

A banner is not wired into the HTML or README. If you add one and want it
displayed, add an `<img>` or GitHub's special `<picture>` block yourself and
use `banner.png` as the relative path. The existing `Github Banner.png` at the
repository root is not part of the Pages site; copy or rename it here first if
you want to use it.

To capture the demo screenshot:

1. Start the dashboard from the repository root:

   ```bash
   streamlit run src/ui/app.py
   ```

2. Submit a sample alert such as `ALT-1003 — prompt injection`.
3. At the HITL gate, capture the triage metrics and step traces.
4. Save the image as `docs/demo.png`.

Until `demo.png` exists, the README image link is broken. Either add the file
or remove that one line from the README. Commit any asset you add; the Pages
workflow publishes only files tracked in `docs/`.

## 3. Example walkthroughs

The site's "Three runs, start to finish" section uses cases from
`evals/datasets/full_benchmark.jsonl`:

- `ALT-2004`: an SSH brute force followed by a login. Intel and the asset record
  raise severity to critical, and the graph pauses with two pending containment
  proposals.
- `ALT-3002`: an internal scanner in a booked window. Low intel confidence and
  the asset record produce a benign verdict with no proposals.
- `ALT-4001`: a User-Agent carrying an instruction override and a request for a
  false-positive verdict. The sanitizer flags it, the verdict stays suspicious,
  and no action runs without approval.

Keep these summaries short if you edit them. They describe behaviour, not a
marketing pitch, and the records are synthetic.

## 4. Enable GitHub Pages

In the repository on GitHub.com:

1. Open **Settings → Pages**.
2. Under **Build and deployment**, set **Source** to **GitHub Actions**.
3. Push a commit to `main`, or run the **Deploy GitHub Pages** workflow from
   the Actions tab.

The workflow uploads this folder and deploys it. The live URL is reported in
the workflow run and also shown under Settings → Pages. No other settings are
needed for the site itself.

## Manual steps to check before release

- Set **Source** to **GitHub Actions** as described above.
- Confirm the Actions workflow has permission to write Pages; the workflow
  declares `pages: write` and `id-token: write` itself.
- Confirm the CI badge in the root README points at the intended repository.
- Add `docs/demo.png` if you want the README screenshot to resolve.
