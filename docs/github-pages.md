# Project website

The public website is a static GitHub Pages site. Its HTML, CSS and
brand image live in `website/`; it needs no package installation or build step.

Preview it locally from the repository root:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory website
```

Open <http://127.0.0.1:8080/>. Asset paths are relative, so the same files work at
the project URL, <https://emcrisostomo.github.io/dnie-macos/>.

## Publish

After reviewing and approving the exact public source commit, choose **GitHub Actions**
in the public repository's **Settings → Pages → Build and deployment → Source**.
The committed `.github/workflows/pages.yml` deploys only `website/` on relevant pushes
to `main`, or through **Actions → Publish project website → Run workflow**.
The `github-pages` environment can enforce deployment approval or branch protection.

The workflow uses immutable official action revisions, a read-only checkout job,
and a separate deployment job with only the Pages/OIDC permissions it needs. It
never builds the app, reads local terminal resources, signs packages or publishes
repository contents as the site artifact.

Keep experimental status and release availability accurate. See the
[branding and licensing notices](../LICENSES/README.md); the project does not
imply endorsement by Apple or the Spanish government.

[GitHub Pages workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
