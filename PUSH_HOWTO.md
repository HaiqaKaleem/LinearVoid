# Push and deploy this branch

## 1. What is ready right now

- Everything is committed locally on `freebuff/e76f9bac84e8c495968fc452`.
- CI (GitHub Actions) is in `.github/workflows/deploy.yml`.
- The push is failing in this environment because it tries to authenticate to
  `https://github.com/HaiqaKaleem1/hybrid-oidc.git` with an empty token.

## 2. Push from your own machine

You only need to do this once.

```bash
# From your own checkout of the repo:
cd hybrid-oidc
git fetch origin              # or whatever your remote is called
git checkout freebuff/e76f9bac84e8c495968fc452
git pull origin freebuff/e76f9bac84e8c495968fc452   # if GitHub already has it
git push origin freebuff/e76f9bac84e8c495968fc452
```

If you are cloning fresh on this machine, this is enough:

```bash
git clone https://github.com/HaiqaKaleem1/hybrid-oidc.git
cd hybrid-oidc
git checkout freebuff/e76f9bac84e8c495968fc452
git push origin freebuff/e76f9bac84e8c495968fc452
```

A personal access token (classic or fine-grained) with `repo` scope is what
`git push` over HTTPS needs. If you prefer SSH, use an SSH remote instead:
`git remote set-url origin git@github.com:HaiqaKaleem1/hybrid-oidc.git`.

## 3. What happens after the push

### GitHub Actions
Pushing to `freebuff/e76f9bac84e8c495968fc452` will start the workflow in
`.github/workflows/deploy.yml`. It will:

- check formatting
- run clippy
- run the full test suite
- build `hybrid-demo` in release mode

You can watch it under the Actions tab on the repo.

### No automatic deploy yet
The current workflow validates the code. It does not publish anything. If you
want an actual deploy target, pick one and I can wire it up:

- GitHub Pages for static docs/artifacts (does not run the demo server)
- A separate deploy workflow to whatever host you want to use for the demo

## 4. If you want me to keep working in this environment

Tell me a deploy target that does not need the GitHub push to succeed first
(for example, a local smoke test, or a different hosting service), and I can
keep going. I cannot push to GitHub from here until the environment has a
working credential.