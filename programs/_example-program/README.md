# Example program (reference)

This folder shows the shape of a per-program scope. It is **not** a real program —
`scope.yaml` has `enrolled: false`, so `scope-authorization-guard` will refuse every target
here by design.

## Make a real one

```bash
cp -r programs/_example-program programs/<your-program>
# edit programs/<your-program>/scope.yaml:
#   - set program.name / handle / policy_url
#   - set enrolled: true   (only if you are actually enrolled)
#   - paste in_scope / out_of_scope verbatim from the HackerOne policy
```

Then, in the Sixth panel:

> `/scope-authorization-guard` confirm `app.<your-program>.com` is in scope for
> `<your-program>`, then `/bug-bounty-orchestrator` run a passive recon pass.

Evidence and draft reports for this program will be written to
`findings/<your-program>/` (git-ignored).
