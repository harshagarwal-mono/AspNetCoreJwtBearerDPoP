# Building and releasing

Maintainers use these steps to build, pack, and publish to NuGet.org. This file is not included in the NuGet package readme.

Preferred path: **Trusted Publishing** via GitHub Actions (no long-lived API key in the repo). Manual API-key push remains available as a fallback.

## Build and test (local)

```bash
dotnet build -c Release
dotnet test -c Release
```

## Pack (local)

```bash
dotnet pack -c Release -o artifacts -p:Version=1.0.0
```

`dotnet pack` also writes a `.snupkg` symbol package next to each `.nupkg`. The default version prefix is `1.0.0` from `Directory.Build.props`.

## Publish with Trusted Publishing (recommended)

Uses GitHub’s hosted runner (`ubuntu-latest`) and OIDC. No self-hosted runner and no NuGet API key secret.

### One-time setup

1. Sign in at [nuget.org](https://www.nuget.org).
2. Open **username → Trusted Publishing → Add**.
3. Create a policy matching this repo’s release workflow:
   - **Repository owner:** `harshagarwal-mono`
   - **Repository:** `AspNetCoreJwtBearerDPoP`
   - **Workflow file:** `release.yml` (filename only; not `.github/workflows/...`)
   - **Environment:** leave empty (this workflow does not use a GitHub Environment)
4. In the GitHub repo: **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `NUGET_USER`
   - Value: your **nuget.org username** (profile name), not your email

### Release a version

1. Merge the code you want to ship to the default branch.
2. On GitHub: **Releases → Draft a new release**.
3. Create a tag such as `v1.0.0` (leading `v` is stripped for the package version).
4. Publish the release.

That runs [`.github/workflows/release.yml`](../.github/workflows/release.yml): test → pack → `NuGet/login@v1` (OIDC) → `dotnet nuget push`.

You can also run the workflow manually: **Actions → Release → Run workflow** and enter a version like `1.0.0`.

### First-time package ownership

The nuget.org account used as `NUGET_USER` must be allowed to push these package IDs. For a brand-new ID, the first successful push creates the packages under that account.

## Publish with an API key (manual fallback)

1. Sign in at [nuget.org](https://www.nuget.org) and create an API key (**username → API Keys → Create**).
2. Scope the key to **Push** (and new package versions as needed). A package glob such as `AspNetCoreJwtBearerDPoP*` covers both packages.
3. Push (do not commit the key):

```bash
dotnet nuget push "artifacts/*.nupkg" --api-key <your-nuget-api-key> --source https://api.nuget.org/v3/index.json
```

Pushing the `.nupkg` also publishes matching symbols when they were produced next to it.

## Package readme

NuGet.org shows the repository root [`README.md`](../README.md), which is packed via `PackageReadmeFile` in `src/Directory.Build.props`. Keep install and usage docs there; keep release steps in this file.
