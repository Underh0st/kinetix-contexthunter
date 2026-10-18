# language: PowerShell, file: scripts/push_historyless.ps1, target: Windows PowerShell / pwsh
# Publishes the current state of the repository as a single root (orphan) commit,
# wiping all prior commit history on both local and remote (GitHub) so no previous
# changes or diffs are ever visible.

param(
    [string]$CommitMessage = "release: KINETIX by Oscar Emiliano Constanzo Quezada"
)

$ErrorActionPreference = "Stop"

Write-Host "[KINETIX] Rebuilding orphan branch to eliminate all prior commit history..."
git checkout --orphan clean_root_state
git add -A
git commit -m $CommitMessage
git branch -D main 2>$null
git branch -m main
git gc --prune=now --aggressive

$remotes = git remote
if ($remotes -contains "origin") {
    Write-Host "[KINETIX] Force-pushing single-commit state to origin/main (zero history)..."
    git push -f -u origin main
    Write-Host "[KINETIX] Done. Remote repository now has exactly 1 commit and zero history."
} else {
    Write-Host "[KINETIX] Local repository reset to 1 root commit (zero history). Add remote 'origin' to push."
}
