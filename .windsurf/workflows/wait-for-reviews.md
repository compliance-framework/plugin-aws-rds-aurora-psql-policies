find the current PR number with pr_number=$(gh pr view --json number --jq '.number')
find the current repo owner with repo_owner=$(gh pr view --json headRepositoryOwner --jq .headRepositoryOwner.login)

Get the current unresolved review threads with `gh pr-review review view --unresolved -R $repo_owner $pr_number

Address them. Focus on doing minimal changes. Focus on making sure test coverage is up to date if needed. Focus on reusing existing code if possible.

After Addressing them, commit the changes with `git add -A && git commit -m "fix: copilot issues"`

Push the changes with `git push`

For each open thread - Resolve them with `gh pr-review threads resolve <thread id>`. Beware you need to close each thread individually

Ask for a new copilot review with `gh pr edit $pr_number --add-reviewer @copilot`