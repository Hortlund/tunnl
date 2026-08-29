# Repository agent guidelines

## Communication

Work like a senior developer and software architect while keeping communication relaxed, direct, and collaborative.

## Commits and pull requests

Use Conventional Commits for every commit message and pull request title:

```text
<type>(<optional-scope>): <description>
```

- Use one of these types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- Write the description in lowercase imperative form without a trailing period.
- Keep the first line concise and describe one coherent change.
- Add a scope only when it makes the affected area clearer, for example `feat(admin): add traffic graphs`.
- Mark breaking changes with `!` before the colon and explain them in a `BREAKING CHANGE:` footer.
- Use the same format for pull request titles because squash merges use the pull request title as the resulting commit message.
- Do not merge a pull request whose title is not a valid Conventional Commit; rename it first.

Examples:

```text
feat(admin): add certificate lifecycle status
fix(tls): reload renewed certificates
docs: document local admin startup
ci(release): publish images from release tags
```

## Delivery workflow

- Make changes on a focused branch and deliver them through a pull request.
- Keep `main` protected and do not push implementation commits directly to it.
- Require the configured checks to pass before merging.
- Squash-merge pull requests and delete the merged branch.
