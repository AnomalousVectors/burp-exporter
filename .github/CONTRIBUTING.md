# Contributing

Thanks for your interest in contributing.

## Before You Start

- Use Discussions for questions and design discussion
- Use Issues for bugs and feature requests
- Use GitHub Private Vulnerability Reporting for security issues
- Read the [README](../README.md) for project context and the [repository wiki](../../../wiki) for user-facing documentation
- Prefer the issue forms so reports include the triage details maintainers need

## Contribution Guidelines

- Keep changes minimal and focused
- Do not modify unrelated code
- Preserve existing formatting, structure, and layout
- Follow existing naming and project conventions
- Discuss larger changes before opening a pull request
- Prefer small pull requests that are easy to review and test

## Testing

For Gradle commands, static analysis checks, and local vs CI OpenSearch integration test notes, see the repository wiki [Contributor Guide](https://github.com/AnomalousVectors/burp-exporter/wiki/Contributor-Guide).

- For code changes, run the full test and build from the repository root:
  - Add opensearch.url to your host file and point to your configured OpenSearch instance.
  - Run `gradle clean build -POPENSEARCH_USER=admin -POPENSEARCH_PASSWORD=<yourPassword>`
- Ensure the extension loads in Burp Suite without errors
- Validate UI changes visually
- Include reproduction steps for bug fixes where applicable
- Prefer `build/tmp/...` for test-created files and directories instead of raw OS temp locations

## Good Reports and PRs

- Good bug reports usually include:
  - Burp version and edition
  - Java version and OS
  - Whether export was running
  - Whether the issue affected OpenSearch, file export, or both
  - Sanitized logs, screenshots, and relevant config details
- Good feature requests usually explain:
  - The operator problem or workflow gap
  - The expected user value
  - Which areas are affected, such as UI, export destinations, or schema
- Good pull requests usually call out:
  - User-facing impact
  - Config or schema changes
  - Any Burp-edition-specific behavior

## Pull Requests

- Clearly describe what changed and why
- Reference related issues or discussions if applicable
- Include screenshots for UI changes
- Call out any OpenSearch, file-export, or Burp-edition-specific behavior changes