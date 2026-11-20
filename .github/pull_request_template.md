## Summary

Describe what changed and why.

## Impact

- User-facing impact:
- Config or schema impact:
- Breaking change: Yes / No

## Testing

- [ ] Passed full build:
  - Add opensearch.url to your host file and point to your configured OpenSearch instance.
  - Run `./gradlew clean build -POPENSEARCH_USER=admin "-POPENSEARCH_PASSWORD=<yourPassword>"` (on Windows, replace `./gradlew` with `.\gradlew.bat`).
- [ ] Loaded successfully in Burp Suite
- [ ] UI changes validated visually
- [ ] No unrelated files were modified

## Release Notes

- User-facing notes:
- Migration or follow-up notes:

## Notes

Add any relevant context, screenshots, or follow-up details here.
