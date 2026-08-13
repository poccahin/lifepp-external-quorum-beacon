## External CAI enrollment

- Enrollment request: `sha256:af751b72b1a80cdada836f00320e20ac59786eda3240a5ef1a72fe6ea96148c5`
- Submission path: `submissions/<persona-id>.json`
- GitHub account binding: immutable numeric database ID of this PR author

Checklist:

- [ ] This pull request changes exactly one signed enrollment JSON file.
- [ ] The response contains no private key, credential, token, seed phrase,
      raw identity document, biometric data, or other secret value.
- [ ] Every declaration and evidence reference is independently supportable.
- [ ] `github_account_id` exactly matches my immutable numeric GitHub database
      ID, encoded as a JSON string.
- [ ] I understand that a passing check is an integrity result only and grants
      no committee seat, protocol vote, source access, or production authority.
