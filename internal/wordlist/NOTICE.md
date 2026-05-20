# Wordlist Attribution

kembar bundles wordlists from [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists), the standard wordlist collection used by `ffuf`, `gobuster`, `dirsearch`, `feroxbuster`, and most other web pentest tools.

SecLists is distributed under the **MIT License**. Original source: <https://github.com/danielmiessler/SecLists>.

## Files bundled

| File | Upstream path | Lines | Used by |
|---|---|---|---|
| `seclists_common_paths.txt` | `Discovery/Web-Content/common.txt` | ~4750 | dir bruteforce |
| `seclists_quickhits.txt` | `Discovery/Web-Content/quickhits.txt` | ~2567 | sensitive-files |
| `seclists_default_passwords.csv` | `Passwords/Default-Credentials/default-passwords.csv` | ~2876 | default-creds (deep mode) |

The curated web-credentials list (`curatedWebCreds` in `wordlist.go`) is a small hand-picked subset emphasizing credentials that actually appear on web admin panels and CI tools — it is the default `kembar` uses to keep scans fast.

## License

```
MIT License

Copyright (c) 2014-2024 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```
