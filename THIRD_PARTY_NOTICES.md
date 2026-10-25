# Third-party notices

SuckerPot ships a few pieces of third-party material. Software dependencies keep their own licences (see each package's lockfile); this file covers data that is bundled in the repository.

## Common passwords list

`api/api/data/common-passwords.txt` lists 1000 very common passwords (12 characters or longer), used to refuse weak dashboard passwords. It is a filtered copy of the "100k most used passwords" list of the UK National Cyber Security Centre (NCSC).

- Contains public sector information licensed under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).
- Obtained from the [SecLists](https://github.com/danielmiessler/SecLists) project (`Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt`), which is distributed under the MIT licence. Copyright (c) Daniel Miessler and contributors.
- Changes: only entries of at least 12 characters, ASCII only, lower-cased, duplicates removed, the first 1000 by frequency kept.
