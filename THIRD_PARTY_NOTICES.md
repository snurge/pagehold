# Third-Party Notices

PageHold is licensed under `AGPL-3.0-only`. It depends on the independently
licensed packages below. They are installed from Python package indexes and
are not relicensed by PageHold.

| Package | Pinned version | License |
| --- | ---: | --- |
| Playwright for Python | 1.60.0 | Apache-2.0 |
| cryptography | 49.0.0 | Apache-2.0 OR BSD-3-Clause |
| jsonschema | 4.25.1 | MIT |
| attrs | 26.1.0 | MIT |
| cffi | 2.1.0 | MIT-0 |
| greenlet | 3.5.4 | MIT AND PSF-2.0 |
| jsonschema-specifications | 2025.9.1 | MIT |
| pycparser | 3.0 | BSD-3-Clause |
| pyee | 13.0.1 | MIT |
| referencing | 0.37.0 | MIT |
| rpds-py | 2026.6.3 | MIT |
| typing-extensions | 4.16.0 | PSF-2.0 |

Package distributions include their applicable license texts. Source and
license information is available from:

- <https://github.com/microsoft/playwright-python>
- <https://github.com/pyca/cryptography>
- <https://github.com/python-jsonschema/jsonschema>
- <https://github.com/python-attrs/attrs>
- <https://github.com/python-cffi/cffi>
- <https://github.com/python-greenlet/greenlet>
- <https://github.com/python-jsonschema/jsonschema-specifications>
- <https://github.com/eliben/pycparser>
- <https://github.com/jfhbrook/pyee>
- <https://github.com/python-jsonschema/referencing>
- <https://github.com/crate-py/rpds>
- <https://github.com/python/typing_extensions>

`python -m playwright install chromium` downloads browser and media binaries
separately from this source repository. Those binaries retain their own
upstream licenses and notices. PageHold does not claim ownership of them.

This inventory describes the pinned standalone release dependencies as of
2026-07-30. A release check must update it whenever `requirements.txt` changes.
