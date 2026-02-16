> [!IMPORTANT]
> SpruceID does not use the DIDKit bindings internally anymore, and they decided to archive their respective repositories. Considering the Open edX project dependency on didkit-python bindings for the
verifiable credentials support and requires VC 2.0 support, a decision was made to fork the solution, implement minor module updates and publish under the name openedx-didkit as a drop-in replacement for didkit PyPI package.

[![PyPI version](https://badge.fury.io/py/openedx-didkit.svg)](https://badge.fury.io/py/openedx-didkit)

Check out the DIDKit documentation [here](https://spruceid.dev/docs/didkit/).

# DIDKit Python

DIDKit provides Verifiable Credential and Decentralized Identifier
functionality across different platforms. It was written primarily in Rust due
to Rust's expressive type system, memory safety, simple dependency web, and
suitability across different platforms including embedded systems. DIDKit
embeds the [`ssi`](https://github.com/spruceid/ssi) library, which contains the
core functionality.

## Installation and Usage

DIDKit is available [on PyPI](https://pypi.org/project/openedx-didkit/).

You can install it globally with:
```bash
$ pip install -U didkit
```

> `asyncio` is required, meaning you will need Python 3.7 or above.

## Build from Source

```bash
$ maturin build
```

> You can install `maturin` with `pip install maturin`.

Now the `wheel` should be in the [target directory](../../target/wheel).

### Custom Builds

To enable or disable certain features of DIDKit, or use different cryptography
backends, you will need edit the `Cargo.toml`.

## Development

When adding a function or changing the signature of an existing one, make sure
to reflect the changes in [the stub file](./didkit/pydidkit.pyi). This is
important for static analysis and IDE support. (This will be automated in the
future.)

## Test

```bash
poetry install
poetry run maturin develop
poetry run pytest
```

