# jwt-encryption
[![Build Status](https://github.com/megablend/jwt-encryption/actions/workflows/build.yml/badge.svg?branch=master)][build]
[![GoDoc](https://img.shields.io/badge/api-Godoc-blue.svg)][godoc]
[![Coverage](https://codecov.io/gh/megablend/jwt-encryption/branch/master/graph/badge.svg)][coverage]
[![Issues](https://img.shields.io/github/issues/megablend/jwt-encryption.svg)][issues]
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg)][license]

[build]: https://github.com/megablend/jwt-encryption/actions
[godoc]: https://pkg.go.dev/github.com/megablend/jwt-encryption
[coverage]: https://codecov.io/gh/megablend/jwt-encryption
[issues]: https://github.com/megablend/jwt-encryption/issues
[license]: https://github.com/megablend/jwt-encryption/blob/master/LICENSE

jwt-encryption aims to serve as a one-stop-shop for providing both JWT and JWE token
encryption using RSA keys. The implementation abstracts the difficulties of understanding
the underlying concept of generating encrypted tokens for developers.

## Installing

Install jwt-encryption by running:

```bash
go get github.com/megablend/jwt-encryption@v0.1.0
```

and ensuring that `$GOPATH/bin` is added to your `$PATH`.

## Documentation

- [Usage][]
- [FAQ][]

[Usage]: ./docs/usage.md
[FAQ]: ./docs/faq.md

## Project status

As of version v0.1.0, jwt-encryption is *beta* and is not considered feature complete. It
works well for the JWT encryption, and we prefer to keep it as simple as possible.
