# How to build a Debian package.

You should be in a checked-out `debian/latest` branch.

The simplest tool to use to build Rust-based Debian packages is `cargo-deb`, installed with:
```sh
carg add --dev cargo-deb
```
Then build the package with:

```sh
cargo deb
```

This will produce a `.deb` package in the `./target/debian` directory.
