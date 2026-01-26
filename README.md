# XrdOfsOpenVerify

An XRootD `XrdSfsFileSystem` plugin that wraps the native filesystem and
intercepts file open decisions to verify the file's integrity.

## Build

```bash
cd build
cmake ..
make
```

## Installation

```bash
sudo cmake --install build
```

## XRootD configuration

Add the plugin in your server config:
```
xrootd.fslib ++ libXrdOfsOpenVerify.so
```