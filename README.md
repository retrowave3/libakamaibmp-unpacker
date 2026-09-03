# libakamaibmp-unpacker

> [!NOTE]
> This unpacker only supports ARM64

Akamai BMP 4.x.x unpacker utilizing [Emulite](https://github.com/retrowave3/emulite)

## Installation
```console
python -m pip install emulite keystone-engine
```

## Simple Usage
Place libakamaibmp.so in the same folder and run
```console
python bmp_unpacker.py
```

## Advanced Usage
The unpacker is configurable so figure out what layer of unpacking you prefer.
Putting everything to False yields the most barebone unpacking
```python
from bmp_unpacker import AkamaiBmpUnpacker

unpacker = AkamaiBmpUnpacker()
unpacker.load("libakamaibmp.so")
result = unpacker.unpack(
    remove_proxy_calls=True,   # Resolve the proxified calls
    remove_proxy_shims=True,   # Makes the resolved proxified calls direct (remove_proxy_calls required) 
    remove_fake_calls=True,    # Resolve fake BL's which never returns
    remove_nop_b=True,         # Make the fake calls direct (remove_fake_calls required) 
)

with open('libakamaibmp.unpacked.so', 'wb') as fw:
    fw.write(result)

# If you prefer to write your own proxy handling the unpacker exposes the following method
destination = unpacker.resolve_proxy_destination(caller_rva=0x12345)
```