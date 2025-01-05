# Mei_SHA256

A fast, header-only SHA-256 implementation in C11.

## Features

- Header-only
- Thread-safe using `_Thread_local`
- No dynamic memory allocation
- No external dependencies
- No undefined behavior
- Loop-unrolled message schedule computation for better performance

## Requirements

- C11 or newer
- `stdint.h` for fixed-width integer types
- `string.h` for `memset` and `strlen`

## Usage

### String Input

```c
#include "mei_sha256.h"
#include <stdio.h>

int main()
{
    const char *message = "Hello, world!";
    char* hash_res = mei_sha256(message, strlen(message));
    printf("%s\n", hash_res);
    return 0;
}
```

### Raw Data

```c
#include "mei_sha256.h"
#include <stdio.h>

int main()
{
    uint8_t data[] = { 0x13, 0x37 };
    uint8_t hash[32];
    mei_sha256_hash(data, sizeof(data), hash);

    for(int i = 0; i < 32; ++i)
        printf("%02X", hash[i]);

    printf("\n");
    return 0;
}
```

### Streaming

```c
#include "mei_sha256.h"

int main(void)
{
    SHA256_CTX ctx;
    uint8_t hash[32];

    mei_sha256_init(&ctx);
    mei_sha256_update(&ctx, (uint8_t*)"part1", 5);
    mei_sha256_update(&ctx, (uint8_t*)"part2", 5);
    mei_sha256_final(&ctx, hash);
    return 0;
}
```

## API
```c
// One-shot functions
char* sha256(const char* data);                              // Returns hex string
void sha256_hash(const uint8_t* data, size_t len,           // Writes raw bytes
                 uint8_t hash[32]);

// Streaming interface
void sha256_init(SHA256_CTX* ctx);                          // Initialize context
void sha256_update(SHA256_CTX* ctx, const uint8_t* data,    // Update with data
                   size_t len);
void sha256_final(SHA256_CTX* ctx, uint8_t hash[32]);       // Get final hash
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
