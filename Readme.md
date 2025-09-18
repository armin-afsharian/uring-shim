# `uring_shim`

`uring_shim` is a C library that provides a simplified, abstraction over Linux's `io_uring` asynchronous I/O interface. It is designed to make it easier to build high-performance network applications by integrating `io_uring`'s capabilities into event loops.

### Key Features
*   **Simplified Callback API**: Abstracts away direct management of submission and completion queues.
*   **Dual Event Loop Models**: Supports both integration with external event loops (like `epoll`) via an `eventfd`, and a native polling mode that calls `io_uring_enter` directly.
*   **Multishot Operations**: Natively supports efficient `recv_multishot` and `accept_multishot` operations.
*   **Provided Buffers**: Manages a ring of provided buffers for efficient, zero-copy style receives.
*   **Flexible Threading**: Supports both single-issuer and multi-threaded submission models via a configuration flag.

## Prerequisites

You must have the `liburing` development library installed on your system.

### On Debian / Ubuntu
```bash
sudo apt-get update
sudo apt-get install liburing-dev
```

### Building `liburing` from Source (Recommended)

If your distribution's package manager provides a version older than 2.1, it is recommended to build the latest version from source to ensure all required features are available.

1.  **Install build dependencies:**
    ```bash
    sudo apt-get install gcc make libelf-devl
    ```

2.  **Clone the `liburing` repository:**
    ```bash
    git clone https://github.com/axboe/liburing.git
    cd liburing
    ```

3.  **Configure, build, and install:**
    ```bash
    ./configure
    make
    sudo make install
    ```

## Building the Library

Clone the repository and use the provided `Makefile`.

1.  **Build the shared library:**
    This command compiles the source and creates `build/liburing_shim.so`.
    ```bash
    make
    ```

2.  **Install the library (Optional):**
    This command installs the shared library to `/usr/local/lib/` and the header file to `/usr/local/include/`.
    ```bash
    sudo make install
    ```

3.  **Clean build files:**
    ```bash
    make clean
    ```

## Compiling Your Application

To compile your own application that uses `liburing_shim`, you must link against both `uring_shim` and `uring`.

```bash
gcc your_app.c -o your_app -luring_shim -luring
```