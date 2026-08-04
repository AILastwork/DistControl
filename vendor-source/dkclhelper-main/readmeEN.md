## Instructions for Installing and Compiling Code into .exe

1. **Download MSYS2**:
   - From the official website: [MSYS2](https://www.msys2.org/)
   - Direct link: [msys2-x86_64-20241208.exe](https://github.com/msys2/msys2-installer/releases/download/2024-12-08/msys2-x86_64-20241208.exe)

2. **Launch the console application** `msys2.exe`.

3. **Execute the command to install libraries and the compiler**:
   ```sh
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gtk4 mingw-w64-x86_64-pkg-config mingw-w64-ucrt-x86_64-toolchain base-devel
   ```
   Download links for libraries and the compiler from the official MSYS2 website:
   - [mingw-w64-x86_64-gcc](https://packages.msys2.org/packages/mingw-w64-x86_64-gcc)
   - [mingw-w64-x86_64-gtk4](https://packages.msys2.org/packages/mingw-w64-x86_64-gtk4)
   - [mingw-w64-x86_64-pkg-config](https://packages.msys2.org/packages/mingw-w64-x86_64-pkg-config)
   - [mingw-w64-ucrt-x86_64-toolchain](https://packages.msys2.org/groups/mingw-w64-ucrt-x86_64-toolchain)

4. **Open Windows Environment Variables** (administrator rights are required to edit system variables).

5. **Add library paths to Windows Environment Variables**:
   ```plaintext
   C:\\msys64\\ucrt64\\include
   C:\\msys64\\ucrt64\\bin
   C:\\msys64\\ucrt64\\lib
   ```

6. **Execute the following commands in the** `msys2.exe` **terminal**:
   ```sh
   pkg-config --cflags gtk4
   pkg-config --libs gtk4
   ```

7. **Open the** `ucrt64.exe` **console**.

8. **Enter the command**:
   ```sh
   g++ -g -mwindows <output of pkg-config --cflags gtk4> <path/to/main.cpp> -o <path/where/main.exe/will/be/compiled> <output of pkg-config --libs gtk4>
   ```