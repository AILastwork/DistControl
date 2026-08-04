## Инструкция по установке и компиляции кода в .exe

1. **Скачать MSYS2**:
   - С официального сайта: [MSYS2](https://www.msys2.org/)
   - Прямая ссылка: [msys2-x86_64-20241208.exe](https://github.com/msys2/msys2-installer/releases/download/2024-12-08/msys2-x86_64-20241208.exe)

2. **Запустить консольное приложение** `msys2.exe`.

3. **Выполнить команду по установке библиотек и компилятора**:
   ```sh
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gtk4 mingw-w64-x86_64-pkg-config mingw-w64-ucrt-x86_64-toolchain base-devel
   ```
   Ссылки для скачивания библиотек и компилятора с официального сайта MSYS2:
   - [mingw-w64-x86_64-gcc](https://packages.msys2.org/packages/mingw-w64-x86_64-gcc)
   - [mingw-w64-x86_64-gtk4](https://packages.msys2.org/packages/mingw-w64-x86_64-gtk4)
   - [mingw-w64-x86_64-pkg-config](https://packages.msys2.org/packages/mingw-w64-x86_64-pkg-config)
   - [mingw-w64-ucrt-x86_64-toolchain](https://packages.msys2.org/groups/mingw-w64-ucrt-x86_64-toolchain)

4. **Открыть переменные среды Windows** (для редактирования системных переменных нужны права администратора).

5. **Добавить пути к библиотекам в переменные среды Windows**:
   ```plaintext
   C:\\msys64\\ucrt64\\include
   C:\\msys64\\ucrt64\\bin
   C:\\msys64\\ucrt64\\lib
   ```

6. **Выполнить в терминале** `msys2.exe` **команды**:
   ```sh
   pkg-config --cflags gtk4
   pkg-config --libs gtk4
   ```

7. **Открыть консоль** `ucrt64.exe`.

8. **Ввести команду**:
   ```sh
   g++ -g -mwindows <вывод команды pkg-config --cflags gtk4> <путь/до/main.cpp> -o <путь/куда/скомпилируется/main.exe> <вывод команды pkg-config --libs gtk4>
   ```
