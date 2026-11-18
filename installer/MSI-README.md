# MSI-пакет клиента DistControl

## Готовая конфигурация

По умолчанию пакет собирается со значениями:

- сервер управления: `http://10.14.32.179:8765`;
- папка таймеров: `\\dfs\fs\IT\soft\DistKontrol\time`.

MSI запускает тот же установщик DistControl, который определяет пользователя
активного сеанса, устанавливает программу в его профиль, регистрирует службы
`dkclient` и `DistControlAgent`, настраивает драйвер и отправляет заявку серверу.
Вложенный установщик кэшируется в `C:\Program Files\DistControl Installer`,
а установка выполняется в повышенной системной части Windows Installer без скрытого
интерактивного окна. Если установка не завершилась, MSI откатывается и его можно запустить
повторно.

Устанавливайте MSI интерактивно из сеанса целевого пользователя с подтверждением
прав администратора:

```powershell
msiexec.exe /i .\DistControl-Client-0.8.14.msi
```

## Сборка с другими адресами

Исходный код редактировать не требуется. Запустите из корня проекта:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\installer\Build-MsiPackage.ps1 `
  -DefaultServerUrl "http://10.14.32.200:8765" `
  -DefaultUsageStateDirectory "\\NEW-SERVER\DistControl\time"
```

Результат появится в `dist`:

- `DistControl-Client-0.8.14.msi`;
- `DistControl-Client-0.8.14.msi.sha256`.

WiX Toolset загружается автоматически в `build\tools` и не устанавливается в
Windows. Для сборки без повторной компиляции приложения добавьте `-SkipBuild`.

Для MSI адреса зашиваются при сборке. В отдельном `DistControl-Setup.exe` их можно
проверить или временно изменить в окне перед установкой.
