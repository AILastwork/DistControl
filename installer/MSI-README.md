# MSI-пакет клиента DistControl

## Готовая конфигурация

По умолчанию пакет собирается со значениями:

- сервер управления: `http://10.14.32.179:8765`;
- папка таймеров: `\\dfs\fs\IT\soft\DistKontrol\time`.

MSI запускает тот же установщик DistControl, который определяет пользователя
активного сеанса, устанавливает программу в его профиль, регистрирует службы
`dkclient` и `DistControlAgent`, настраивает драйвер и отправляет заявку серверу.

Устанавливайте MSI интерактивно из сеанса целевого пользователя с подтверждением
прав администратора:

```powershell
msiexec.exe /i .\DistControl-Client-0.8.11.msi
```

## Сборка с другими адресами

Исходный код редактировать не требуется. Запустите из корня проекта:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\installer\Build-MsiPackage.ps1 `
  -DefaultServerUrl "http://10.14.32.200:8765" `
  -DefaultUsageStateDirectory "\\NEW-SERVER\DistControl\time"
```

Результат появится в `dist`:

- `DistControl-Client-0.8.11.msi`;
- `DistControl-Client-0.8.11.msi.sha256`.

WiX Toolset загружается автоматически в `build\tools` и не устанавливается в
Windows. Для сборки без повторной компиляции приложения добавьте `-SkipBuild`.

Адреса являются начальными значениями и отображаются в окне перед установкой,
поэтому администратор может проверить или временно изменить их вручную.
