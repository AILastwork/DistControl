// Включение библиотек которые будут использоваться в коде 
#include <gtk/gtk.h>
#include <glib.h>
#include <windows.h>

// Указание пути до канада обмена данными клиентского приложения и концентратора
#define IPC_PATH "\\\\.\\pipe\\dkclient"
// Размер буфера для хранения вывода команд
#define BUFFER_SIZE 64096

// Структуры данных

// Структура для хранения данных о USB-порте и устройстве вставленом в него
struct Device {
    gchar *portName;
    gchar *address;
    gchar *status;
    gchar *productName;
};

// Структура для хранения данных о сервере и группах устройств на нем
struct ServerGroup {
    gchar *groupName;
    gchar *serverPort;
    GHashTable *devices; 
};

// Структура для хранения всех серверов и их групп
struct Server {
    gchar *serverName;
    GHashTable *serverGroups; 
};

// Основная структура для управления серверами, группами и устройствами
struct ServerData {
    GHashTable *servers;  // Хэш-таблица для хранения серверов

    // Конструктор: инициализация хэш-таблицы
    ServerData() {
        servers = g_hash_table_new(g_str_hash, g_str_equal);
    }

    // Деструктор: освобождение ресурсов
    ~ServerData() {
        g_hash_table_destroy(servers);
    }

    // Добавление устройства в группу серверов
    void addDevice(const gchar *serverName, const gchar *groupName, const gchar *serverPort, Device *device) {
        // Поиск или создание сервера
        Server *server = static_cast<Server*>(g_hash_table_lookup(servers, serverName));
        if (!server) {
            server = g_new0(Server, 1);
            server->serverName = g_strdup(serverName);
            server->serverGroups = g_hash_table_new(g_str_hash, g_str_equal);
            g_hash_table_insert(servers, server->serverName, server);
        }

        // Поиск или создание группы
        ServerGroup *group = static_cast<ServerGroup*>(g_hash_table_lookup(server->serverGroups, groupName));
        if (!group) {
            group = g_new0(ServerGroup, 1);
            group->groupName = g_strdup(groupName);
            group->serverPort = g_strdup(serverPort);
            group->devices = g_hash_table_new(g_str_hash, g_str_equal);
            g_hash_table_insert(server->serverGroups, group->groupName, group);
        }

        // Добавление устройства в группу
        g_hash_table_insert(group->devices, device->address, device);
    }

    // Получение устройства по имени сервера, группы и адресу устройства
    Device* getDevice(const gchar *serverName, const gchar *groupName, const gchar *deviceAddress) {
        Server *server = static_cast<Server*>(g_hash_table_lookup(servers, serverName));
        if (!server) return nullptr;

        ServerGroup *group = static_cast<ServerGroup*>(g_hash_table_lookup(server->serverGroups, groupName));
        if (!group) return nullptr;

        return static_cast<Device*>(g_hash_table_lookup(group->devices, deviceAddress));
    }

    // Получение количества серверов
    guint getServerCount() {
        return g_hash_table_size(servers);
    }

    // Получение списка имен всех серверов
    GList* getServerNames() {
        GList *serverNames = nullptr;
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, servers);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            Server *server = static_cast<Server*>(value);
            serverNames = g_list_append(serverNames, g_strdup(server->serverName));
        }

        return serverNames;
    }
};

// Класс отвечающий за парсинг вывода команд LIST и DEVICE INFO
class Parser {
// методы используемые вне класса 
public:
    // метод вызова функции парсинга вывода команды LIST
    static void parseListCommand(const gchar *output, ServerData &serverData);
    // метод вызова функции парсинга вывода команды DEVICE INFO
    static void parseDeviceInfoCommand(const gchar *output, ServerData &serverData, const gchar *serverName, const gchar *groupName, const gchar *deviceAddress);

private:

    static gchar* parseStatus(const gchar *inUseBy); 
};

// функця определения статуса USB-порта
gchar* Parser::parseStatus(const gchar *inUseBy) {
    if (g_strcmp0(inUseBy, "NO ONE") == 0) {
        return g_strdup("Free");
    } else if (g_strcmp0(inUseBy, "YOU") == 0) {
        return g_strdup("In Use");
    } else {
        return g_strdup_printf("Used by %s", inUseBy);
    }
}

// функция парсинга вывода команды LIST
void Parser::parseListCommand(const gchar *output, ServerData &serverData) {
    // Регулярное выражение для захвата имени сервера, группы и порта
        GRegex *serverRegex = g_regex_new(
            "([^-]+)-Gr-(\\d+) \\([^:]+:(\\d+)\\)", 
            G_REGEX_OPTIMIZE, 
            static_cast<GRegexMatchFlags>(0), 
            nullptr
        );
        // Регулярное выражение для захвата информации об устройстве
        GRegex *deviceRegex = g_regex_new(
            "([^ ]+) \\([^-]+-Gr-\\d+\\.(\\d+)\\)", 
            G_REGEX_OPTIMIZE, 
            static_cast<GRegexMatchFlags>(0), 
            nullptr
        );

        gchar **lines = g_strsplit(output, "\n", -1);
        gchar *currentServerName = nullptr;
        gchar *currentGroupName = nullptr;
        gchar *currentServerPort = nullptr;

        for (gchar **line = lines; *line; line++) {
            GMatchInfo *matchInfo;

            if (g_regex_match(serverRegex, *line, static_cast<GRegexMatchFlags>(0), &matchInfo)) {
                currentServerName = g_match_info_fetch(matchInfo, 1); // Имя сервера
                currentGroupName = g_match_info_fetch(matchInfo, 2);  // Имя группы
                currentServerPort = g_match_info_fetch(matchInfo, 3); // Порт сервера
                g_match_info_free(matchInfo);
            } else if (g_regex_match(deviceRegex, *line, static_cast<GRegexMatchFlags>(0), &matchInfo)) {
                gchar *portName = g_match_info_fetch(matchInfo, 1); // Имя порта
                gchar *address = g_match_info_fetch(matchInfo, 2);  // Адрес устройства

                Device *device = g_new0(Device, 1);
                device->portName = g_strdup(portName); 
                device->address = g_strdup(address);
                device->status = g_strdup("Unknown");
                device->productName = g_strdup("Unknown");

                serverData.addDevice(currentServerName, currentGroupName, currentServerPort, device);
                g_match_info_free(matchInfo);
            }
        }

        g_strfreev(lines);
        g_regex_unref(serverRegex);
        g_regex_unref(deviceRegex);
    }

// функция парсинга вывода команды DEVICE INFO
void Parser::parseDeviceInfoCommand(const gchar *output, ServerData &serverData, const gchar *serverName, const gchar *groupName, const gchar *deviceAddress) {
    // Регулярные выражения для захвата имени порта, статуса и названия продукта
    GRegex *nameRegex = g_regex_new("NICKNAME: (.+)", G_REGEX_OPTIMIZE, static_cast<GRegexMatchFlags>(0), nullptr);
    GRegex *statusRegex = g_regex_new("IN USE BY: (.+)", G_REGEX_OPTIMIZE, static_cast<GRegexMatchFlags>(0), nullptr);
    GRegex *productRegex = g_regex_new("PRODUCT: (.+)", G_REGEX_OPTIMIZE, static_cast<GRegexMatchFlags>(0), nullptr);

    gchar **lines = g_strsplit(output, "\n", -1);
    gchar *portName = nullptr;
    gchar *status = nullptr;
    gchar *productName = nullptr;

    for (gchar **line = lines; *line; line++) {
        GMatchInfo *matchInfo;

        if (g_regex_match(nameRegex, *line, static_cast<GRegexMatchFlags>(0), &matchInfo)) {
            portName = g_match_info_fetch(matchInfo, 1);
            g_match_info_free(matchInfo);
        } else if (g_regex_match(statusRegex, *line, static_cast<GRegexMatchFlags>(0), &matchInfo)) {
            gchar *inUseBy = g_match_info_fetch(matchInfo, 1);
            status = parseStatus(inUseBy);
            g_free(inUseBy);
            g_match_info_free(matchInfo);
        } else if (g_regex_match(productRegex, *line, static_cast<GRegexMatchFlags>(0), &matchInfo)) {
            productName = g_match_info_fetch(matchInfo, 1);
            g_match_info_free(matchInfo);
        }
    }

    // Обновляем информацию об устройстве
    Device *device = serverData.getDevice(serverName, groupName, deviceAddress);
    if (device) {
        if (portName) {
            g_free(device->portName);
            device->portName = g_strdup(portName);
        }
        if (status) { // Обновляем статус только если он был найден
            g_free(device->status);
            device->status = g_strdup(status);
        }
        if (productName) {
            g_free(device->productName);
            device->productName = g_strdup(productName);
        }
    }

    g_strfreev(lines);
    g_regex_unref(nameRegex);
    g_regex_unref(statusRegex);
    g_regex_unref(productRegex);

    // Освобождаем временные строки
    if (portName) g_free(portName);
    if (status) g_free(status);
    if (productName) g_free(productName);
}

// Класс для работы с IPC
class IPCClient {
public:
    bool issueIPCCommand(const gchar* request, GString* response, gboolean silent = FALSE) {
        g_string_truncate(response, 0);
        gboolean result = TRUE;
        HANDLE hPipe;

        while (true) {
            hPipe = CreateFile(TEXT(IPC_PATH), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hPipe != INVALID_HANDLE_VALUE) {
                break; 
            }
            if (GetLastError() == ERROR_PIPE_BUSY) { 
                if (!WaitNamedPipe(TEXT(IPC_PATH), 2000)) {
                    if (!silent) {
                    }
                    result = false;
                    break;
                }
            } else {
                if (!silent) {
                }
                result = false;
                break;
            }
        }

        if (result) { 
            DWORD dwMode = PIPE_READMODE_MESSAGE;
            if (SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)) {
                DWORD bytesWritten;
                BOOL fSuccess = WriteFile(hPipe, request, strlen(request), &bytesWritten, NULL);
                if (fSuccess) {
                    DWORD bytesRead;
                    char buffer[BUFFER_SIZE] = { 0 };
                    while (true) {
                        fSuccess = ReadFile(hPipe, buffer, BUFFER_SIZE - 1, &bytesRead, NULL);
                        if (!fSuccess) {
                            result = false;
                            break;
                        }
                        buffer[bytesRead] = '\0'; 
                        g_string_append(response, buffer);
                        if (bytesRead < BUFFER_SIZE - 1) break;
                    }
                } else {
                    if (!silent) {
                    }
                    result = false;
                }
            } else {
                if (!silent) {
                }
                result = false;
            }
            CloseHandle(hPipe);
        }
        return result;
    }
};

// Глобальные переменные для интерфейса
GtkWidget *serverDropdown = nullptr;
GtkWidget *deviceDropdown = nullptr;
ServerData serverData;

// Функция для формирования команды DEVICE INFO
gchar* buildDeviceInfoCommand(const gchar *serverName, const gchar *groupName, const gchar *deviceAddress) {
    return g_strdup_printf("DEVICE INFO,%s-Gr-%s.%s", serverName, groupName, deviceAddress);
}

// Функция для обновления информации вывода команды DEVICE INFO
void updateDeviceInfo(ServerData &serverData, IPCClient &ipcClient, const gchar *dkclPath) {
    GHashTableIter serverIter;
    gpointer serverKey, serverValue;

    g_hash_table_iter_init(&serverIter, serverData.servers);
    while (g_hash_table_iter_next(&serverIter, &serverKey, &serverValue)) {
        Server *server = static_cast<Server*>(serverValue);
        GHashTableIter groupIter;
        gpointer groupKey, groupValue;

        g_hash_table_iter_init(&groupIter, server->serverGroups);
        while (g_hash_table_iter_next(&groupIter, &groupKey, &groupValue)) {
            ServerGroup *group = static_cast<ServerGroup*>(groupValue);
            GHashTableIter deviceIter;
            gpointer deviceKey, deviceValue;

            g_hash_table_iter_init(&deviceIter, group->devices);
            while (g_hash_table_iter_next(&deviceIter, &deviceKey, &deviceValue)) {
                Device *device = static_cast<Device*>(deviceValue);
                GString *response = g_string_new(nullptr);

                // Формируем команду DEVICE INFO
                gchar *command = buildDeviceInfoCommand(server->serverName, group->groupName, device->address);

                if (ipcClient.issueIPCCommand(command, response)) {
                    Parser::parseDeviceInfoCommand(response->str, serverData, server->serverName, group->groupName, device->address);
                }

                g_string_free(response, TRUE);
                g_free(command);
            }
        }
    }
}

// Функция для обновления информации вывода команды LIST
void updateDeviceList(GtkDropDown *dropdown, const gchar *serverName) {
    GListStore *store = g_list_store_new(GTK_TYPE_STRING_OBJECT);
    GHashTableIter serverIter;
    gpointer serverKey, serverValue;

    g_hash_table_iter_init(&serverIter, serverData.servers);
    while (g_hash_table_iter_next(&serverIter, &serverKey, &serverValue)) {
        Server *server = static_cast<Server*>(serverValue);
        if (g_strcmp0(server->serverName, serverName) == 0) {
            GHashTableIter groupIter;
            gpointer groupKey, groupValue;

            g_hash_table_iter_init(&groupIter, server->serverGroups);
            while (g_hash_table_iter_next(&groupIter, &groupKey, &groupValue)) {
                ServerGroup *group = static_cast<ServerGroup*>(groupValue);
                GHashTableIter deviceIter;
                gpointer deviceKey, deviceValue;

                g_hash_table_iter_init(&deviceIter, group->devices);
                while (g_hash_table_iter_next(&deviceIter, &deviceKey, &deviceValue)) {
                    Device *device = static_cast<Device*>(deviceValue);
                    gchar *deviceInfo = g_strdup_printf("%s - %s (%s)", device->portName, device->productName, device->status);
                    GtkStringObject *stringObject = gtk_string_object_new(deviceInfo);
                    g_list_store_append(store, stringObject);
                    g_free(deviceInfo);
                }
            }
        }
    }

    gtk_drop_down_set_model(dropdown, G_LIST_MODEL(store));
}

// Обработчик изменения выбора сервера
void on_server_selected(GtkDropDown *dropdown, GParamSpec *pspec, gpointer user_data) {
    const gchar *selectedServer = gtk_string_object_get_string(GTK_STRING_OBJECT(gtk_drop_down_get_selected_item(dropdown)));
    if (selectedServer) {
        updateDeviceList(GTK_DROP_DOWN(deviceDropdown), selectedServer);
    }
}


// Функция для получения списка подключённых дисков
GList* get_connected_drives() {
    GList *drives = NULL;
    DWORD driveMask = GetLogicalDrives(); // Получаем маску подключённых дисков

    for (int i = 0; i < 26; i++) { // Перебираем все возможные диски (A-Z)
        if (driveMask & (1 << i)) { // Проверяем, подключён ли диск
            gchar driveLetter = 'A' + i;
            gchar drivePath[4] = {driveLetter, ':', '\\', '\0'};

            // Получаем тип диска
            UINT driveType = GetDriveType(drivePath);

            // Если это CD/DVD-привод, добавляем его в список
            if (driveType == DRIVE_CDROM) {
                drives = g_list_append(drives, g_strdup(drivePath));
            }
        }
    }

    return drives;
}

// Функция для сравнения двух списков дисков и поиска нового диска
gchar* find_new_drive(GList *before, GList *after) {
    GList *after_iter = after;
    while (after_iter != NULL) {
        gchar *drive_path = (gchar*)after_iter->data;
        if (!g_list_find_custom(before, drive_path, (GCompareFunc)g_strcmp0)) {
            return g_strdup(drive_path); // Найден новый диск
        }
        after_iter = after_iter->next;
    }
    return NULL; // Новый диск не найден
}

// Обработчик нажатия на кнопку "Use USB-Device"
static void on_use_button_clicked(GtkButton *button, gpointer user_data) {
    // Получаем выбранное устройство из deviceDropdown
    GtkStringObject *selectedDevice = GTK_STRING_OBJECT(gtk_drop_down_get_selected_item(GTK_DROP_DOWN(deviceDropdown)));
    if (!selectedDevice) {
        g_print("No device selected!\n");
        return;
    }

    // Получаем имя выбранного устройства
    const gchar *deviceInfo = gtk_string_object_get_string(selectedDevice);

    // Получаем список подключённых дисков до выполнения команды USE
    GList *drives_before = get_connected_drives();

    // Ищем устройство в структурах данных
    GHashTableIter serverIter;
    gpointer serverKey, serverValue;

    g_hash_table_iter_init(&serverIter, serverData.servers);
    while (g_hash_table_iter_next(&serverIter, &serverKey, &serverValue)) {
        Server *server = static_cast<Server*>(serverValue);
        GHashTableIter groupIter;
        gpointer groupKey, groupValue;

        g_hash_table_iter_init(&groupIter, server->serverGroups);
        while (g_hash_table_iter_next(&groupIter, &groupKey, &groupValue)) {
            ServerGroup *group = static_cast<ServerGroup*>(groupValue);
            GHashTableIter deviceIter;
            gpointer deviceKey, deviceValue;

            g_hash_table_iter_init(&deviceIter, group->devices);
            while (g_hash_table_iter_next(&deviceIter, &deviceKey, &deviceValue)) {
                Device *device = static_cast<Device*>(deviceValue);

                // Формируем строку для сравнения с выбранным устройством
                gchar *currentDeviceInfo = g_strdup_printf("%s - %s (%s)", device->portName, device->productName, device->status);
                if (g_strcmp0(currentDeviceInfo, deviceInfo) == 0) {
                    // Проверяем статус устройства
                    if (g_strcmp0(device->status, "Free") != 0) {
                        g_print("Device is not free!\n");
                        g_free(currentDeviceInfo);
                        g_list_free_full(drives_before, g_free);
                        return;
                    }

                    // Формируем команду USE
                    gchar *useCommand = g_strdup_printf("USE,%s-Gr-%s.%s", server->serverName, group->groupName, device->address);
                    g_print("Executing command: %s\n", useCommand);

                    // Выполняем команду через IPCClient
                    IPCClient ipcClient;
                    GString *useResponse = g_string_new(nullptr);
                    if (ipcClient.issueIPCCommand(useCommand, useResponse)) {
                        g_print("USE command executed successfully.\n");

                        // Обновляем статус устройства
                        g_free(device->status);
                        device->status = g_strdup("In Use");

                        // Обновляем интерфейс
                        updateDeviceList(GTK_DROP_DOWN(deviceDropdown), server->serverName);

                        // Получаем список подключённых дисков после выполнения команды USE
                        GList *drives_after = get_connected_drives();

                        // Ищем новый диск
                        gchar *new_drive = find_new_drive(drives_before, drives_after);
                        if (new_drive) {
                            g_print("New drive detected: %s\n", new_drive);

                            // Проверяем, содержит ли путь к диску подстроку "CD" (например, "D:\")
                            if (g_strstr_len(new_drive, -1, "CD") != NULL) {
                                g_print("Drive contains 'CD' in its path.\n");

                                // Формируем команду STOP USING
                                gchar *stopCommand = g_strdup_printf("STOP USING,%s-Gr-%s.%s", server->serverName, group->groupName, device->address);
                                g_print("Executing command: %s\n", stopCommand);

                                // Выполняем команду STOP USING
                                GString *stopResponse = g_string_new(nullptr);
                                if (ipcClient.issueIPCCommand(stopCommand, stopResponse)) {
                                    g_print("STOP USING command executed successfully.\n");

                                    // Повторно выполняем команду USE
                                    gchar *useCommandAgain = g_strdup_printf("USE,%s-Gr-%s.%s", server->serverName, group->groupName, device->address);
                                    g_print("Executing command again: %s\n", useCommandAgain);

                                    GString *useResponseAgain = g_string_new(nullptr);
                                    if (ipcClient.issueIPCCommand(useCommandAgain, useResponseAgain)) {
                                        g_print("USE command executed successfully after STOP USING.\n");
                                    } else {
                                        g_print("Failed to execute USE command again!\n");
                                    }

                                    g_string_free(useResponseAgain, TRUE);
                                    g_free(useCommandAgain);
                                } else {
                                    g_print("Failed to execute STOP USING command!\n");
                                }

                                g_string_free(stopResponse, TRUE);
                                g_free(stopCommand);
                            }

                            g_free(new_drive);
                        }

                        // Освобождаем список дисков
                        g_list_free_full(drives_after, g_free);
                    } else {
                        g_print("Failed to execute USE command!\n");
                    }

                    // Освобождаем ресурсы
                    g_string_free(useResponse, TRUE);
                    g_free(useCommand);
                    g_free(currentDeviceInfo);
                    g_list_free_full(drives_before, g_free);
                    return;
                }

                g_free(currentDeviceInfo);
            }
        }
    }

    g_print("Device not found!\n");
    g_list_free_full(drives_before, g_free);
}

// Функция для проверки, запущено ли приложение
bool isAppRunning(const gchar *appName) {
    gchar *command = g_strdup_printf("tasklist /FI \"IMAGENAME eq %s\"", appName);
    gchar *output = nullptr;
    GError *error = nullptr;

    // Выполняем команду и получаем её вывод
    gboolean success = g_spawn_command_line_sync(command, &output, nullptr, nullptr, &error);
    g_free(command);

    if (!success) {
        g_printerr("Error executing tasklist: %s\n", error->message);
        g_error_free(error);
        return false;
    }

    // Проверяем, содержится ли имя приложения в выводе
    bool isRunning = (strstr(output, appName) != nullptr);
    g_free(output);

    return isRunning;
}

// Функция для запуска приложения dkcl64.exe
void launchApp() {
    ShellExecute(NULL, "open", "dkcl64.exe", NULL, NULL, SW_SHOWDEFAULT);
}

// Проверка и запуск dkcl64.exe при старте приложения
void startAppIfNotRunning() {
    if (!isAppRunning("dkcl64.exe")) {
        launchApp();
        g_print("dkcl64.exe not running on start.\n");
    }
}

// Функция для периодического обновления списка устройств
static gboolean update_device_list_periodically(gpointer user_data) {
    IPCClient *ipcClient = static_cast<IPCClient*>(user_data);

    // Обновляем информацию об устройствах с помощью команды DEVICE INFO
    updateDeviceInfo(serverData, *ipcClient, nullptr);

    // Обновляем список устройств в интерфейсе
    if (serverData.getServerCount() > 0) {
        GHashTableIter serverIter;
        gpointer serverKey, serverValue;
        g_hash_table_iter_init(&serverIter, serverData.servers);
        g_hash_table_iter_next(&serverIter, &serverKey, &serverValue);
        Server *server = static_cast<Server*>(serverValue);
        updateDeviceList(GTK_DROP_DOWN(deviceDropdown), server->serverName);
    }

    // Возвращаем TRUE, чтобы таймер продолжал работать
    return TRUE;
}



static void activate(GtkApplication *app, gpointer user_data) {
    // Проверяем и запускаем dkcl64.exe, если он не запущен
    startAppIfNotRunning();

    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "DKCL Helper");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_window_set_child(GTK_WINDOW(window), box);

    // Получаем текущую директорию и формируем путь к dkcl64.exe
    gchar *currentDir = g_get_current_dir();
    gchar *dkclPath = g_build_filename(currentDir, "dkcl64.exe", nullptr);
    g_free(currentDir);

    g_print("Using dkcl64.exe path: %s\n", dkclPath); // Выводим путь для отладки

    // Создаём кнопку "Use USB-Device"
    GtkWidget *useButton = gtk_button_new_with_label("Use USB-Device");
    gtk_box_append(GTK_BOX(box), useButton);

    // Подключаем обработчик нажатия на кнопку
    g_signal_connect(useButton, "clicked", G_CALLBACK(on_use_button_clicked), nullptr);

    // Выполняем команду LIST и парсим её вывод
    IPCClient ipcClient;
    GString *response = g_string_new(nullptr);
    if (ipcClient.issueIPCCommand("LIST", response)) {
        Parser::parseListCommand(response->str, serverData);
    }
    g_string_free(response, TRUE);

    // Обновляем информацию об устройствах с помощью команды DEVICE INFO
    updateDeviceInfo(serverData, ipcClient, dkclPath);

    // Если серверов больше одного, создаём serverDropdown
    if (serverData.getServerCount() > 1) {
        serverDropdown = gtk_drop_down_new(nullptr, nullptr);
        GListStore *serverStore = g_list_store_new(GTK_TYPE_STRING_OBJECT);
        GList *serverNames = serverData.getServerNames();

        for (GList *iter = serverNames; iter; iter = iter->next) {
            GtkStringObject *stringObject = gtk_string_object_new(static_cast<gchar*>(iter->data));
            g_list_store_append(serverStore, stringObject);
        }

        gtk_drop_down_set_model(GTK_DROP_DOWN(serverDropdown), G_LIST_MODEL(serverStore));
        gtk_box_append(GTK_BOX(box), serverDropdown);

        // Подключаем обработчик изменения выбора сервера
        g_signal_connect(serverDropdown, "notify::selected-item", G_CALLBACK(on_server_selected), nullptr);

        g_list_free_full(serverNames, g_free);
    }

    // Создаём deviceDropdown
    deviceDropdown = gtk_drop_down_new(nullptr, nullptr);
    gtk_box_append(GTK_BOX(box), deviceDropdown);

    // Обновляем список устройств для первого сервера (если серверы есть)
    if (serverData.getServerCount() > 0) {
        GHashTableIter serverIter;
        gpointer serverKey, serverValue;
        g_hash_table_iter_init(&serverIter, serverData.servers);
        g_hash_table_iter_next(&serverIter, &serverKey, &serverValue);
        Server *server = static_cast<Server*>(serverValue);
        updateDeviceList(GTK_DROP_DOWN(deviceDropdown), server->serverName);
    }

    // Запускаем таймер для периодического обновления списка устройств
    g_timeout_add_seconds(5, update_device_list_periodically, &ipcClient); // Обновление каждые 5 секунд

    gtk_window_present(GTK_WINDOW(window));

    // Освобождаем путь к dkcl64.exe
    g_free(dkclPath);
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("org.example.device_monitor", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), nullptr);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}