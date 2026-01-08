using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Terminal.Gui;

namespace netstatExtendedTUIv3
{
    internal class Program
    {
        // Словарь известных портов
        private static Dictionary<int, string> knownPorts = new Dictionary<int, string>
        {
            // Windows системные порты
            { 135, "RPC (Remote Procedure Call)" },
            { 137, "NetBIOS Name Service" },
            { 138, "NetBIOS Datagram Service" },
            { 139, "NetBIOS Session Service (SMB over NetBIOS)" },
            { 445, "Microsoft-DS (SMB over TCP)" },
            { 593, "RPC over HTTP" },
            { 3389, "RDP (Remote Desktop Protocol)" },
            
            // Базы данных
            { 1433, "Microsoft SQL Server" },
            { 1434, "Microsoft SQL Monitor" },
            { 1521, "Oracle Database" },
            { 1522, "Oracle Database" },
            { 1525, "Oracle Database" },
            { 3306, "MySQL Database" },
            { 5432, "PostgreSQL" },
            { 27017, "MongoDB" },
            { 27018, "MongoDB Sharding" },
            { 27019, "MongoDB" },
            { 5984, "CouchDB" },
            { 6379, "Redis" },
            { 9200, "Elasticsearch" },
            { 9300, "Elasticsearch Cluster" },
            
            // Веб-серверы
            { 80, "HTTP" },
            { 443, "HTTPS" },
            { 8080, "HTTP Alternative/Proxy" },
            { 8443, "HTTPS Alternative" },
            { 8888, "HTTP Alternative" },
            { 8000, "HTTP Alternative/Django/Development" },
            { 3000, "Node.js/React/Grafana" },
            { 5000, "Flask/Development/Synology DSM" },
            
            // Файловые протоколы
            { 21, "FTP" },
            { 22, "SSH" },
            { 23, "Telnet [unsafe]" },
            { 69, "TFTP" },
            { 2049, "NFS" },
            { 873, "rsync" },
            
            // Почтовые протоколы
            { 25, "SMTP" },
            { 110, "POP3" },
            { 143, "IMAP" },
            { 465, "SMTPS" },
            { 587, "SMTP Submission" },
            { 993, "IMAPS" },
            { 995, "POP3S" },
            
            // Удаленный доступ
            { 5900, "VNC" },
            { 5901, "VNC" },
            { 5800, "VNC over HTTP" },
            { 5801, "VNC over HTTP" },
            { 5190, "AOL/ICQ" },
            
            // Игровые серверы
            { 27015, "Steam/CS:GO" },
            { 25565, "Minecraft" },
            { 7777, "Unreal Tournament" },
            { 28960, "Call of Duty" },
            
            // Виртуализация
            { 902, "VMware ESXi" },
            { 903, "VMware ESXi" },
            { 2375, "Docker [unsafe]" },
            { 2376, "Docker TLS" },
            
            // Сетевые протоколы
            { 53, "DNS" },
            { 67, "DHCP Server" },
            { 68, "DHCP Client" },
            { 161, "SNMP" },
            { 162, "SNMP Trap" },
            { 389, "LDAP" },
            { 636, "LDAPS" },
            { 1812, "RADIUS Authentication" },
            { 1813, "RADIUS Accounting" },
            
            // Опасные порты
            { 4444, "Meterpreter" },
            { 31337, "Back Orifice" },
            { 666, "Doom/IRC" },
            { 1337, "Backdoor" },
            { 12345, "NetBus" },
            { 12346, "NetBus" },
            { 20034, "NetBus Pro" },
            { 27374, "SubSeven" },
            { 54320, "Back Orifice 2000" },
            { 54321, "Back Orifice 2000" },
            
            // Медиа-серверы
            { 32400, "Plex Media Server" },
            { 1900, "UPnP/SSDP" },
            { 5001, "Synology DSM" },
            
            // IoT
            { 1883, "MQTT" },
            { 8883, "MQTTS" },
            { 5683, "CoAP" },
            { 5684, "CoAPS" },
            
            // Мониторинг
            { 9090, "Prometheus" },
            { 9093, "Alertmanager" },
            { 9100, "Node Exporter" },
            
            // Контейнеры и оркестрация
            { 6443, "Kubernetes API" },
            { 10250, "Kubelet API" },
            { 10255, "Kubelet Read-Only" },
            { 10256, "kube-proxy" },
            { 2379, "etcd Client" },
            { 2380, "etcd Peer" },
            
            // Разное
            { 514, "Syslog" },
            { 1194, "OpenVPN" },
            { 1723, "PPTP" },
            { 1701, "L2TP" },
            { 5060, "SIP" },
            { 5061, "SIPS" },
            { 5222, "XMPP/Jabber" },
            { 5269, "XMPP Server-to-Server" },
            { 6667, "IRC" },
            { 6697, "IRC over SSL" },
            { 10000, "Webmin" }
        };

        // Определение опасных портов
        private static bool IsDangerousPort(int port)
        {
            int[] dangerousPorts = { 135, 137, 138, 139, 445, 1433, 1434, 22, 23, 3389, 5900 };
            return dangerousPorts.Contains(port);
        }

        // КОМПОНЕНТЫ TERMINAL GUI
        private static Window _tcpWindow;
        private static Window _portsWindow;
        private static Window _pidsWindow;
        private static Window _currentWindow;

        private static TextView _tcpTextView;
        private static TextView _portsTextView;
        private static TextView _pidsTextView;

        private static Button _refreshTcpButton;
        private static Button _refreshPortsButton;
        private static Button _refreshPidsButton;

        private static bool _monitoringActive = false;
        private static Thread _monitoringThread;

        // КЭШИ ДЛЯ PID
        private static Dictionary<int, int> _portPidCache = new Dictionary<int, int>();
        private static DateTime _lastCacheUpdate = DateTime.MinValue;
        private static Dictionary<int, (string name, string status, long memory, DateTime startTime, string path)>
            _processInfoCache = new Dictionary<int, (string, string, long, DateTime, string)>();

        // МЕТОДЫ ДЛЯ РАБОТЫ С PID
        private static void UpdatePortPidCache()
        {
            try
            {
                var process = new Process();
                process.StartInfo.FileName = "netstat";
                process.StartInfo.Arguments = "-ano";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.StandardOutputEncoding = Encoding.GetEncoding(866);

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Парсим каждую строку
                foreach (string line in output.Split('\n'))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    // Разделяем строку по пробелам
                    string[] parts = line.Trim().Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

                    // Ищем TCP строки
                    if (parts.Length >= 4 && (parts[0] == "TCP" || parts[0] == "UDP"))
                    {
                        // Локальный адрес:порт - обычно вторая колонка
                        string localAddress = parts[1];

                        // Парсим порт из формата IP:PORT
                        if (localAddress.Contains(":"))
                        {
                            string[] addressParts = localAddress.Split(':');
                            if (addressParts.Length >= 2 && int.TryParse(addressParts.Last(), out int localPort))
                            {
                                // PID находится в последней колонке
                                if (int.TryParse(parts.Last(), out int pid) && pid > 0)
                                {
                                    _portPidCache[localPort] = pid;
                                }
                            }
                        }
                    }
                }

                // Отладочный вывод в консоль
                Console.WriteLine($"[PID CACHE] Обновлен кэш PID: {_portPidCache.Count} записей");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[PID CACHE ERROR] {ex.Message}");
            }
        }

        private static int? GetPidFromPort(int port)
        {
            try
            {
                // Кэшируем результаты на 2 секунды
                if ((DateTime.Now - _lastCacheUpdate).TotalSeconds > 2)
                {
                    _portPidCache.Clear();
                    UpdatePortPidCache();
                    _lastCacheUpdate = DateTime.Now;
                }

                if (_portPidCache.ContainsKey(port))
                    return _portPidCache[port];
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[GetPidFromPort ERROR] {ex.Message}");
            }

            return null;
        }

        private static (string name, string status, long memory, DateTime startTime, string path) GetProcessInfo(int pid)
        {
            // Используем кэш для избежания повторных запросов
            if (_processInfoCache.ContainsKey(pid))
                return _processInfoCache[pid];

            string name = "N/A";
            string status = "N/A";
            long memory = 0;
            DateTime startTime = DateTime.MinValue;
            string path = "N/A";

            try
            {
                var process = Process.GetProcessById(pid);
                name = process.ProcessName;
                status = process.HasExited ? "Завершен" : "Активен";

                if (!process.HasExited)
                {
                    try
                    {
                        memory = process.WorkingSet64;
                        startTime = process.StartTime;

                        // Пробуем получить полный путь
                        try
                        {
                            path = process.MainModule?.FileName ?? "N/A";

                            // Сокращаем длинные пути
                            if (path.Length > 50 && path != "N/A")
                                path = "..." + path.Substring(Math.Max(0, path.Length - 47));
                        }
                        catch (System.ComponentModel.Win32Exception)
                        {
                            path = "Недостаточно прав";
                        }
                        catch (InvalidOperationException)
                        {
                            path = "Процесс завершен";
                        }
                    }
                    catch (System.ComponentModel.Win32Exception)
                    {
                        status = "Нет доступа";
                    }
                }
                else
                {
                    status = "Завершен";
                }
            }
            catch (ArgumentException)
            {
                name = "Не найден";
                status = "Завершен";
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                name = $"Ошибка: {ex.NativeErrorCode}";
                status = "Нет доступа";
            }

            var result = (name, status, memory, startTime, path);
            _processInfoCache[pid] = result;

            return result;
        }

        // МЕТОДЫ ВЫВОДА СЕТЕВОЙ ИНФОРМАЦИИ
        private static string GetStateWithIcon(TcpState state)
        {
            switch (state)
            {
                case TcpState.Established:
                    return "Установлено [*]";
                case TcpState.Listen:
                    return "Слушает     [?!]";
                case TcpState.TimeWait:
                    return "Ожидание    [Zzz]";
                case TcpState.FinWait1:
                    return "Ожидание    [Zzzfw1]";
                case TcpState.FinWait2:
                    return "Ожидание    [Zzzfw2]";
                case TcpState.CloseWait:
                    return "Закрытие    [!X]";
                case TcpState.SynSent:
                    return "Отправил SYN Жду SYN-ACK";
                case TcpState.SynReceived:
                    return "Сервер получил SYN-ACK";
                case TcpState.Unknown:
                    return "Низвестно   [???]";
                case TcpState.DeleteTcb:
                    return "Память освобождается ...";
                case TcpState.Closing:
                    return "Закрыто [X]";
                default:
                    return state.ToString();
            }
        }

        private static string GetTcpConnectionsString()
        {
            var sb = new StringBuilder();
            sb.AppendLine("╔══════════════════════════════════════════════════════════╗");
            sb.AppendLine("║                    АКТИВНЫЕ TCP СОЕДИНЕНИЯ               ║");
            sb.AppendLine("╚══════════════════════════════════════════════════════════╝\n");

            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                sb.AppendLine($"Всего соединений: {connections.Length}");
                sb.AppendLine("─".PadRight(80, '─'));
                sb.AppendLine("ЛОКАЛЬНЫЙ АДРЕС".PadRight(25) + " │ " +
                            "ВНЕШНИЙ АДРЕС".PadRight(25) + " │ СОСТОЯНИЕ");
                sb.AppendLine("─".PadRight(80, '─'));

                foreach (var conn in connections.Take(50))
                {
                    string state = GetStateWithIcon(conn.State);
                    sb.AppendLine($"{conn.LocalEndPoint.ToString().PadRight(25)} │ " +
                                $"{conn.RemoteEndPoint.ToString().PadRight(25)} │ {state}");
                }

                if (connections.Length > 50)
                    sb.AppendLine($"\n... и еще {connections.Length - 50} соединений");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"Ошибка: {ex.Message}");
            }

            return sb.ToString();
        }

        private static string GetKnownPortsString()
        {
            var sb = new StringBuilder();
            sb.AppendLine("╔══════════════════════════════════════════════════════════╗");
            sb.AppendLine("║               ИЗВЕСТНЫЕ И ОПАСНЫЕ ПОРТЫ                  ║");
            sb.AppendLine("╚══════════════════════════════════════════════════════════╝\n");

            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                sb.AppendLine("TCP СЛУШАТЕЛИ:");
                sb.AppendLine("─".PadRight(80, '─'));
                var tcpListeners = properties.GetActiveTcpListeners();
                foreach (var endpoint in tcpListeners)
                {
                    if (knownPorts.TryGetValue(endpoint.Port, out string service))
                    {
                        bool dangerous = IsDangerousPort(endpoint.Port);
                        string marker = dangerous ? " !" : "  ";
                        sb.AppendLine($"{marker}{endpoint.Port,-6} {endpoint.Address,-20} {service}");
                    }
                }

                sb.AppendLine("\n" + "─".PadRight(80, '─'));

                sb.AppendLine("\nUDP СЛУШАТЕЛИ:");
                sb.AppendLine("─".PadRight(80, '─'));
                var udpListeners = properties.GetActiveUdpListeners();
                foreach (var endpoint in udpListeners)
                {
                    if (knownPorts.TryGetValue(endpoint.Port, out string service))
                    {
                        bool dangerous = IsDangerousPort(endpoint.Port);
                        string marker = dangerous ? " !" : "  ";
                        sb.AppendLine($"{marker}{endpoint.Port,-6} {endpoint.Address,-20} {service}");
                    }
                }

                sb.AppendLine("\n" + "═".PadRight(80, '═'));
                var udpStats = properties.GetUdpIPv4Statistics();
                sb.AppendLine($"СТАТИСТИКА UDP:");
                sb.AppendLine($"Получено пакетов: {udpStats.DatagramsReceived}");
                sb.AppendLine($"Отправлено пакетов: {udpStats.DatagramsSent}");
            }
            catch (Exception ex)
            {
                sb.AppendLine($"Ошибка: {ex.Message}");
            }

            return sb.ToString();
        }

        private static string GetPidsString()
        {
            var sb = new StringBuilder();
            sb.AppendLine("╔══════════════════════════════════════════════════════════╗");
            sb.AppendLine("║                    ПРОЦЕССЫ (PID)                        ║");
            sb.AppendLine("╚══════════════════════════════════════════════════════════╝\n");

            try
            {
                // Обновляем кэш PID
                UpdatePortPidCache();

                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                // Группируем порты по PID
                var pidPortsMap = new Dictionary<int, List<int>>();

                // Заполняем карту PID -> порты
                foreach (var conn in connections)
                {
                    int? pid = GetPidFromPort(conn.LocalEndPoint.Port);

                    if (pid.HasValue && pid.Value > 0)
                    {
                        if (!pidPortsMap.ContainsKey(pid.Value))
                        {
                            pidPortsMap[pid.Value] = new List<int>();
                        }

                        if (!pidPortsMap[pid.Value].Contains(conn.LocalEndPoint.Port))
                        {
                            pidPortsMap[pid.Value].Add(conn.LocalEndPoint.Port);
                        }
                    }
                }

                sb.AppendLine($"Найдено процессов: {pidPortsMap.Count}");
                sb.AppendLine($"Кэш PID: {_portPidCache.Count} записей");
                sb.AppendLine("─".PadRight(100, '─'));

                if (pidPortsMap.Count == 0)
                {
                    sb.AppendLine("\n!  Не удалось получить процессы.");
                    sb.AppendLine("   Запустите от администратора и проверьте:");
                    sb.AppendLine("   1. Запуск от имени администратора");
                    sb.AppendLine("   2. Антивирус не блокирует netstat");
                    sb.AppendLine("   3. Попробуйте команду: netstat -ano | findstr :80");
                    return sb.ToString();
                }

                sb.AppendLine("PID".PadRight(8) + "   │  " +
                            "ИМЯ ПРОЦЕССА".PadRight(20) + "    │  " +
                            "ПОРТЫ".PadRight(20) + "    │  " +
                            "СТАТУС".PadRight(10) + "    │  " +
                            "ПАМЯТЬ".PadRight(10) + "│  " +
                            "ЗАПУЩЕН");
                sb.AppendLine("─".PadRight(100, '─'));

                int count = 0;
                foreach (var kvp in pidPortsMap.OrderBy(k => k.Key).Take(25))
                {
                    int pid = kvp.Key;
                    var ports = kvp.Value;

                    var processInfo = GetProcessInfo(pid);

                    // Форматируем порты
                    string portsStr;
                    if (ports.Count == 1)
                        portsStr = ports[0].ToString();
                    else if (ports.Count <= 3)
                        portsStr = string.Join(", ", ports);
                    else
                        portsStr = $"{string.Join(", ", ports.Take(3))}, +{ports.Count - 3}";

                    // Форматируем память
                    string memoryStr = processInfo.memory > 0
                        ? $"{(processInfo.memory / 1024 / 1024):N1}МБ"
                        : "N/A";

                    // Форматируем время запуска
                    string startTimeStr = processInfo.startTime != DateTime.MinValue
                        ? processInfo.startTime.ToString("HH:mm:ss")
                        : "N/A";

                    // Иконки для разных типов процессов
                    string processName = processInfo.name;
                    if (processName.Contains("svchost") || processName.Contains("System") ||
                        processName.Contains("services") || processName.Contains("lsass"))
                    {
                        processName = $" {processName}";
                    }
                    else if (processName.Contains("chrome") || processName.Contains("firefox") ||
                             processName.Contains("msedge") || processName.Contains("opera"))
                    {
                        processName = $" {processName}";
                    }
                    else if (processName.Contains("explorer") || processName.Contains("winlogon"))
                    {
                        processName = $" {processName}";
                    }

                    sb.AppendLine($"{pid.ToString().PadRight(8)}   │   " +
                                $"{processName.PadRight(20)}   │   " +
                                $"{portsStr.PadRight(20)}   │   " +
                                $"{processInfo.status.PadRight(10)}   │   " +
                                $"{memoryStr.PadRight(10)}   │   " +
                                $"{startTimeStr}");

                    count++;
                }

                sb.AppendLine("─".PadRight(100, '─'));
                sb.AppendLine($"Показано: {count} из {pidPortsMap.Count} процессов");

                // Пример работы для отладки
                if (_portPidCache.Count > 0)
                {
                    sb.AppendLine("\n Примеры найденных PID:");
                    int exampleCount = 0;
                    foreach (var kvp in _portPidCache.Take(3))
                    {
                        var info = GetProcessInfo(kvp.Value);
                        sb.AppendLine($"   Порт {kvp.Key} → PID {kvp.Value} ({info.name})");
                        exampleCount++;
                    }
                    if (_portPidCache.Count > 5)
                        sb.AppendLine($"   ... и еще {_portPidCache.Count - 3} портов");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"Ошибка: {ex.Message}");
            }

            return sb.ToString();
        }

        // МЕТОДЫ ОБНОВЛЕНИЯ UI
        private static void UpdateTcpWindow()
        {
            string tcpInfo = GetTcpConnectionsString();
            Application.MainLoop.Invoke(() => {
                _tcpTextView.Text = tcpInfo;
                _tcpTextView.SetNeedsDisplay();
            });
        }

        private static void UpdatePortsWindow()
        {
            string portsInfo = GetKnownPortsString();
            Application.MainLoop.Invoke(() => {
                _portsTextView.Text = portsInfo;
                _portsTextView.SetNeedsDisplay();
            });
        }

        private static void UpdatePidsWindow()
        {
            string pidsInfo = GetPidsString();
            Application.MainLoop.Invoke(() => {
                _pidsTextView.Text = pidsInfo;
                _pidsTextView.SetNeedsDisplay();
            });
        }

        // ФОНОВЫЙ МОНИТОРИНГ
        private static void StartMonitoring()
        {
            _monitoringActive = true;
            _monitoringThread = new Thread(() => {
                while (_monitoringActive)
                {
                    UpdateTcpWindow();
                    UpdatePortsWindow();
                    UpdatePidsWindow();
                    Thread.Sleep(3000);
                }
            });
            _monitoringThread.Start();
        }

        private static void StopMonitoring()
        {
            _monitoringActive = false;
            _monitoringThread?.Join(1000);
        }

        // ЦВЕТОВАЯ СХЕМА
        private static ColorScheme CreateDarkColorScheme()
        {
            var scheme = new ColorScheme();
            scheme.Normal = Terminal.Gui.Attribute.Make(Color.White, Color.Black);
            scheme.HotNormal = Terminal.Gui.Attribute.Make(Color.BrightYellow, Color.Black);
            scheme.Focus = Terminal.Gui.Attribute.Make(Color.Black, Color.DarkGray);
            scheme.HotFocus = Terminal.Gui.Attribute.Make(Color.BrightMagenta, Color.DarkGray);

            return scheme;
        }

        // ОСНОВНОЙ КОД TUI
        static void Main(string[] args)
        {
            Console.WriteLine("Запуск сетевого монитора...");
            Console.WriteLine("Для получения PID требуется запуск от администратора!");

            // Тест получения PID перед запуском TUI
            UpdatePortPidCache();
            Console.WriteLine($"Кэш PID загружен: {_portPidCache.Count} записей");

            if (_portPidCache.Count == 0)
            {
                Console.WriteLine("\n!  ВНИМАНИЕ: Не удалось получить PID!");
                Console.WriteLine("   Запустите программу от имени администратора.");
                Console.WriteLine("   Нажмите Enter для продолжения или Ctrl+C для выхода...");
                Console.ReadLine();
            }

            Application.Init();
            ColorScheme darkScheme = CreateDarkColorScheme();

            // Меню
            var menu = new MenuBar(new MenuBarItem[] {
                new MenuBarItem("_Файл", new MenuItem[] {
                    new MenuItem("_Обновить всё", "", () => {
                        UpdateTcpWindow();
                        UpdatePortsWindow();
                        UpdatePidsWindow();
                    }),
                    new MenuItem("_Выход", "", () => {
                        StopMonitoring();
                        Application.RequestStop();
                    })
                }),
                new MenuBarItem("_Окна", new MenuItem[] {
                    new MenuItem("_TCP Монитор", "", () => SwitchToWindow(_tcpWindow)),
                    new MenuItem("_Порты", "", () => SwitchToWindow(_portsWindow)),
                    new MenuItem("_Процессы (PID)", "", () => SwitchToWindow(_pidsWindow)),
                    new MenuItem("_Разделить (3 окна)", "", () => ShowThreeWindows()),
                    new MenuItem("_Разделить (TCP + PID)", "", () => ShowTwoWindows())
                }),
                new MenuBarItem("_Справка", new MenuItem[] {
                    new MenuItem("_О программе", "", () =>
                        MessageBox.Query("netstatExtendedTUI v3.0",
                            "Монитор сетевых соединений\n" +
                            "TCP соединения + Анализ портов + Мониторинг процессов\n" +
                            "Требуются права администратора для получения PID\n" +
                            "Обновление каждые 3 секунды\n" +
                            "© 2025", "OK"))
                })
            });

            // ОКНО 1: TCP МОНИТОРИНГ
            _tcpWindow = new Window("TCP Мониторинг")
            {
                X = 0,
                Y = 1,
                Width = Dim.Fill(),
                Height = Dim.Fill(),
                ColorScheme = darkScheme
            };

            _refreshTcpButton = new Button("Обновить")
            {
                X = Pos.Center(),
                Y = 1,
                ColorScheme = darkScheme
            };
            _refreshTcpButton.Clicked += () => UpdateTcpWindow();

            _tcpTextView = new TextView()
            {
                X = 0,
                Y = 3,
                Width = Dim.Fill(),
                Height = Dim.Fill() - 1,
                ReadOnly = true,
                WordWrap = false,
                ColorScheme = darkScheme
            };

            _tcpWindow.Add(
                new Label("Режим реального времени (обновление каждые 3 сек):")
                {
                    X = 2,
                    Y = 0,
                    ColorScheme = darkScheme
                },
                _refreshTcpButton,
                _tcpTextView
            );

            // ОКНО 2: АНАЛИЗ ПОРТОВ
            _portsWindow = new Window("Анализ портов")
            {
                X = 0,
                Y = 1,
                Width = Dim.Fill(),
                Height = Dim.Fill(),
                Visible = false,
                ColorScheme = darkScheme
            };

            _refreshPortsButton = new Button("Обновить")
            {
                X = Pos.Center(),
                Y = 1,
                ColorScheme = darkScheme
            };
            _refreshPortsButton.Clicked += () => UpdatePortsWindow();

            _portsTextView = new TextView()
            {
                X = 0,
                Y = 3,
                Width = Dim.Fill(),
                Height = Dim.Fill() - 1,
                ReadOnly = true,
                WordWrap = false,
                ColorScheme = darkScheme
            };

            _portsWindow.Add(
                new Label("Опасные порты помечены [ ! ]:")
                {
                    X = 2,
                    Y = 0,
                    ColorScheme = darkScheme
                },
                _refreshPortsButton,
                _portsTextView
            );

            // ОКНО 3: ПРОЦЕССЫ (PID)
            _pidsWindow = new Window("Процессы (PID)")
            {
                X = 0,
                Y = 1,
                Width = Dim.Fill(),
                Height = Dim.Fill(),
                Visible = false,
                ColorScheme = darkScheme
            };

            _refreshPidsButton = new Button("Обновить")
            {
                X = Pos.Center(),
                Y = 1,
                ColorScheme = darkScheme
            };
            _refreshPidsButton.Clicked += () => UpdatePidsWindow();

            _pidsTextView = new TextView()
            {
                X = 0,
                Y = 3,
                Width = Dim.Fill(),
                Height = Dim.Fill() - 1,
                ReadOnly = true,
                WordWrap = false,
                ColorScheme = darkScheme
            };

            _pidsWindow.Add(
                new Label("")
                {
                    X = 2,
                    Y = 0,
                    ColorScheme = darkScheme
                },
                _refreshPidsButton,
                _pidsTextView
            );

            _currentWindow = _tcpWindow;

            var top = Application.Top;
            top.Add(menu, _tcpWindow, _portsWindow, _pidsWindow);

            // Инициализация данных
            UpdateTcpWindow();
            UpdatePortsWindow();
            UpdatePidsWindow();

            StartMonitoring();

            Application.Run(top);

            StopMonitoring();
            Application.Shutdown();
        }

        // МЕТОДЫ УПРАВЛЕНИЯ ОКНАМИ
        private static void SwitchToWindow(Window windowToShow)
        {
            if (windowToShow == _currentWindow) return;

            _currentWindow.Visible = false;
            windowToShow.Visible = true;
            _currentWindow = windowToShow;

            Application.Top.SetNeedsDisplay();
        }

        private static void ShowThreeWindows()
        {
            // Три окна в ряд
            _tcpWindow.X = 0;
            _tcpWindow.Y = 1;
            _tcpWindow.Width = Dim.Percent(33);
            _tcpWindow.Height = Dim.Fill();
            _tcpWindow.Visible = true;

            _portsWindow.X = Pos.Percent(33);
            _portsWindow.Y = 1;
            _portsWindow.Width = Dim.Percent(33);
            _portsWindow.Height = Dim.Fill();
            _portsWindow.Visible = true;

            _pidsWindow.X = Pos.Percent(66);
            _pidsWindow.Y = 1;
            _pidsWindow.Width = Dim.Percent(34);
            _pidsWindow.Height = Dim.Fill();
            _pidsWindow.Visible = true;

            _currentWindow = _tcpWindow;
            Application.Top.SetNeedsDisplay();
        }

        private static void ShowTwoWindows()
        {
            // Два окна: TCP слева, PID справа
            _tcpWindow.X = 0;
            _tcpWindow.Y = 1;
            _tcpWindow.Width = Dim.Percent(50);
            _tcpWindow.Height = Dim.Fill();
            _tcpWindow.Visible = true;

            _portsWindow.Visible = false;

            _pidsWindow.X = Pos.Percent(50);
            _pidsWindow.Y = 1;
            _pidsWindow.Width = Dim.Percent(50);
            _pidsWindow.Height = Dim.Fill();
            _pidsWindow.Visible = true;

            _currentWindow = _tcpWindow;
            Application.Top.SetNeedsDisplay();
        }
    }
}
