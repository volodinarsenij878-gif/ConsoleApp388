using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TerminalAccessSecurityHub
{
    // =========================================================
    // Шаг 1. Модель учетной карточки сотрудника
    // =========================================================
    public class EmployeePass
    {
        public int EmployeeId { get; }      // табельный номер (уникальный ключ)
        public string FullName { get; }     // ФИО сотрудника
        public string Department { get; }   // отдел
        public int AccessLevel { get; }     // уровень допуска (1–5)

        public EmployeePass(int employeeId, string fullName, string department, int accessLevel)
        {
            EmployeeId = employeeId;
            FullName = fullName;
            Department = department;
            AccessLevel = accessLevel;
        }

        public override string ToString()
        {
            return $"[ID: {EmployeeId}] {FullName} | Отдел: {Department} | Уровень допуска: {AccessLevel}";
        }
    }

    // =========================================================
    // Шаг 2. Модель записи журнала проходов
    // =========================================================
    public class AccessLogRecord
    {
        public DateTime Timestamp { get; }   // штамп времени события
        public int EmployeeId { get; }       // номер сотрудника
        public string GateName { get; }      // имя КПП
        public bool IsGranted { get; }       // флаг успешности прохода
        public string DenialReason { get; }  // причина отказа (если отклонен)

        public AccessLogRecord(DateTime timestamp, int employeeId,
                               string gateName, bool isGranted, string denialReason = null)
        {
            Timestamp = timestamp;
            EmployeeId = employeeId;
            GateName = gateName;
            IsGranted = isGranted;
            DenialReason = denialReason;
        }

        public override string ToString()
        {
            string status = IsGranted
                ? "ДОСТУП РАЗРЕШЕН"
                : $"ОТКАЗ ({DenialReason})";

            return $"[{Timestamp:dd.MM.yyyy HH:mm:ss}] ID {EmployeeId} | КПП \"{GateName}\" | {status}";
        }
    }

    // =========================================================
    // Шаг 3. Диспетчер доступа CheckpointController
    // =========================================================
    public class CheckpointController
    {
        // Реестр сотрудников: ключ — EmployeeId, значение — карточка (O(1) поиск)
        private Dictionary<int, EmployeePass> _employeeDirectory;

        // Белый список активных пропусков (множество, O(1) проверка)
        private HashSet<int> _activeRfidTags;

        // Черный список украденных/аннулированных пропусков
        private HashSet<int> _blacklistedTags;

        // Сквозная хронологическая лента проходов
        private List<AccessLogRecord> _auditLog;

        public CheckpointController()
        {
            _employeeDirectory = new Dictionary<int, EmployeePass>();
            _activeRfidTags = new HashSet<int>();
            _blacklistedTags = new HashSet<int>();
            _auditLog = new List<AccessLogRecord>();
        }

        // Регистрация сотрудника: защита от дубликата ключа словаря
        public void RegisterEmployee(EmployeePass pass)
        {
            if (_employeeDirectory.ContainsKey(pass.EmployeeId))
            {
                Console.WriteLine($"[КПП] ВНИМАНИЕ: сотрудник с ID {pass.EmployeeId} уже зарегистрирован! Дубликат отклонен.");
                return;
            }

            _employeeDirectory.Add(pass.EmployeeId, pass);
            _activeRfidTags.Add(pass.EmployeeId);

            Console.WriteLine($"[КПП] Зарегистрирован: {pass}");
        }

        // Перевод пропуска в черный список
        public void RevokeToBlacklist(int employeeId)
        {
            _activeRfidTags.Remove(employeeId);
            _blacklistedTags.Add(employeeId);
            Console.WriteLine($"[КПП] Пропуск ID {employeeId} переведен в черный список.");
        }

        // Попытка прохода через КПП
        public bool RequestEntry(int employeeId, string gateName, int requiredAccessLevel)
        {
            // 1. Черный список — проверка за O(1)
            if (_blacklistedTags.Contains(employeeId))
            {
                _auditLog.Add(new AccessLogRecord(DateTime.Now, employeeId, gateName,
                    false, "Пропуск в черном списке!"));
                Console.WriteLine($"[КПП] ID {employeeId}: ОТКАЗ — пропуск в черном списке!");
                return false;
            }

            // 2. Активность пропуска — проверка за O(1)
            if (!_activeRfidTags.Contains(employeeId))
            {
                _auditLog.Add(new AccessLogRecord(DateTime.Now, employeeId, gateName,
                    false, "Пропуск не зарегистрирован"));
                Console.WriteLine($"[КПП] ID {employeeId}: ОТКАЗ — пропуск не зарегистрирован.");
                return false;
            }

            // 3. Получение карточки из словаря — O(1), безопасно через TryGetValue
            if (!_employeeDirectory.TryGetValue(employeeId, out EmployeePass pass))
            {
                _auditLog.Add(new AccessLogRecord(DateTime.Now, employeeId, gateName,
                    false, "Пропуск не зарегистрирован"));
                Console.WriteLine($"[КПП] ID {employeeId}: ОТКАЗ — пропуск не зарегистрирован.");
                return false;
            }

            // 4. Проверка уровня допуска
            if (pass.AccessLevel < requiredAccessLevel)
            {
                _auditLog.Add(new AccessLogRecord(DateTime.Now, employeeId, gateName,
                    false, "Недостаточный уровень допуска"));
                Console.WriteLine($"[КПП] ID {employeeId}: ОТКАЗ — недостаточный уровень допуска " +
                                  $"(есть {pass.AccessLevel}, требуется {requiredAccessLevel}).");
                return false;
            }

            // Все проверки пройдены
            _auditLog.Add(new AccessLogRecord(DateTime.Now, employeeId, gateName, true));
            Console.WriteLine($"[КПП] ID {employeeId}: ДОСТУП РАЗРЕШЕН на \"{gateName}\".");
            return true;
        }

        // Полный журнал событий
        public void PrintAuditHistory()
        {
            Console.WriteLine($"\n>>> ПОЛНЫЙ ЖУРНАЛ ПРОХОДОВ (всего событий: {_auditLog.Count}):");
            foreach (AccessLogRecord record in _auditLog)
            {
                Console.WriteLine("  " + record);
            }
        }

        // Отчет по отделу: выборка из словаря
        public void PrintDepartmentReport(string department)
        {
            Console.WriteLine($"\n>>> ОТЧЕТ ПО ОТДЕЛУ \"{department}\":");

            bool found = false;
            foreach (KeyValuePair<int, EmployeePass> pair in _employeeDirectory)
            {
                if (pair.Value.Department == department)
                {
                    Console.WriteLine("  " + pair.Value);
                    found = true;
                }
            }

            if (!found)
            {
                Console.WriteLine("  Сотрудников отдела не найдено.");
            }
        }

        // Пересечение активных меток терминала с внешним списком аудита
        public HashSet<int> GetCrossAuditedTags(HashSet<int> externalAuditorList)
        {
            // Копируем белое множество, чтобы не изменять исходное
            HashSet<int> intersection = new HashSet<int>(_activeRfidTags);
            intersection.IntersectWith(externalAuditorList); // операция пересечения множеств
            return intersection;
        }
    }

    // =========================================================
    // Шаг 4. Демонстрационный сценарий
    // =========================================================
    class Program
    {
        static void Main()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.WriteLine("=== ИНТЕЛЛЕКТУАЛЬНЫЙ КОНТРОЛЬНО-ПРОПУСКНОЙ ПУНКТ ТЕРМИНАЛА ===\n");

            // ---------------------------------------------------------
            // 4.1. Инициализация КПП
            // ---------------------------------------------------------
            CheckpointController hub = new CheckpointController();

            // ---------------------------------------------------------
            // 4.2. Наполнение реестра (Dictionary + HashSet)
            // ---------------------------------------------------------
            Console.WriteLine("--- ЧАСТЬ 2: регистрация сотрудников ---\n");

            hub.RegisterEmployee(new EmployeePass(101, "Иванов И.И.", "Охрана", 4));
            hub.RegisterEmployee(new EmployeePass(102, "Петров П.П.", "Склад", 2));
            hub.RegisterEmployee(new EmployeePass(103, "Сидорова А.С.", "Логистика", 1));
            hub.RegisterEmployee(new EmployeePass(104, "Кузнецов В.В.", "Дирекция", 5));

            // Попытка дубликата: словарь блокирует повторную регистрацию
            Console.WriteLine("\n>>> Попытка повторной регистрации ID 101:");
            hub.RegisterEmployee(new EmployeePass(101, "Иванов И.И. (дубль)", "Охрана", 4));

            // ---------------------------------------------------------
            // 4.3. Моделирование серии проходов (List-журнал)
            // ---------------------------------------------------------
            Console.WriteLine("\n--- ЧАСТЬ 3: серия проходов через КПП ---\n");

            hub.RequestEntry(102, "Шлюз-Север", 2);   // успешно (уровень 2 >= 2)
            hub.RequestEntry(103, "Шлюз-Север", 2);   // отказ: уровень 1 < 2
            hub.RequestEntry(999, "Шлюз-Юг", 1);   // отказ: пропуск не зарегистрирован

            // ---------------------------------------------------------
            // 4.4. Блокировка пропуска (HashSet: Remove + Add)
            // ---------------------------------------------------------
            Console.WriteLine("\n--- ЧАСТЬ 4: блокировка пропуска ---\n");

            hub.RevokeToBlacklist(102);
            hub.RequestEntry(102, "Шлюз-Север", 2);   // отказ: пропуск в черном списке

            // ---------------------------------------------------------
            // 4.5. Математические операции множеств (IntersectWith)
            // ---------------------------------------------------------
            Console.WriteLine("\n--- ЧАСТЬ 5: пересечение множеств (аудит) ---\n");

            HashSet<int> auditTags = new HashSet<int> { 101, 104, 555, 777 };
            HashSet<int> crossAudited = hub.GetCrossAuditedTags(auditTags);

            Console.Write("Совпавшие ID сотрудников (пересечение): [ ");
            foreach (int id in crossAudited)
            {
                Console.Write(id + " ");
            }
            Console.WriteLine("]");
            Console.WriteLine("Ожидаемо: активны 101 и 104 (102 — в черном списке, 103 активен, но не в списке аудита),\n" +
                              "555 и 777 — внешние метки, которых нет на терминале.\n");

            // ---------------------------------------------------------
            // 4.6. Сводная аналитика
            // ---------------------------------------------------------
            Console.WriteLine("--- ЧАСТЬ 6: сводная аналитика ---");

            hub.PrintDepartmentReport("Склад");
            hub.PrintAuditHistory();

            Console.WriteLine("\nНажмите любую клавишу для завершения...");
            Console.ReadKey();
        }
    }
}
