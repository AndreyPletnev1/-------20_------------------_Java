import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Scanner;

public class Main {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ .,?";
    private static final Path DATA_DIR = findDataDirectory();
    private static final Scanner CONSOLE = new Scanner(System.in, StandardCharsets.UTF_8);

    public static void main(String[] args) {
        while (true) {
            System.out.println("1 - Шифрование");
            System.out.println("2 - Расшифрование");
            System.out.println("0 - Выход");
            System.out.print("Выберите действие: ");
            System.out.flush();
            String choice = CONSOLE.nextLine().trim();

            if (choice.equals("0")) {
                System.out.println("Работа программы завершена.");
                return;
            }
            try {
                if (choice.equals("1")) {
                    
                    encrypt();
                } else if (choice.equals("2")) {
                    
                    decrypt();
                } else {
                    System.out.println("Ошибка: выберите 1, 2 или 0.");
                }
            } catch (IOException | IllegalArgumentException exception) {
                System.out.println("Ошибка: " + exception.getMessage());
            }
        }
    }

    
    private static Path findDataDirectory() {
        Path currentDirectory = Path.of("data");
        if (Files.isDirectory(currentDirectory)) {
            return currentDirectory;
        }

        try {
            Path classDirectory = Path.of(Main.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            Path projectDirectory = classDirectory.getParent();
            if (projectDirectory != null && Files.isDirectory(projectDirectory.resolve("data"))) {
                return projectDirectory.resolve("data");
            }
            if (Files.isDirectory(classDirectory.resolve("data"))) {
                return classDirectory.resolve("data");
            }
        } catch (Exception ignored) {
            
        }
        return currentDirectory;
    }

    private static void encrypt() throws IOException {
        Path inputPath = DATA_DIR.resolve("input.txt");
        Path startPath = DATA_DIR.resolve("start_position.txt");
        String input = readText(inputPath).toUpperCase(Locale.ROOT);
        if (input.isEmpty()) {
            throw new IllegalArgumentException("Файл data/input.txt пуст.");
        }
        validateText(input, "исходном тексте");

        int startPosition = readStartPosition(startPath);
        int keyLength;
        try {
            keyLength = Math.addExact(startPosition, input.length());
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("Начальная позиция слишком велика.");
        }
        if (keyLength > 1_000_000) {
            throw new IllegalArgumentException("Начальная позиция слишком велика для создания ключа.");
        }

        String keyDigits = generateRandomDigits(keyLength);
        String ciphertext = transform(input, keyDigits, startPosition, true);
        String keyFile = "Начальная позиция (с нуля): " + startPosition + System.lineSeparator()
                + "Случайные цифры: " + keyDigits + System.lineSeparator();
        String report = createReport("ШИФРОВАНИЕ", input, ciphertext, keyDigits, startPosition, true);

        Files.writeString(DATA_DIR.resolve("key.txt"), keyFile, StandardCharsets.UTF_8);
        Files.writeString(DATA_DIR.resolve("ciphertext.txt"), ciphertext, StandardCharsets.UTF_8);
        Files.writeString(DATA_DIR.resolve("report.txt"), report, StandardCharsets.UTF_8);
        System.out.println("Шифрование завершено.");
        System.out.println("Ключ сохранён");
        System.out.println();
        System.out.print(report);
    }

    private static void decrypt() throws IOException {
        Path ciphertextPath = DATA_DIR.resolve("ciphertext.txt");
        Path keyPath = DATA_DIR.resolve("key.txt");
        String ciphertext = readText(ciphertextPath);
        if (ciphertext.isEmpty()) {
            throw new IllegalArgumentException("Файл data/ciphertext.txt пуст.");
        }
        validateText(ciphertext, "шифртексте");

        KeyData key = readKey(keyPath);
        long requiredLength = (long) key.startPosition + ciphertext.length();
        if (requiredLength > key.digits.length()) {
            throw new IllegalArgumentException("В data/key.txt недостаточно цифр для шифртекста и начальной позиции.");
        }

        String plaintext = transform(ciphertext, key.digits, key.startPosition, false);
        String report = createReport("РАСШИФРОВАНИЕ", plaintext, ciphertext,
                key.digits, key.startPosition, false);
        Files.writeString(DATA_DIR.resolve("decrypted.txt"), plaintext, StandardCharsets.UTF_8);
        Files.writeString(DATA_DIR.resolve("report.txt"), report, StandardCharsets.UTF_8);
        System.out.println("Расшифрование завершено.");
        System.out.println();
        System.out.print(report);
    }

    /** Читает UTF-8 и убирает только завершающие переводы строк файла. */
    private static String readText(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Не найден файл " + path.toString().replace('\\', '/') + ".");
        }
        return Files.readString(path, StandardCharsets.UTF_8).replaceFirst("[\\r\\n]+$", "");
    }

    private static int readStartPosition(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Не найден файл data/start_position.txt.");
        }
        String value = Files.readString(path, StandardCharsets.UTF_8).trim();
        try {
            int position = Integer.parseInt(value);
            if (position < 0) {
                throw new IllegalArgumentException("Начальная позиция не может быть отрицательной.");
            }
            return position;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("В data/start_position.txt должно быть целое число от нуля.");
        }
    }

    /** Читает сохранённый ключ формата из двух подписанных строк. */
    private static KeyData readKey(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException("Не найден файл data/key.txt. Сначала выполните шифрование.");
        }
        String[] lines = Files.readString(path, StandardCharsets.UTF_8).split("\\R");
        if (lines.length < 2 || !lines[0].startsWith("Начальная позиция (с нуля): ")
                || !lines[1].startsWith("Случайные цифры: ")) {
            throw new IllegalArgumentException("Формат data/key.txt повреждён. Нужны строки с начальной позицией и случайными цифрами.");
        }

        int startPosition;
        try {
            startPosition = Integer.parseInt(lines[0].substring("Начальная позиция (с нуля): ".length()).trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("В data/key.txt указана неверная начальная позиция.");
        }
        if (startPosition < 0) {
            throw new IllegalArgumentException("Начальная позиция в data/key.txt не может быть отрицательной.");
        }

        String digits = lines[1].substring("Случайные цифры: ".length()).trim();
        if (digits.isEmpty() || !digits.matches("[0-9]+")) {
            throw new IllegalArgumentException("В data/key.txt должны быть только случайные цифры от 0 до 9.");
        }
        return new KeyData(startPosition, digits);
    }

    private static String generateRandomDigits(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder digits = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            digits.append(random.nextInt(10));
        }
        return digits.toString();
    }

    private static void validateText(String text, String description) {
        for (int i = 0; i < text.length(); i++) {
            if (ALPHABET.indexOf(text.charAt(i)) < 0) {
                throw new IllegalArgumentException("Недопустимый символ в " + description + ": '"
                        + displaySymbol(text.charAt(i)) + "'. Разрешены английские буквы, пробел и знаки . , ?");
            }
        }
    }

    /** Шифрование: C_i=(M_i+K_i) mod 30; расшифрование: M_i=(C_i-K_i+30) mod 30. */
    private static String transform(String text, String keyDigits, int startPosition, boolean encrypt) {
        StringBuilder result = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            int textCode = ALPHABET.indexOf(text.charAt(i));
            int keyCode = keyDigits.charAt(startPosition + i) - '0';
            int resultCode = encrypt
                    ? (textCode + keyCode) % ALPHABET.length()
                    : (textCode - keyCode + ALPHABET.length()) % ALPHABET.length();
            result.append(ALPHABET.charAt(resultCode));
        }
        return result.toString();
    }

    private static String createReport(String operation, String plaintext, String ciphertext,
            String keyDigits, int startPosition, boolean encrypt) {
        StringBuilder report = new StringBuilder();
        report.append("Операция: ").append(operation).append('\n');
        report.append("Размер алфавита: ").append(ALPHABET.length()).append("\n\n");
        report.append("Основной алфавит (строки по 6 символов):\n");
        report.append(renderAlphabetGrid(ALPHABET)).append('\n');
        int firstKeyDigit = keyDigits.charAt(startPosition) - '0';
        report.append("Алфавит замены для первой позиции (сдвиг ").append(firstKeyDigit).append("):\n");
        report.append(renderAlphabetGrid(shiftAlphabet(firstKeyDigit))).append('\n');
        report.append("Начальная позиция в ключе (с нуля): ").append(startPosition).append('\n');
        report.append("Использованные цифры ключа: ")
                .append(keyDigits, startPosition, startPosition + plaintext.length()).append("\n\n");
        report.append("Исходный текст: ").append(plaintext).append('\n');
        report.append("Зашифрованный текст: ").append(ciphertext).append("\n\n");
        report.append("Проверка по символам:\n");
        report.append("Поз.  Символ  M_i  K_i  C_i  Результат\n");
        for (int i = 0; i < plaintext.length(); i++) {
            int messageCode = ALPHABET.indexOf(plaintext.charAt(i));
            int keyCode = keyDigits.charAt(startPosition + i) - '0';
            int cipherCode = (messageCode + keyCode) % ALPHABET.length();
            report.append(String.format(Locale.ROOT, "%3d   %-7s %3d  %3d  %3d  %s%n",
                    i + 1, displaySymbol(plaintext.charAt(i)), messageCode, keyCode, cipherCode,
                    displaySymbol(ALPHABET.charAt(cipherCode))));
        }
        report.append("\nФормула шифрования: C_i = (M_i + K_i) mod 30\n");
        report.append("Формула расшифрования: M_i = (C_i - K_i + 30) mod 30\n");
        report.append("Для расшифрования используется сохранённый ключ из data/key.txt.\n");
        return report.toString();
    }

    private static String renderAlphabetGrid(String alphabet) {
        StringBuilder result = new StringBuilder();
        for (int row = 0; row < 5; row++) {
            for (int column = 0; column < 6; column++) {
                if (column > 0) {
                    result.append("   ");
                }
                result.append(displaySymbol(alphabet.charAt(row * 6 + column)));
            }
            result.append('\n');
        }
        return result.toString();
    }

    private static String shiftAlphabet(int shift) {
        StringBuilder shifted = new StringBuilder(ALPHABET.length());
        for (int i = 0; i < ALPHABET.length(); i++) {
            shifted.append(ALPHABET.charAt((i + shift) % ALPHABET.length()));
        }
        return shifted.toString();
    }

    private static String displaySymbol(char symbol) {
        return symbol == ' ' ? "[ ]" : Character.toString(symbol);
    }

    private static final class KeyData {
        private final int startPosition;
        private final String digits;

        private KeyData(int startPosition, String digits) {
            this.startPosition = startPosition;
            this.digits = digits;
        }
    }
}
