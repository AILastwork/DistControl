#pragma once

#include <cwctype>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace DistControlJson {
struct JsonValue {
    enum class Type { Null, Boolean, String, Number, Object, Array };

    Type type = Type::Null;
    bool booleanValue = false;
    std::wstring stringValue;
    double numberValue = 0;
    std::map<std::wstring, JsonValue> objectValue;
    std::vector<JsonValue> arrayValue;

    const JsonValue* find(const std::wstring& key) const {
        const auto it = objectValue.find(key);
        return it == objectValue.end() ? nullptr : &it->second;
    }
};

class JsonParser {
public:
    explicit JsonParser(std::wstring text) : text_(std::move(text)) {}

    JsonValue parse() {
        skipWs();
        JsonValue value = parseValue();
        skipWs();
        if (pos_ != text_.size()) {
            throw std::runtime_error("Unexpected JSON content.");
        }
        return value;
    }

private:
    JsonValue parseValue() {
        skipWs();
        if (peek() == L'{') {
            return parseObject();
        }
        if (peek() == L'[') {
            return parseArray();
        }
        if (peek() == L'"') {
            JsonValue value;
            value.type = JsonValue::Type::String;
            value.stringValue = parseString();
            return value;
        }
        if (std::iswdigit(peek()) || peek() == L'-') {
            return parseNumber();
        }

        if (matchLiteral(L"true")) {
            JsonValue value;
            value.type = JsonValue::Type::Boolean;
            value.booleanValue = true;
            return value;
        }
        if (matchLiteral(L"false")) {
            JsonValue value;
            value.type = JsonValue::Type::Boolean;
            return value;
        }
        if (matchLiteral(L"null")) {
            return {};
        }

        throw std::runtime_error("Invalid JSON value.");
    }

    JsonValue parseObject() {
        consume(L'{');
        JsonValue value;
        value.type = JsonValue::Type::Object;
        skipWs();
        if (peek() == L'}') {
            ++pos_;
            return value;
        }

        while (true) {
            const std::wstring key = parseString();
            skipWs();
            consume(L':');
            value.objectValue[key] = parseValue();
            skipWs();
            if (peek() == L'}') {
                ++pos_;
                break;
            }
            consume(L',');
        }
        return value;
    }

    JsonValue parseArray() {
        consume(L'[');
        JsonValue value;
        value.type = JsonValue::Type::Array;
        skipWs();
        if (peek() == L']') {
            ++pos_;
            return value;
        }

        while (true) {
            value.arrayValue.push_back(parseValue());
            skipWs();
            if (peek() == L']') {
                ++pos_;
                break;
            }
            consume(L',');
        }
        return value;
    }

    JsonValue parseNumber() {
        const size_t start = pos_;
        if (peek() == L'-') {
            ++pos_;
        }
        while (std::iswdigit(peek())) {
            ++pos_;
        }
        if (peek() == L'.') {
            ++pos_;
            while (std::iswdigit(peek())) {
                ++pos_;
            }
        }

        JsonValue value;
        value.type = JsonValue::Type::Number;
        value.numberValue = std::wcstod(text_.substr(start, pos_ - start).c_str(), nullptr);
        return value;
    }

    std::wstring parseString() {
        consume(L'"');
        std::wstring result;
        while (pos_ < text_.size()) {
            wchar_t ch = text_[pos_++];
            if (ch == L'"') {
                return result;
            }
            if (ch != L'\\') {
                if (ch < 0x20) {
                    throw std::runtime_error("Unescaped JSON control character.");
                }
                result.push_back(ch);
                continue;
            }

            if (pos_ >= text_.size()) {
                throw std::runtime_error("Invalid JSON escape.");
            }
            ch = text_[pos_++];
            switch (ch) {
            case L'"': result.push_back(L'"'); break;
            case L'\\': result.push_back(L'\\'); break;
            case L'/': result.push_back(L'/'); break;
            case L'b': result.push_back(L'\b'); break;
            case L'f': result.push_back(L'\f'); break;
            case L'n': result.push_back(L'\n'); break;
            case L'r': result.push_back(L'\r'); break;
            case L't': result.push_back(L'\t'); break;
            case L'u':
                result.push_back(parseUnicodeEscape());
                break;
            default:
                throw std::runtime_error("Unsupported JSON escape.");
            }
        }
        throw std::runtime_error("Unterminated JSON string.");
    }

    wchar_t parseUnicodeEscape() {
        if (pos_ + 4 > text_.size()) {
            throw std::runtime_error("Invalid unicode escape.");
        }
        unsigned int value = 0;
        for (int i = 0; i < 4; ++i) {
            const wchar_t ch = text_[pos_++];
            value <<= 4;
            if (ch >= L'0' && ch <= L'9') {
                value += ch - L'0';
            }
            else if (ch >= L'a' && ch <= L'f') {
                value += ch - L'a' + 10;
            }
            else if (ch >= L'A' && ch <= L'F') {
                value += ch - L'A' + 10;
            }
            else {
                throw std::runtime_error("Invalid unicode escape.");
            }
        }
        return static_cast<wchar_t>(value);
    }

    bool matchLiteral(const wchar_t* literal) {
        const std::wstring value(literal);
        if (text_.compare(pos_, value.size(), value) == 0) {
            pos_ += value.size();
            return true;
        }
        return false;
    }

    void consume(wchar_t expected) {
        skipWs();
        if (peek() != expected) {
            throw std::runtime_error("Unexpected JSON token.");
        }
        ++pos_;
    }

    wchar_t peek() const {
        return pos_ < text_.size() ? text_[pos_] : L'\0';
    }

    void skipWs() {
        while (pos_ < text_.size() && std::iswspace(text_[pos_])) {
            ++pos_;
        }
    }

    std::wstring text_;
    size_t pos_ = 0;
};

inline std::wstring jsonEscape(const std::wstring& value) {
    std::wstring escaped = L"\"";
    for (wchar_t ch : value) {
        switch (ch) {
        case L'"': escaped += L"\\\""; break;
        case L'\\': escaped += L"\\\\"; break;
        case L'\b': escaped += L"\\b"; break;
        case L'\f': escaped += L"\\f"; break;
        case L'\n': escaped += L"\\n"; break;
        case L'\r': escaped += L"\\r"; break;
        case L'\t': escaped += L"\\t"; break;
        default:
            if (ch < 0x20) {
                const wchar_t* hex = L"0123456789abcdef";
                escaped += L"\\u00";
                escaped.push_back(hex[(ch >> 4) & 15]);
                escaped.push_back(hex[ch & 15]);
            }
            else {
                escaped.push_back(ch);
            }
            break;
        }
    }
    escaped.push_back(L'"');
    return escaped;
}

inline void writeIndent(std::wostringstream& stream, int indent) {
    for (int i = 0; i < indent; ++i) {
        stream << L"  ";
    }
}

inline void serializeJson(const JsonValue& value, std::wostringstream& stream, int indent) {
    switch (value.type) {
    case JsonValue::Type::Boolean:
        stream << (value.booleanValue ? L"true" : L"false");
        break;
    case JsonValue::Type::String:
        stream << jsonEscape(value.stringValue);
        break;
    case JsonValue::Type::Number:
        stream << value.numberValue;
        break;
    case JsonValue::Type::Array:
        stream << L"[\n";
        for (size_t i = 0; i < value.arrayValue.size(); ++i) {
            writeIndent(stream, indent + 1);
            serializeJson(value.arrayValue[i], stream, indent + 1);
            stream << (i + 1 < value.arrayValue.size() ? L"," : L"") << L"\n";
        }
        writeIndent(stream, indent);
        stream << L"]";
        break;
    case JsonValue::Type::Object:
        stream << L"{\n";
        for (auto it = value.objectValue.begin(); it != value.objectValue.end(); ++it) {
            writeIndent(stream, indent + 1);
            stream << jsonEscape(it->first) << L": ";
            serializeJson(it->second, stream, indent + 1);
            stream << (std::next(it) != value.objectValue.end() ? L"," : L"") << L"\n";
        }
        writeIndent(stream, indent);
        stream << L"}";
        break;
    case JsonValue::Type::Null:
    default:
        stream << L"null";
        break;
    }
}

inline std::wstring serializeJson(const JsonValue& value) {
    std::wostringstream stream;
    serializeJson(value, stream, 0);
    stream << L"\n";
    return stream.str();
}

}
