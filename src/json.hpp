#pragma once

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace forge {

struct JsonValue {
    enum class Type : uint8_t { Null, Bool, Int, Double, String, Array, Object };

    Type type = Type::Null;
    bool b = false;
    int64_t i = 0;
    double d = 0.0;
    std::string s;
    std::vector<JsonValue> arr;
    std::vector<std::pair<std::string, JsonValue>> obj;

    static JsonValue make_null() { return JsonValue{}; }
    static JsonValue make_bool(bool v) { JsonValue j; j.type = Type::Bool; j.b = v; return j; }
    static JsonValue make_int(int64_t v) { JsonValue j; j.type = Type::Int; j.i = v; return j; }
    static JsonValue make_double(double v) { JsonValue j; j.type = Type::Double; j.d = v; return j; }
    static JsonValue make_string(std::string v) { JsonValue j; j.type = Type::String; j.s = std::move(v); return j; }
    static JsonValue make_array() { JsonValue j; j.type = Type::Array; return j; }
    static JsonValue make_object() { JsonValue j; j.type = Type::Object; return j; }

    bool is_null() const noexcept { return type == Type::Null; }
    bool is_bool() const noexcept { return type == Type::Bool; }
    bool is_int() const noexcept { return type == Type::Int; }
    bool is_number() const noexcept { return type == Type::Int || type == Type::Double; }
    bool is_string() const noexcept { return type == Type::String; }
    bool is_array() const noexcept { return type == Type::Array; }
    bool is_object() const noexcept { return type == Type::Object; }

    const JsonValue* get(std::string_view key) const noexcept {
        if (type != Type::Object) return nullptr;
        for (const auto& kv : obj) {
            if (kv.first == key) return &kv.second;
        }
        return nullptr;
    }

    JsonValue* get_mut(std::string_view key) noexcept {
        if (type != Type::Object) return nullptr;
        for (auto& kv : obj) {
            if (kv.first == key) return &kv.second;
        }
        return nullptr;
    }

    void set(std::string key, JsonValue val) {
        for (auto& kv : obj) {
            if (kv.first == key) {
                kv.second = std::move(val);
                return;
            }
        }
        obj.emplace_back(std::move(key), std::move(val));
    }

    std::string as_string(std::string_view def = "") const {
        return type == Type::String ? s : std::string(def);
    }

    int64_t as_int(int64_t def = 0) const noexcept {
        if (type == Type::Int) return i;
        if (type == Type::Double) return static_cast<int64_t>(d);
        return def;
    }

    bool as_bool(bool def = false) const noexcept {
        return type == Type::Bool ? b : def;
    }
};

inline void append_json_escaped(std::string& out, std::string_view s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\b': out.append("\\b"); break;
            case '\f': out.append("\\f"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out.append(buf, 6);
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

inline void serialize_json(const JsonValue& v, std::string& out) {
    switch (v.type) {
        case JsonValue::Type::Null:
            out.append("null");
            break;
        case JsonValue::Type::Bool:
            out.append(v.b ? "true" : "false");
            break;
        case JsonValue::Type::Int: {
            char buf[32];
            int n = std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v.i));
            out.append(buf, static_cast<size_t>(n));
            break;
        }
        case JsonValue::Type::Double: {
            if (!std::isfinite(v.d)) {
                out.append("null");
            } else {
                char buf[48];
                int n = std::snprintf(buf, sizeof(buf), "%.15g", v.d);
                out.append(buf, static_cast<size_t>(n));
            }
            break;
        }
        case JsonValue::Type::String:
            append_json_escaped(out, v.s);
            break;
        case JsonValue::Type::Array:
            out.push_back('[');
            for (size_t i = 0; i < v.arr.size(); ++i) {
                if (i > 0) out.push_back(',');
                serialize_json(v.arr[i], out);
            }
            out.push_back(']');
            break;
        case JsonValue::Type::Object:
            out.push_back('{');
            for (size_t i = 0; i < v.obj.size(); ++i) {
                if (i > 0) out.push_back(',');
                append_json_escaped(out, v.obj[i].first);
                out.push_back(':');
                serialize_json(v.obj[i].second, out);
            }
            out.push_back('}');
            break;
    }
}

inline std::string to_json(const JsonValue& v) {
    std::string out;
    out.reserve(128);
    serialize_json(v, out);
    return out;
}

class JsonParser {
public:
    explicit JsonParser(std::string_view input) noexcept : src_(input) {}

    bool parse(JsonValue& out) {
        skip_ws();
        if (!parse_value(out, 0)) return false;
        skip_ws();
        return pos_ == src_.size();
    }

private:
    void skip_ws() noexcept {
        while (pos_ < src_.size()) {
            char c = src_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++pos_;
            else break;
        }
    }

    static void append_utf8(std::string& out, uint32_t cp) {
        if (cp <= 0x7f) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7ff) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else if (cp <= 0xffff) {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else {
            out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        }
    }

    bool parse_hex4(uint32_t& out) noexcept {
        if (pos_ + 4 > src_.size()) return false;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            char c = src_[pos_++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else return false;
        }
        out = v;
        return true;
    }

    bool parse_string(std::string& out) {
        if (pos_ >= src_.size() || src_[pos_] != '"') return false;
        ++pos_;
        out.clear();
        while (pos_ < src_.size()) {
            unsigned char c = static_cast<unsigned char>(src_[pos_++]);
            if (c == '"') return true;
            if (c < 0x20) return false;
            if (c == '\\') {
                if (pos_ >= src_.size()) return false;
                char esc = src_[pos_++];
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint32_t cp = 0;
                        if (!parse_hex4(cp)) return false;
                        if (cp >= 0xd800 && cp <= 0xdbff) {
                            if (pos_ + 2 <= src_.size() && src_[pos_] == '\\' && src_[pos_ + 1] == 'u') {
                                pos_ += 2;
                                uint32_t lo = 0;
                                if (!parse_hex4(lo) || lo < 0xdc00 || lo > 0xdfff) return false;
                                cp = 0x10000 + (((cp - 0xd800) << 10) | (lo - 0xdc00));
                            }
                        }
                        append_utf8(out, cp);
                        break;
                    }
                    default:
                        return false;
                }
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
        return false;
    }

    bool parse_number(JsonValue& out) {
        size_t start = pos_;
        bool neg = false;
        if (pos_ < src_.size() && src_[pos_] == '-') {
            neg = true;
            ++pos_;
        }
        if (pos_ >= src_.size()) return false;
        if (src_[pos_] == '0') {
            ++pos_;
        } else if (src_[pos_] >= '1' && src_[pos_] <= '9') {
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        } else {
            return false;
        }
        bool is_float = false;
        if (pos_ < src_.size() && src_[pos_] == '.') {
            is_float = true;
            ++pos_;
            if (pos_ >= src_.size() || src_[pos_] < '0' || src_[pos_] > '9') return false;
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        }
        if (pos_ < src_.size() && (src_[pos_] == 'e' || src_[pos_] == 'E')) {
            is_float = true;
            ++pos_;
            if (pos_ < src_.size() && (src_[pos_] == '+' || src_[pos_] == '-')) ++pos_;
            if (pos_ >= src_.size() || src_[pos_] < '0' || src_[pos_] > '9') return false;
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        }
        std::string tmp(src_.substr(start, pos_ - start));
        if (!is_float) {
            try {
                out.type = JsonValue::Type::Int;
                out.i = std::stoll(tmp);
                return true;
            } catch (...) {
                is_float = true;
            }
        }
        try {
            out.type = JsonValue::Type::Double;
            out.d = std::stod(tmp);
            (void)neg;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool parse_value(JsonValue& out, int depth) {
        if (depth > 64 || pos_ >= src_.size()) return false;
        char c = src_[pos_];
        if (c == 'n') {
            if (src_.substr(pos_, 4) != "null") return false;
            pos_ += 4;
            out = JsonValue::make_null();
            return true;
        }
        if (c == 't') {
            if (src_.substr(pos_, 4) != "true") return false;
            pos_ += 4;
            out = JsonValue::make_bool(true);
            return true;
        }
        if (c == 'f') {
            if (src_.substr(pos_, 5) != "false") return false;
            pos_ += 5;
            out = JsonValue::make_bool(false);
            return true;
        }
        if (c == '"') {
            out = JsonValue{};
            out.type = JsonValue::Type::String;
            return parse_string(out.s);
        }
        if (c == '[') {
            ++pos_;
            out = JsonValue::make_array();
            skip_ws();
            if (pos_ < src_.size() && src_[pos_] == ']') {
                ++pos_;
                return true;
            }
            for (;;) {
                skip_ws();
                JsonValue elem;
                if (!parse_value(elem, depth + 1)) return false;
                out.arr.push_back(std::move(elem));
                skip_ws();
                if (pos_ >= src_.size()) return false;
                if (src_[pos_] == ',') {
                    ++pos_;
                    continue;
                }
                if (src_[pos_] == ']') {
                    ++pos_;
                    return true;
                }
                return false;
            }
        }
        if (c == '{') {
            ++pos_;
            out = JsonValue::make_object();
            skip_ws();
            if (pos_ < src_.size() && src_[pos_] == '}') {
                ++pos_;
                return true;
            }
            for (;;) {
                skip_ws();
                std::string key;
                if (!parse_string(key)) return false;
                skip_ws();
                if (pos_ >= src_.size() || src_[pos_] != ':') return false;
                ++pos_;
                skip_ws();
                JsonValue val;
                if (!parse_value(val, depth + 1)) return false;
                out.obj.emplace_back(std::move(key), std::move(val));
                skip_ws();
                if (pos_ >= src_.size()) return false;
                if (src_[pos_] == ',') {
                    ++pos_;
                    continue;
                }
                if (src_[pos_] == '}') {
                    ++pos_;
                    return true;
                }
                return false;
            }
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            return parse_number(out);
        }
        return false;
    }

    std::string_view src_;
    size_t pos_ = 0;
};

inline bool parse_json(std::string_view input, JsonValue& out) {
    JsonParser p(input);
    return p.parse(out);
}

inline std::string base64_encode(const uint8_t* data, size_t len) {
    static constexpr char kTab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        out.push_back(kTab[(v >> 18) & 0x3f]);
        out.push_back(kTab[(v >> 12) & 0x3f]);
        out.push_back(kTab[(v >> 6) & 0x3f]);
        out.push_back(kTab[v & 0x3f]);
        i += 3;
    }
    if (i < len) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        out.push_back(kTab[(v >> 18) & 0x3f]);
        out.push_back(kTab[(v >> 12) & 0x3f]);
        out.push_back((i + 1 < len) ? kTab[(v >> 6) & 0x3f] : '=');
        out.push_back('=');
    }
    return out;
}

inline bool base64_decode(std::string_view in, std::vector<uint8_t>& out) {
    static const int8_t kDec[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-2,-2,-1,-1,-2,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -2,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-3,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    out.clear();
    out.reserve((in.size() * 3) / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : in) {
        int8_t v = kDec[c];
        if (v == -2) continue; // whitespace
        if (v == -3) break;    // '='
        if (v < 0) return false;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xffu));
        }
    }
    return true;
}

inline std::string url_decode(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h = hex(in[i + 1]);
            int l = hex(in[i + 2]);
            if (h >= 0 && l >= 0) {
                out.push_back(static_cast<char>((h << 4) | l));
                i += 2;
                continue;
            }
        }
        if (in[i] == '+') out.push_back(' ');
        else out.push_back(in[i]);
    }
    return out;
}

} // namespace forge
