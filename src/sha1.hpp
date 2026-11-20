#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

namespace forge {

struct Oid {
    std::array<uint8_t, 20> bytes{};

    bool operator==(const Oid& other) const noexcept {
        return std::memcmp(bytes.data(), other.bytes.data(), 20) == 0;
    }
    bool operator!=(const Oid& other) const noexcept {
        return !(*this == other);
    }
    bool operator<(const Oid& other) const noexcept {
        return std::memcmp(bytes.data(), other.bytes.data(), 20) < 0;
    }
    bool is_zero() const noexcept {
        for (uint8_t b : bytes) {
            if (b != 0) return false;
        }
        return true;
    }
    std::string hex() const {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out(40, '\0');
        for (size_t i = 0; i < 20; ++i) {
            out[2 * i] = kHex[bytes[i] >> 4];
            out[2 * i + 1] = kHex[bytes[i] & 0x0f];
        }
        return out;
    }
    void write_hex(char* dst) const noexcept {
        static constexpr char kHex[] = "0123456789abcdef";
        for (size_t i = 0; i < 20; ++i) {
            dst[2 * i] = kHex[bytes[i] >> 4];
            dst[2 * i + 1] = kHex[bytes[i] & 0x0f];
        }
    }
};

struct OidHash {
    size_t operator()(const Oid& oid) const noexcept {
        uint64_t h = 0;
        std::memcpy(&h, oid.bytes.data(), sizeof(h));
        return static_cast<size_t>(h);
    }
};

inline int hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool parse_oid(std::string_view sv, Oid& out) noexcept {
    if (sv.size() != 40) return false;
    for (size_t i = 0; i < 20; ++i) {
        int hi = hex_nibble(sv[2 * i]);
        int lo = hex_nibble(sv[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

class Sha1 {
public:
    Sha1() noexcept { reset(); }

    void reset() noexcept {
        h_[0] = 0x67452301u;
        h_[1] = 0xefcdab89u;
        h_[2] = 0x98badcfeu;
        h_[3] = 0x10325476u;
        h_[4] = 0xc3d2e1f0u;
        total_bytes_ = 0;
        buf_len_ = 0;
    }

    void update(const void* data, size_t len) noexcept {
        const auto* p = static_cast<const uint8_t*>(data);
        total_bytes_ += len;
        if (buf_len_ > 0) {
            size_t take = 64 - buf_len_;
            if (take > len) take = len;
            std::memcpy(buf_ + buf_len_, p, take);
            buf_len_ += take;
            p += take;
            len -= take;
            if (buf_len_ == 64) {
                compress(buf_);
                buf_len_ = 0;
            }
        }
        while (len >= 64) {
            compress(p);
            p += 64;
            len -= 64;
        }
        if (len > 0) {
            std::memcpy(buf_, p, len);
            buf_len_ = len;
        }
    }

    void update(std::string_view sv) noexcept {
        update(sv.data(), sv.size());
    }

    Oid final() noexcept {
        uint64_t total_bits = total_bytes_ * 8;
        buf_[buf_len_++] = 0x80;
        if (buf_len_ > 56) {
            std::memset(buf_ + buf_len_, 0, 64 - buf_len_);
            compress(buf_);
            buf_len_ = 0;
        }
        std::memset(buf_ + buf_len_, 0, 56 - buf_len_);
        for (int i = 0; i < 8; ++i) {
            buf_[56 + i] = static_cast<uint8_t>((total_bits >> (56 - 8 * i)) & 0xffu);
        }
        compress(buf_);

        Oid out;
        for (int i = 0; i < 5; ++i) {
            out.bytes[4 * i + 0] = static_cast<uint8_t>((h_[i] >> 24) & 0xffu);
            out.bytes[4 * i + 1] = static_cast<uint8_t>((h_[i] >> 16) & 0xffu);
            out.bytes[4 * i + 2] = static_cast<uint8_t>((h_[i] >> 8) & 0xffu);
            out.bytes[4 * i + 3] = static_cast<uint8_t>(h_[i] & 0xffu);
        }
        return out;
    }

    static Oid digest(const void* data, size_t len) noexcept {
        Sha1 s;
        s.update(data, len);
        return s.final();
    }

private:
    static inline uint32_t rol32(uint32_t v, unsigned s) noexcept {
        return (v << s) | (v >> (32 - s));
    }

    void compress(const uint8_t block[64]) noexcept {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            uint32_t v;
            std::memcpy(&v, block + 4 * i, 4);
            w[i] = __builtin_bswap32(v);
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
#define SHA1_R0(v, w_, x, y, z, i) z += ((w_ & (x ^ y)) ^ y) + w[i] + 0x5a827999u + rol32(v, 5); w_ = rol32(w_, 30)
#define SHA1_R1(v, w_, x, y, z, i) z += (w_ ^ x ^ y) + w[i] + 0x6ed9eba1u + rol32(v, 5); w_ = rol32(w_, 30)
#define SHA1_R2(v, w_, x, y, z, i) z += (((w_ | x) & y) | (w_ & x)) + w[i] + 0x8f1bbcdcu + rol32(v, 5); w_ = rol32(w_, 30)
#define SHA1_R3(v, w_, x, y, z, i) z += (w_ ^ x ^ y) + w[i] + 0xca62c1d6u + rol32(v, 5); w_ = rol32(w_, 30)
        for (int i = 0; i < 20; i += 5) {
            SHA1_R0(a, b, c, d, e, i + 0);
            SHA1_R0(e, a, b, c, d, i + 1);
            SHA1_R0(d, e, a, b, c, i + 2);
            SHA1_R0(c, d, e, a, b, i + 3);
            SHA1_R0(b, c, d, e, a, i + 4);
        }
        for (int i = 20; i < 40; i += 5) {
            SHA1_R1(a, b, c, d, e, i + 0);
            SHA1_R1(e, a, b, c, d, i + 1);
            SHA1_R1(d, e, a, b, c, i + 2);
            SHA1_R1(c, d, e, a, b, i + 3);
            SHA1_R1(b, c, d, e, a, i + 4);
        }
        for (int i = 40; i < 60; i += 5) {
            SHA1_R2(a, b, c, d, e, i + 0);
            SHA1_R2(e, a, b, c, d, i + 1);
            SHA1_R2(d, e, a, b, c, i + 2);
            SHA1_R2(c, d, e, a, b, i + 3);
            SHA1_R2(b, c, d, e, a, i + 4);
        }
        for (int i = 60; i < 80; i += 5) {
            SHA1_R3(a, b, c, d, e, i + 0);
            SHA1_R3(e, a, b, c, d, i + 1);
            SHA1_R3(d, e, a, b, c, i + 2);
            SHA1_R3(c, d, e, a, b, i + 3);
            SHA1_R3(b, c, d, e, a, i + 4);
        }
#undef SHA1_R0
#undef SHA1_R1
#undef SHA1_R2
#undef SHA1_R3
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
    }

    uint32_t h_[5]{};
    uint64_t total_bytes_ = 0;
    uint8_t buf_[64]{};
    size_t buf_len_ = 0;
};

} // namespace forge
