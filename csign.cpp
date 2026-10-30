// csign - cross-platform iOS .ipa signer and USB/Wi-Fi installer.
//
// Single-file C++17 implementation. Everything needed to re-sign an .ipa
// (Mach-O parsing, code signature generation, bundle sealing) and to push the
// result to a connected device (lockdownd, AFC, installation proxy) lives here.
//
// Supported commands:
//   csign sign <ipa> [--pkey <p12>] [--prov <profile>] [--password <pw>]
//                    [--output <path>] [-i]
//   csign install <ipa>
//   csign cert
//   csign check <ipa>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <libimobiledevice/afc.h>
#include <libimobiledevice/installation_proxy.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>

#include <plist/plist.h>
#include <zip.h>

namespace fs = std::filesystem;

namespace {

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

constexpr char kVersion[] = "1.0";

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

struct SignError : std::runtime_error {
    explicit SignError(const std::string& what) : std::runtime_error(what) {}
};

[[noreturn]] void die(const std::string& message) { throw SignError(message); }

// ---------------------------------------------------------------------------
// Mach-O on-disk structures (kept local so no platform headers are required)
// ---------------------------------------------------------------------------

#pragma pack(push, 1)

struct fat_header_t {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct fat_arch_t {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

struct mach_header_t {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct mach_header_64_t {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command_t {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct linkedit_data_command_t {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct segment_command_t {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct segment_command_64_t {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_t {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct section_64_t {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct encryption_info_command_t {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
};

struct cs_blob_index_t {
    uint32_t type;
    uint32_t offset;
};

struct cs_super_blob_t {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
};

struct cs_code_directory_t {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    uint32_t spare2;
    uint32_t scatterOffset;
    uint32_t teamOffset;
    uint32_t spare3;
    uint64_t codeLimit64;
    uint64_t execSegBase;
    uint64_t execSegLimit;
    uint64_t execSegFlags;
};

#pragma pack(pop)

// Mach-O magic values, compared against a big-endian read of the first word.
constexpr uint32_t kFatMagic = 0xcafebabe;
constexpr uint32_t kFatCigam = 0xbebafeca;
constexpr uint32_t kMachMagic = 0xfeedface;
constexpr uint32_t kMachCigam = 0xcefaedfe;
constexpr uint32_t kMachMagic64 = 0xfeedfacf;
constexpr uint32_t kMachCigam64 = 0xcffaedfe;

constexpr uint32_t kLcSegment = 0x00000001;
constexpr uint32_t kLcSegment64 = 0x00000019;
constexpr uint32_t kLcCodeSignature = 0x0000001d;

constexpr uint32_t kMhExecute = 0x00000002;

// Code signing blob types.
constexpr uint32_t kCsMagicRequirements = 0xfade0c01;
constexpr uint32_t kCsMagicRequirement = 0xfade0c00;
constexpr uint32_t kCsMagicCodeDirectory = 0xfade0c02;
constexpr uint32_t kCsMagicEmbeddedSignature = 0xfade0cc0;
constexpr uint32_t kCsMagicEmbeddedEntitlements = 0xfade7171;
constexpr uint32_t kCsMagicEmbeddedDerEntitlements = 0xfade7172;
constexpr uint32_t kCsMagicBlobWrapper = 0xfade0b01;

constexpr uint32_t kCsSlotCodeDirectory = 0;
constexpr uint32_t kCsSlotInfoPlist = 1;
constexpr uint32_t kCsSlotRequirements = 2;
constexpr uint32_t kCsSlotResourceDir = 3;
constexpr uint32_t kCsSlotEntitlements = 5;
constexpr uint32_t kCsSlotDerEntitlements = 7;
constexpr uint32_t kCsSlotAlternateCodeDirectories = 0x1000;
constexpr uint32_t kCsSlotSignature = 0x10000;

constexpr uint32_t kCsVersion = 0x20400;
constexpr uint32_t kCsAdhocFlag = 0x0002;
constexpr uint64_t kCsExecSegMainBinary = 0x1;

constexpr uint32_t kCodePageShift = 12;
constexpr uint32_t kCodePageSize = 1u << kCodePageShift;

// ---------------------------------------------------------------------------
// Apple public certificate anchors
// ---------------------------------------------------------------------------
//
// Only the WWDR intermediates and Apple roots are needed: they let the CMS
// signature carry a complete chain even when the .p12 holds nothing but the
// leaf certificate and its private key.
//
// Expiry dates of the bundled anchors, so a stale build is easy to spot:
//   WWDR G2  2029-05-06    WWDR G3  2030-02-20    WWDR G4  2030-12-10
//   WWDR G5  2030-12-10    WWDR G6  2036-03-19
//   Apple Root CA  2035-02-09    Apple Root CA G2  2039-04-30
//   Apple Root CA G3  2039-04-30
// A warning is printed at run time once one of them is close to expiring.

const char* const kIntermediatePems[] = {
    // Apple Worldwide Developer Relations CA - G2
    "-----BEGIN CERTIFICATE-----\n"
    "MIIC9zCCAnygAwIBAgIIb+/Y9emjp+4wCgYIKoZIzj0EAwIwZzEbMBkGA1UEAwwS\n"
    "QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u\n"
    "IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN\n"
    "MTQwNTA2MjM0MzI0WhcNMjkwNTA2MjM0MzI0WjCBgDE0MDIGA1UEAwwrQXBwbGUg\n"
    "V29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ0EgLSBHMjEmMCQGA1UECwwd\n"
    "QXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIElu\n"
    "Yy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3fC3BkvP\n"
    "3XMEE8RDiQOTgPte9nStQmFSWAImUxnIYyIHCVJhysTZV+9tJmiLdJGMxPmAaCj8\n"
    "CWjwENrp0C7JGqOB9zCB9DBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0\n"
    "dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDQtYXBwbGVyb290Y2FnMzAdBgNVHQ4E\n"
    "FgQUhLaEzDqGYnIWWZToGqO9SN863wswDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME\n"
    "GDAWgBS7sN6hWDOImqSKmd6+veuv2sskqzA3BgNVHR8EMDAuMCygKqAohiZodHRw\n"
    "Oi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWczLmNybDAOBgNVHQ8BAf8EBAMC\n"
    "AQYwEAYKKoZIhvdjZAYCDwQCBQAwCgYIKoZIzj0EAwIDaQAwZgIxANmxxzHGI/ZP\n"
    "TdDZR8V9GGkRh3En02it4Jtlmr5s3z9GppAJvm6hOyywUYlBPIfSvwIxAPxkUolL\n"
    "PF2/axzCiZgvcq61m6oaCyNUd1ToFUOixRLal1BzfF7QbrJcYlDXUfE6Wg==\n"
    "-----END CERTIFICATE-----\n",
    // Apple Worldwide Developer Relations Certification Authority (G3)
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi\n"
    "MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw\n"
    "bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg\n"
    "Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB\n"
    "cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u\n"
    "IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ\n"
    "BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ\n"
    "C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW\n"
    "BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj\n"
    "+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b\n"
    "5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A\n"
    "0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS\n"
    "VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j\n"
    "BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG\n"
    "AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh\n"
    "MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js\n"
    "MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw\n"
    "EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH\n"
    "Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA\n"
    "HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK\n"
    "XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7\n"
    "bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC\n"
    "NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza\n"
    "UDSdlTs=\n"
    "-----END CERTIFICATE-----\n",
    // Apple Worldwide Developer Relations CA - G4
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEVTCCAz2gAwIBAgIUE9x3lVJx5T3GMujM/+Uh88zFztIwDQYJKoZIhvcNAQEL\n"
    "BQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsT\n"
    "HUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBS\n"
    "b290IENBMB4XDTIwMTIxNjE5MzYwNFoXDTMwMTIxMDAwMDAwMFowdTFEMEIGA1UE\n"
    "Aww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNh\n"
    "dGlvbiBBdXRob3JpdHkxCzAJBgNVBAsMAkc0MRMwEQYDVQQKDApBcHBsZSBJbmMu\n"
    "MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAf\n"
    "eKp6JzKwRl/nF3bYoJ0OKY6tPTKlxGs3yeRBkWq3eXFdDDQEYHX3rkOPR8SGHgjo\n"
    "v9Y5Ui8eZ/xx8YJtPH4GUnadLLzVQ+mxtLxAOnhRXVGhJeG+bJGdayFZGEHVD41t\n"
    "QSo5SiHgkJ9OE0/QjJoyuNdqkh4laqQyziIZhQVg3AJK8lrrd3kCfcCXVGySjnYB\n"
    "5kaP5eYq+6KwrRitbTOFOCOL6oqW7Z+uZk+jDEAnbZXQYojZQykn/e2kv1MukBVl\n"
    "PNkuYmQzHWxq3Y4hqqRfFcYw7V/mjDaSlLfcOQIA+2SM1AyB8j/VNJeHdSbCb64D\n"
    "YyEMe9QbsWLFApy9/a8CAwEAAaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8G\n"
    "A1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0\n"
    "BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJv\n"
    "b3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFwcGxlLmNvbS9yb290\n"
    "LmNybDAdBgNVHQ4EFgQUW9n6HeeaGgujmXYiUIY+kchbd6gwDgYDVR0PAQH/BAQD\n"
    "AgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQA/Vj2e5bbD\n"
    "eeZFIGi9v3OLLBKeAuOugCKMBB7DUshwgKj7zqew1UJEggOCTwb8O0kU+9h0UoWv\n"
    "p50h5wESA5/NQFjQAde/MoMrU1goPO6cn1R2PWQnxn6NHThNLa6B5rmluJyJlPef\n"
    "x4elUWY0GzlxOSTjh2fvpbFoe4zuPfeutnvi0v/fYcZqdUmVIkSoBPyUuAsuORFJ\n"
    "EtHlgepZAE9bPFo22noicwkJac3AfOriJP6YRLj477JxPxpd1F1+M02cHSS+APCQ\n"
    "A1iZQT0xWmJArzmoUUOSqwSonMJNsUvSq3xKX+udO7xPiEAGE/+QF4oIRynoYpgp\n"
    "pU8RBWk6z/Kf\n"
    "-----END CERTIFICATE-----\n",
    // Apple Worldwide Developer Relations CA - G5
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEVTCCAz2gAwIBAgIUO36ACu7TAqHm7NuX2cqsKJzxaZQwDQYJKoZIhvcNAQEL\n"
    "BQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsT\n"
    "HUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBS\n"
    "b290IENBMB4XDTIwMTIxNjE5Mzg1NloXDTMwMTIxMDAwMDAwMFowdTFEMEIGA1UE\n"
    "Aww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNh\n"
    "dGlvbiBBdXRob3JpdHkxCzAJBgNVBAsMAkc1MRMwEQYDVQQKDApBcHBsZSBJbmMu\n"
    "MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ9d\n"
    "2h/7+rzQSyI8x9Ym+hf39J8ePmQRZprvXr6rNL2qLCFu1h6UIYUsdMEOEGGqPGNK\n"
    "fkrjyHXWz8KcCEh7arkpsclm/ciKFtGyBDyCuoBs4v8Kcuus/jtvSL6eixFNlX2y\n"
    "e5AvAhxO/Em+12+1T754xtress3J2WYRO1rpCUVziVDUTuJoBX7adZxLAa7a489t\n"
    "dE3eU9DVGjiCOtCd410pe7GB6iknC/tgfIYS+/BiTwbnTNEf2W2e7XPaeCENnXDZ\n"
    "RleQX2eEwXN3CqhiYraucIa7dSOJrXn25qTU/YMmMgo7JJJbIKGc0S+AGJvdPAvn\n"
    "tf3sgFcPF54/K4cnu/cCAwEAAaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8G\n"
    "A1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0\n"
    "BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJv\n"
    "b3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFwcGxlLmNvbS9yb290\n"
    "LmNybDAdBgNVHQ4EFgQUGYuXjUpbYXhX9KVcNRKKOQjjsHUwDgYDVR0PAQH/BAQD\n"
    "AgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQBaxDWi2eYK\n"
    "nlKiAIIid81yL5D5Iq8UJcyqCkJgksK9dR3rTMoV5X5rQBBe+1tFdA3wen2Ikc7e\n"
    "Y4tCidIY30GzWJ4GCIdI3UCvI9Xt6yxg5eukfxzpnIPWlF9MYjmKTq4TjX1DuNxe\n"
    "rL4YQPLmDyxdE5Pxe2WowmhI3v+0lpsM+zI2np4NlV84CouW0hJst4sLjtc+7G8B\n"
    "qs5NRWDbhHFmYuUZZTDNiv9FU/tu+4h3Q8NIY/n3UbNyXnniVs+8u4S5OFp4rhFI\n"
    "UrsNNYuU3sx0mmj1SWCUrPKosxWGkNDMMEOG0+VwAlG0gcCol9Tq6rCMCUDvOJOy\n"
    "zSID62dDZchF\n"
    "-----END CERTIFICATE-----\n",
    // Apple Worldwide Developer Relations CA - G6
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMw\n"
    "ZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBD\n"
    "ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG\n"
    "A1UEBhMCVVMwHhcNMjEwMzE3MjAzNzEwWhcNMzYwMzE5MDAwMDAwWjB1MUQwQgYD\n"
    "VQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZp\n"
    "Y2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIElu\n"
    "Yy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbsQKC94PrlWm\n"
    "ZXnXgtxzdVJL8T0SGYngDRGpngn3N6PT8JMEb7FDi4bBmPhCnZ3/sq6PF/cGcKXW\n"
    "sL5vOteRhyJ45x3ASP7cOB+aao90fcpxSv/EZFbniAbNgZGhIhpIo4H6MIH3MBIG\n"
    "A1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rL\n"
    "JKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBs\n"
    "ZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0\n"
    "cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFD8v\n"
    "lCNR01DJmig97bB85c+lkGKZMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIB\n"
    "BAIFADAKBggqhkjOPQQDAwNoADBlAjBAXhSq5IyKogMCPtw490BaB677CaEGJXuf\n"
    "QB/EqZGd6CSjiCtOnuMTbXVXmxxcxfkCMQDTSPxarZXvNrkxU3TkUMI33yzvFVVR\n"
    "T4wxWJC994OsdcZ4+RGNsYDyR5gmdr0nDGg=\n"
    "-----END CERTIFICATE-----\n",
};

const char* const kRootPems[] = {
    // Apple Root CA
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET\n"
    "MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv\n"
    "biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0\n"
    "MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw\n"
    "bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx\n"
    "FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
    "ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+\n"
    "+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1\n"
    "XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w\n"
    "tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW\n"
    "q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM\n"
    "aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E\n"
    "BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3\n"
    "R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE\n"
    "ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93\n"
    "d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl\n"
    "IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0\n"
    "YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj\n"
    "b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp\n"
    "Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc\n"
    "NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP\n"
    "y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7\n"
    "R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg\n"
    "xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP\n"
    "IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX\n"
    "UKqK1drk/NAJBzewdXUh\n"
    "-----END CERTIFICATE-----\n",
    // Apple Root CA - G2
    "-----BEGIN CERTIFICATE-----\n"
    "MIIFkjCCA3qgAwIBAgIIAeDltYNno+AwDQYJKoZIhvcNAQEMBQAwZzEbMBkGA1UE\n"
    "AwwSQXBwbGUgUm9vdCBDQSAtIEcyMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0\n"
    "aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMw\n"
    "HhcNMTQwNDMwMTgxMDA5WhcNMzkwNDMwMTgxMDA5WjBnMRswGQYDVQQDDBJBcHBs\n"
    "ZSBSb290IENBIC0gRzIxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0\n"
    "aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzCCAiIwDQYJ\n"
    "KoZIhvcNAQEBBQADggIPADCCAgoCggIBANgREkhI2imKScUcx+xuM23+TfvgHN6s\n"
    "XuI2pyT5f1BrTM65MFQn5bPW7SXmMLYFN14UIhHF6Kob0vuy0gmVOKTvKkmMXT5x\n"
    "ZgM4+xb1hYjkWpIMBDLyyED7Ul+f9sDx47pFoFDVEovy3d6RhiPw9bZyLgHaC/Yu\n"
    "OQhfGaFjQQscp5TBhsRTL3b2CtcM0YM/GlMZ81fVJ3/8E7j4ko380yhDPLVoACVd\n"
    "J2LT3VXdRCCQgzWTxb+4Gftr49wIQuavbfqeQMpOhYV4SbHXw8EwOTKrfl+q04tv\n"
    "ny0aIWhwZ7Oj8ZhBbZF8+NfbqOdfIRqMM78xdLe40fTgIvS/cjTf94FNcX1RoeKz\n"
    "8NMoFnNvzcytN31O661A4T+B/fc9Cj6i8b0xlilZ3MIZgIxbdMYs0xBTJh0UT8TU\n"
    "gWY8h2czJxQI6bR3hDRSj4n4aJgXv8O7qhOTH11UL6jHfPsNFL4VPSQ08prcdUFm\n"
    "IrQB1guvkJ4M6mL4m1k8COKWNORj3rw31OsMiANDC1CvoDTdUE0V+1ok2Az6DGOe\n"
    "HwOx4e7hqkP0ZmUoNwIx7wHHHtHMn23KVDpA287PT0aLSmWaasZobNfMmRtHsHLD\n"
    "d4/E92GcdB/O/WuhwpyUgquUoue9G7q5cDmVF8Up8zlYNPXEpMZ7YLlmQ1A/bmH8\n"
    "DvmGqmAMQ0uVAgMBAAGjQjBAMB0GA1UdDgQWBBTEmRNsGAPCe8CjoA1/coB6HHcm\n"
    "jTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQwF\n"
    "AAOCAgEAUabz4vS4PZO/Lc4Pu1vhVRROTtHlznldgX/+tvCHM/jvlOV+3Gp5pxy+\n"
    "8JS3ptEwnMgNCnWefZKVfhidfsJxaXwU6s+DDuQUQp50DhDNqxq6EWGBeNjxtUVA\n"
    "eKuowM77fWM3aPbn+6/Gw0vsHzYmE1SGlHKy6gLti23kDKaQwFd1z4xCfVzmMX3z\n"
    "ybKSaUYOiPjjLUKyOKimGY3xn83uamW8GrAlvacp/fQ+onVJv57byfenHmOZ4VxG\n"
    "/5IFjPoeIPmGlFYl5bRXOJ3riGQUIUkhOb9iZqmxospvPyFgxYnURTbImHy99v6Z\n"
    "SYA7LNKmp4gDBDEZt7Y6YUX6yfIjyGNzv1aJMbDZfGKnexWoiIqrOEDCzBL/FePw\n"
    "N983csvMmOa/orz6JopxVtfnJBtIRD6e/J/JzBrsQzwBvDR4yGn1xuZW7AYJNpDr\n"
    "FEobXsmII9oDMJELuDY++ee1KG++P+w8j2Ud5cAeh6Squpj9kuNsJnfdBrRkBof0\n"
    "Tta6SqoWqPQFZ2aWuuJVecMsXUmPgEkrihLHdoBR37q9ZV0+N0djMenl9MU/S60E\n"
    "inpxLK8JQzcPqOMyT/RFtm2XNuyE9QoB6he7hY1Ck3DDUOUUi78/w0EP3SIEIwiK\n"
    "um1xRKtzCTrJ+VKACd+66eYWyi4uTLLT3OUEVLLUNIAytbwPF+E=\n"
    "-----END CERTIFICATE-----\n",
    // Apple Root CA - G3
    "-----BEGIN CERTIFICATE-----\n"
    "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS\n"
    "QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u\n"
    "IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN\n"
    "MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS\n"
    "b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y\n"
    "aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49\n"
    "AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf\n"
    "TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517\n"
    "IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr\n"
    "MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA\n"
    "MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4\n"
    "at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM\n"
    "6BgD56KyKA==\n"
    "-----END CERTIFICATE-----\n",
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

inline uint32_t swap32(uint32_t v) { return __builtin_bswap32(v); }
inline uint64_t swap64(uint64_t v) { return __builtin_bswap64(v); }

inline uint32_t alignUp32(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) / alignment * alignment;
}

inline uint64_t alignUp64(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) / alignment * alignment;
}

uint32_t readBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

int asn1StringLength(const ASN1_STRING* value) {
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    return ASN1_STRING_get_length(value);
#else
    return ASN1_STRING_length(value);
#endif
}

std::string readFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) die("cannot read '" + path.string() + "': " + std::strerror(errno));
    std::ostringstream buffer;
    buffer << in.rdbuf();
    if (!in.good() && !in.eof()) die("cannot read '" + path.string() + "'");
    return buffer.str();
}

bool readFileIfExists(const fs::path& path, std::string& out) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream buffer;
    buffer << in.rdbuf();
    out = buffer.str();
    return true;
}

void writeFile(const fs::path& path, const void* data, size_t size) {
    std::error_code ec;
    if (!path.parent_path().empty()) fs::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) die("cannot write '" + path.string() + "': " + std::strerror(errno));
    if (size > 0) out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    out.flush();
    if (!out) die("cannot write '" + path.string() + "'");
}

void writeFile(const fs::path& path, const std::string& data) {
    writeFile(path, data.data(), data.size());
}

std::string expandHome(const std::string& value) {
    if (!value.empty() && value[0] == '~') {
        const char* home = std::getenv("HOME");
        if (home == nullptr) die("HOME is not set");
        return std::string(home) + value.substr(1);
    }
    return value;
}

// Reusable message digest helper (no deprecated one-shot SHA API).
struct Digest {
    const EVP_MD* md;
    EVP_MD_CTX* ctx;

    explicit Digest(const EVP_MD* algorithm) : md(algorithm), ctx(EVP_MD_CTX_new()) {
        if (ctx == nullptr) die("out of memory");
    }
    ~Digest() { EVP_MD_CTX_free(ctx); }
    Digest(const Digest&) = delete;
    Digest& operator=(const Digest&) = delete;

    std::string operator()(const void* data, size_t size) const {
        unsigned char out[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) die("digest init failed");
        if (size > 0 && EVP_DigestUpdate(ctx, data, size) != 1) die("digest update failed");
        if (EVP_DigestFinal_ex(ctx, out, &length) != 1) die("digest final failed");
        return std::string(reinterpret_cast<const char*>(out), length);
    }
};

std::string sha1(const std::string& data) {
    Digest digest(EVP_sha1());
    return digest(data.data(), data.size());
}

std::string sha256(const std::string& data) {
    Digest digest(EVP_sha256());
    return digest(data.data(), data.size());
}

std::string readLine() {
    std::string line;
    int ch = 0;
    while ((ch = std::getchar()) != EOF && ch != '\n') line.push_back(static_cast<char>(ch));
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

std::string trimmed(const std::string& value) {
    size_t begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return std::string();
    size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::string promptLine(const std::string& label) {
    std::fputs(label.c_str(), stdout);
    std::fflush(stdout);
    return readLine();
}

// Reads a line from the terminal without echoing it back.
std::string promptHidden(const std::string& label) {
    std::fputs(label.c_str(), stdout);
    std::fflush(stdout);

#ifdef _WIN32
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD originalMode = 0;
    bool restore = false;
    if (input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &originalMode) != 0) {
        const DWORD hiddenMode = originalMode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT);
        if (SetConsoleMode(input, hiddenMode) != 0) restore = true;
    }

    std::string line = readLine();

    if (restore) {
        SetConsoleMode(input, originalMode);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    }
    return line;
#else
    struct termios original {};
    bool restore = false;
    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original) == 0) {
        struct termios hidden = original;
        hidden.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0) restore = true;
    }

    std::string line = readLine();

    if (restore) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    }
    return line;
#endif
}

// ---------------------------------------------------------------------------
// Property list helpers (libplist)
// ---------------------------------------------------------------------------

struct PlistHolder {
    plist_t node = nullptr;

    PlistHolder() = default;
    explicit PlistHolder(plist_t value) : node(value) {}
    ~PlistHolder() { reset(); }
    PlistHolder(const PlistHolder&) = delete;
    PlistHolder& operator=(const PlistHolder&) = delete;
    PlistHolder(PlistHolder&& other) noexcept : node(other.node) { other.node = nullptr; }

    void reset() {
        if (node != nullptr) {
            plist_free(node);
            node = nullptr;
        }
    }
};

plist_t parsePlist(const std::string& data) {
    if (data.empty()) return nullptr;
    plist_t root = nullptr;
    if (plist_from_memory(data.data(), static_cast<uint32_t>(data.size()), &root, nullptr) !=
        PLIST_ERR_SUCCESS) {
        return nullptr;
    }
    return root;
}

std::string plistToString(plist_t node) {
    char* xml = nullptr;
    uint32_t length = 0;
    if (node == nullptr || plist_to_xml(node, &xml, &length) != PLIST_ERR_SUCCESS) {
        if (xml != nullptr) std::free(xml);
        die("cannot serialize property list");
    }
    std::string out(xml, length);
    std::free(xml);
    return out;
}

std::string plistString(plist_t dict, const char* key) {
    plist_t item = plist_dict_get_item(dict, key);
    if (item == nullptr || plist_get_node_type(item) != PLIST_STRING) return std::string();
    char* value = nullptr;
    plist_get_string_val(item, &value);
    std::string out = value != nullptr ? value : "";
    std::free(value);
    return out;
}

// ---------------------------------------------------------------------------
// DER encoding for the entitlements slot
// ---------------------------------------------------------------------------

void derAppendLength(std::string& out, size_t length) {
    if (length < 0x80) {
        out.push_back(static_cast<char>(length));
        return;
    }
    unsigned char bytes[8];
    size_t count = 0;
    size_t remaining = length;
    while (remaining > 0) {
        bytes[count++] = static_cast<unsigned char>(remaining & 0xff);
        remaining >>= 8;
    }
    out.push_back(static_cast<char>(0x80 | count));
    for (size_t i = count; i > 0; --i) out.push_back(static_cast<char>(bytes[i - 1]));
}

void derAppend(std::string& out, unsigned char tag, const std::string& content) {
    out.push_back(static_cast<char>(tag));
    derAppendLength(out, content.size());
    out += content;
}

std::string derSignedInteger(int64_t value) {
    const uint64_t bits = static_cast<uint64_t>(value);
    unsigned char buffer[8];
    for (int i = 0; i < 8; ++i) {
        buffer[i] = static_cast<unsigned char>((bits >> (8 * (7 - i))) & 0xff);
    }
    size_t start = 0;
    while (start < 7) {
        const unsigned char current = buffer[start];
        const unsigned char next = buffer[start + 1];
        const bool redundant = (current == 0x00 && (next & 0x80) == 0) ||
                               (current == 0xff && (next & 0x80) != 0);
        if (!redundant) break;
        ++start;
    }
    return std::string(reinterpret_cast<const char*>(buffer + start), 8 - start);
}

void derEncodePlist(plist_t node, std::string& out) {
    switch (plist_get_node_type(node)) {
        case PLIST_BOOLEAN: {
            uint8_t value = 0;
            plist_get_bool_val(node, &value);
            derAppend(out, 0x01, std::string(1, value != 0 ? '\xff' : '\x00'));
            break;
        }
        case PLIST_INT: {
            int64_t value = 0;
            plist_get_int_val(node, &value);
            derAppend(out, 0x02, derSignedInteger(value));
            break;
        }
        case PLIST_REAL: {
            double value = 0;
            plist_get_real_val(node, &value);
            derAppend(out, 0x03, std::string(reinterpret_cast<const char*>(&value), sizeof(value)));
            break;
        }
        case PLIST_STRING: {
            char* value = nullptr;
            plist_get_string_val(node, &value);
            std::string text = value != nullptr ? value : "";
            std::free(value);
            derAppend(out, 0x0c, text);
            break;
        }
        case PLIST_DATA: {
            char* value = nullptr;
            uint64_t length = 0;
            plist_get_data_val(node, &value, &length);
            std::string bytes(value != nullptr ? value : "", static_cast<size_t>(length));
            std::free(value);
            derAppend(out, 0x04, bytes);
            break;
        }
        case PLIST_ARRAY: {
            std::string items;
            uint32_t count = plist_array_get_size(node);
            for (uint32_t i = 0; i < count; ++i) {
                derEncodePlist(plist_array_get_item(node, i), items);
            }
            derAppend(out, 0x30, items);
            break;
        }
        case PLIST_DICT: {
            std::vector<std::pair<std::string, plist_t>> entries;
            plist_dict_iter iter = nullptr;
            plist_dict_new_iter(node, &iter);
            if (iter != nullptr) {
                char* key = nullptr;
                plist_t value = nullptr;
                do {
                    key = nullptr;
                    value = nullptr;
                    plist_dict_next_item(node, iter, &key, &value);
                    if (key != nullptr && value != nullptr) {
                        entries.emplace_back(key, value);
                    }
                    std::free(key);
                } while (value != nullptr);
                std::free(iter);
            }
            std::sort(entries.begin(), entries.end(),
                      [](const std::pair<std::string, plist_t>& a,
                         const std::pair<std::string, plist_t>& b) { return a.first < b.first; });

            std::string content;
            for (const auto& entry : entries) {
                std::string item;
                derAppend(item, 0x0c, entry.first);
                derEncodePlist(entry.second, item);
                derAppend(content, 0x30, item);
            }
            derAppend(out, 0xb0, content);
            break;
        }
        default:
            die("unsupported entitlement value type in property list");
    }
}

// ---------------------------------------------------------------------------
// Mach-O image handling
// ---------------------------------------------------------------------------

struct MachOSlice {
    std::vector<uint8_t> data;
    uint32_t cputype = 0;
    uint32_t cpusubtype = 0;

    bool parsed = false;
    bool is64 = false;
    bool bigEndian = false;
    uint32_t fileType = 0;
    uint64_t textVmSize = 0;
    uint32_t sigCommandOffset = 0;
    uint32_t codeLimit = 0;
    uint32_t signatureSize = 0;
    uint32_t linkEditCommandOffset = 0;
    uint64_t linkEditFileOffset = 0;
    uint64_t linkEditFileSize = 0;
    uint64_t linkEditVmSize = 0;
    uint32_t loadCommandsFreeSpace = 0;
    std::string embeddedInfoPlist;

    uint32_t rd32(size_t offset) const {
        uint32_t value = 0;
        std::memcpy(&value, data.data() + offset, sizeof(value));
        return bigEndian ? swap32(value) : value;
    }
    uint64_t rd64(size_t offset) const {
        uint64_t value = 0;
        std::memcpy(&value, data.data() + offset, sizeof(value));
        return bigEndian ? swap64(value) : value;
    }
    void wr32(size_t offset, uint32_t value) {
        if (bigEndian) value = swap32(value);
        std::memcpy(data.data() + offset, &value, sizeof(value));
    }
    void wr64(size_t offset, uint64_t value) {
        if (bigEndian) value = swap64(value);
        std::memcpy(data.data() + offset, &value, sizeof(value));
    }

    uint32_t headerSize() const { return is64 ? 32u : 28u; }

    bool parse() {
        parsed = false;
        if (data.size() < 4) return false;

        const uint32_t magic = readBe32(data.data());
        if (magic == kMachMagic || magic == kMachMagic64) {
            bigEndian = true;
        } else if (magic == kMachCigam || magic == kMachCigam64) {
            bigEndian = false;
        } else {
            return false;
        }
        is64 = (magic == kMachMagic64 || magic == kMachCigam64);

        if (data.size() < headerSize()) return false;

        const uint32_t ncmds = rd32(16);
        const uint32_t sizeofcmds = rd32(20);
        fileType = rd32(12);

        size_t cursor = headerSize();
        for (uint32_t i = 0; i < ncmds; ++i) {
            if (cursor + 8 > data.size()) return false;
            const uint32_t cmd = rd32(cursor);
            const uint32_t cmdsize = rd32(cursor + 4);
            if (cmdsize < 8 || cursor + cmdsize > data.size()) return false;

            if (cmd == kLcSegment || cmd == kLcSegment64) {
                const bool segment64 = (cmd == kLcSegment64);
                // Every field read below is inside the fixed part of the
                // command, so the command has to be at least that long.
                const uint32_t fixedSize = segment64 ? 72 : 56;
                if (cmdsize < fixedSize) return false;

                const char* name = reinterpret_cast<const char*>(data.data() + cursor + 8);
                const bool isText = std::strncmp(name, "__TEXT", 16) == 0;
                const bool isLinkEdit = std::strncmp(name, "__LINKEDIT", 16) == 0;

                if (isText) {
                    textVmSize = segment64 ? rd64(cursor + 32) : rd32(cursor + 28);
                    const uint32_t nsects = rd32(cursor + (segment64 ? 64 : 48));
                    const size_t sectionSize = segment64 ? 80 : 68;
                    // The declared sections must fit inside the command.
                    if (static_cast<uint64_t>(nsects) * sectionSize + fixedSize > cmdsize) {
                        return false;
                    }
                    size_t sectionOffset = cursor + fixedSize;
                    const uint32_t commandsEnd = headerSize() + sizeofcmds;
                    uint32_t firstSectionOffset = 0;
                    for (uint32_t s = 0; s < nsects; ++s) {
                        const char* sectName =
                            reinterpret_cast<const char*>(data.data() + sectionOffset);
                        const uint32_t fileOffset =
                            rd32(sectionOffset + (segment64 ? 48 : 40));

                        // The load command area ends where the first section
                        // starts, whichever section that happens to be.
                        if (fileOffset > commandsEnd &&
                            (firstSectionOffset == 0 || fileOffset < firstSectionOffset)) {
                            firstSectionOffset = fileOffset;
                        }

                        if (std::strncmp(sectName, "__info_plist", 16) == 0) {
                            const uint64_t size =
                                segment64 ? rd64(sectionOffset + 40) : rd32(sectionOffset + 36);
                            if (fileOffset + size <= data.size()) {
                                embeddedInfoPlist.assign(
                                    reinterpret_cast<const char*>(data.data() + fileOffset),
                                    static_cast<size_t>(size));
                            }
                        }
                        sectionOffset += sectionSize;
                    }
                    if (firstSectionOffset != 0) {
                        loadCommandsFreeSpace = firstSectionOffset - commandsEnd;
                    }
                } else if (isLinkEdit) {
                    linkEditCommandOffset = static_cast<uint32_t>(cursor);
                    if (segment64) {
                        linkEditVmSize = rd64(cursor + 32);
                        linkEditFileOffset = rd64(cursor + 40);
                        linkEditFileSize = rd64(cursor + 48);
                    } else {
                        linkEditVmSize = rd32(cursor + 28);
                        linkEditFileOffset = rd32(cursor + 32);
                        linkEditFileSize = rd32(cursor + 36);
                    }
                }
            } else if (cmd == kLcCodeSignature) {
                if (cmdsize < 16) return false;
                sigCommandOffset = static_cast<uint32_t>(cursor);
                codeLimit = rd32(cursor + 8);
                signatureSize = rd32(cursor + 12);
            }

            cursor += cmdsize;
        }

        if (sigCommandOffset == 0) {
            codeLimit = alignUp32(static_cast<uint32_t>(data.size()), 16);
            signatureSize = 0;
        }
        parsed = true;
        return true;
    }
};

struct MachOImage {
    bool fat = false;
    bool fatBigEndian = false;
    std::vector<MachOSlice> slices;

    static bool looksLikeMachO(const uint8_t* data, size_t size) {
        if (size < 4) return false;
        const uint32_t magic = readBe32(data);
        return magic == kMachMagic || magic == kMachCigam || magic == kMachMagic64 ||
               magic == kMachCigam64 || magic == kFatMagic || magic == kFatCigam;
    }

    void load(const std::vector<uint8_t>& bytes) {
        slices.clear();
        fat = false;
        fatBigEndian = false;
        if (bytes.size() < 8) die("truncated Mach-O file");

        const uint32_t magic = readBe32(bytes.data());
        if (magic == kFatMagic || magic == kFatCigam) {
            fat = true;
            fatBigEndian = (magic == kFatMagic);
            const uint8_t* header = bytes.data();
            auto read32 = [&](size_t offset) -> uint32_t {
                uint32_t value = 0;
                std::memcpy(&value, header + offset, sizeof(value));
                return fatBigEndian ? swap32(value) : value;
            };
            const uint32_t count = read32(4);
            if (count == 0 || count > 64) die("invalid fat Mach-O header");
            for (uint32_t i = 0; i < count; ++i) {
                const size_t entry = 8 + static_cast<size_t>(i) * 20;
                if (entry + 20 > bytes.size()) die("truncated fat Mach-O header");
                MachOSlice slice;
                slice.cputype = read32(entry);
                slice.cpusubtype = read32(entry + 4);
                const uint32_t offset = read32(entry + 8);
                const uint32_t size = read32(entry + 12);
                if (static_cast<size_t>(offset) + size > bytes.size()) {
                    die("truncated fat Mach-O architecture");
                }
                slice.data.assign(bytes.begin() + offset, bytes.begin() + offset + size);
                if (!slice.parse()) die("unsupported Mach-O architecture");
                slices.push_back(std::move(slice));
            }
            return;
        }

        MachOSlice slice;
        slice.data = bytes;
        if (!slice.parse()) die("not a Mach-O file");
        slices.push_back(std::move(slice));
    }

    std::vector<uint8_t> serialize() const {
        if (!fat) return slices.front().data;

        const size_t headerSize = 8 + slices.size() * 20;
        const uint32_t alignment = 16384;
        std::vector<uint32_t> offsets;
        size_t cursor = alignUp32(static_cast<uint32_t>(headerSize), alignment);
        for (const MachOSlice& slice : slices) {
            offsets.push_back(static_cast<uint32_t>(cursor));
            cursor = alignUp32(static_cast<uint32_t>(cursor + slice.data.size()), alignment);
        }
        // No trailing padding: the file ends exactly where the last slice ends.
        cursor = offsets.back() + slices.back().data.size();

        std::vector<uint8_t> out(cursor, 0);
        auto write32 = [&](size_t offset, uint32_t value) {
            if (fatBigEndian) value = swap32(value);
            std::memcpy(out.data() + offset, &value, sizeof(value));
        };
        write32(0, fatBigEndian ? kFatMagic : kFatCigam);
        write32(4, static_cast<uint32_t>(slices.size()));
        for (size_t i = 0; i < slices.size(); ++i) {
            const size_t entry = 8 + i * 20;
            write32(entry, slices[i].cputype);
            write32(entry + 4, slices[i].cpusubtype);
            write32(entry + 8, offsets[i]);
            write32(entry + 12, static_cast<uint32_t>(slices[i].data.size()));
            write32(entry + 16, 14);
            std::memcpy(out.data() + offsets[i], slices[i].data.data(), slices[i].data.size());
        }
        return out;
    }
};

// ---------------------------------------------------------------------------
// Code signature construction
// ---------------------------------------------------------------------------

std::string buildCodeDirectory(bool useSha256, const MachOSlice& slice,
                               const std::string& identifier, const std::string& teamId,
                               const std::map<uint32_t, std::string>& specialHashes,
                               uint64_t execSegFlags, bool adhoc) {
    const uint32_t hashSize = useSha256 ? 32 : 20;
    const uint8_t hashType = useSha256 ? 2 : 1;
    const uint32_t codeLimit = slice.codeLimit;

    uint32_t maxSpecialSlot = 0;
    for (const auto& entry : specialHashes) {
        if (!entry.second.empty() && entry.first > maxSpecialSlot) maxSpecialSlot = entry.first;
    }

    std::vector<std::string> specialSlots;
    specialSlots.reserve(maxSpecialSlot);
    for (uint32_t slot = maxSpecialSlot; slot >= 1; --slot) {
        auto it = specialHashes.find(slot);
        if (it != specialHashes.end() && !it->second.empty()) {
            specialSlots.push_back(it->second);
        } else {
            specialSlots.push_back(std::string(hashSize, '\0'));
        }
    }

    const uint32_t pageCount =
        (codeLimit + kCodePageSize - 1) / kCodePageSize;

    const uint32_t headerLength = 88;  // fixed size of a 0x20400 code directory
    const uint32_t identifierLength = static_cast<uint32_t>(identifier.size()) + 1;
    const uint32_t teamLength = teamId.empty() ? 0 : static_cast<uint32_t>(teamId.size()) + 1;
    const uint32_t specialLength = static_cast<uint32_t>(specialSlots.size()) * hashSize;
    const uint32_t codeSlotsLength = pageCount * hashSize;
    const uint32_t hashOffset =
        headerLength + identifierLength + teamLength + specialLength;
    const uint32_t totalLength = hashOffset + codeSlotsLength;

    std::string out;
    out.reserve(totalLength);
    out.append(headerLength, '\0');

    auto put32 = [&out](uint32_t offset, uint32_t value) {
        value = swap32(value);
        std::memcpy(&out[offset], &value, sizeof(value));
    };
    auto put64 = [&out](uint32_t offset, uint64_t value) {
        value = swap64(value);
        std::memcpy(&out[offset], &value, sizeof(value));
    };

    put32(0, kCsMagicCodeDirectory);
    put32(4, totalLength);
    put32(8, kCsVersion);
    put32(12, adhoc ? kCsAdhocFlag : 0);
    put32(16, hashOffset);
    put32(20, headerLength);
    put32(24, static_cast<uint32_t>(specialSlots.size()));
    put32(28, pageCount);
    put32(32, codeLimit);
    out[36] = static_cast<char>(hashSize);
    out[37] = static_cast<char>(hashType);
    out[38] = '\0';
    out[39] = static_cast<char>(kCodePageShift);
    put32(40, 0);   // spare2
    put32(44, 0);   // scatterOffset
    put32(48, teamId.empty() ? 0 : headerLength + identifierLength);
    put32(52, 0);   // spare3
    put64(56, 0);   // codeLimit64
    put64(64, 0);   // execSegBase
    put64(72, slice.textVmSize);
    put64(80, execSegFlags);

    out += identifier;
    out.push_back('\0');
    if (!teamId.empty()) {
        out += teamId;
        out.push_back('\0');
    }
    for (const std::string& hash : specialSlots) out += hash;

    Digest digest(useSha256 ? EVP_sha256() : EVP_sha1());
    const uint8_t* code = slice.data.data();
    uint32_t remaining = codeLimit;
    uint32_t offset = 0;
    while (remaining > 0) {
        const uint32_t chunk = std::min(remaining, kCodePageSize);
        out += digest(code + offset, chunk);
        offset += chunk;
        remaining -= chunk;
    }

    return out;
}

std::string buildRequirementsBlob(const std::string& identifier, const std::string& subjectCn) {
    if (identifier.empty() || subjectCn.empty()) {
        // Empty requirement set: magic, length and a zero count.
        std::string empty;
        for (uint32_t value : {kCsMagicRequirements, 12u, 0u}) {
            value = swap32(value);
            empty.append(reinterpret_cast<const char*>(&value), sizeof(value));
        }
        return empty;
    }

    auto append32 = [](std::string& out, uint32_t value) {
        value = swap32(value);
        out.append(reinterpret_cast<const char*>(&value), sizeof(value));
    };
    auto appendString = [&append32](std::string& out, const std::string& text) {
        append32(out, static_cast<uint32_t>(text.size()));
        out += text;
        const size_t padding = (4 - (text.size() % 4)) % 4;
        out.append(padding, '\0');
    };

    // Requirement expression opcodes used by the designated requirement below.
    constexpr uint32_t kOpIdent = 2;
    constexpr uint32_t kOpAnd = 6;
    constexpr uint32_t kOpCertField = 11;
    constexpr uint32_t kOpCertGeneric = 14;
    constexpr uint32_t kOpAppleGenericAnchor = 15;
    constexpr uint32_t kMatchEqual = 1;
    constexpr uint32_t kMatchExists = 0;
    constexpr uint32_t kSecDesignatedRequirementType = 3;

    // Apple WWDR marker OID 1.2.840.113635.100.6.2.1
    static const unsigned char kWorldwideDeveloperOid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                          0x63, 0x64, 0x06, 0x02, 0x01};

    std::string expression;
    append32(expression, 1);  // expression form

    append32(expression, kOpAnd);
    append32(expression, kOpIdent);
    appendString(expression, identifier);

    append32(expression, kOpAnd);
    append32(expression, kOpAppleGenericAnchor);

    append32(expression, kOpAnd);
    append32(expression, kOpCertField);
    append32(expression, 0);  // leaf certificate
    appendString(expression, "subject.CN");
    append32(expression, kMatchEqual);
    appendString(expression, subjectCn);

    append32(expression, kOpCertGeneric);
    append32(expression, 1);  // intermediate certificate
    append32(expression, static_cast<uint32_t>(sizeof(kWorldwideDeveloperOid)));
    expression.append(reinterpret_cast<const char*>(kWorldwideDeveloperOid),
                     sizeof(kWorldwideDeveloperOid));
    expression.append((4 - (sizeof(kWorldwideDeveloperOid) % 4)) % 4, '\0');
    append32(expression, kMatchExists);

    const uint32_t innerLength = 8 + static_cast<uint32_t>(expression.size());
    const uint32_t outerLength = 20 + innerLength;

    std::string blob;
    append32(blob, kCsMagicRequirements);
    append32(blob, outerLength);
    append32(blob, 1);  // one requirement
    append32(blob, kSecDesignatedRequirementType);
    append32(blob, 20);  // offset of the inner blob
    append32(blob, kCsMagicRequirement);
    append32(blob, innerLength);
    blob += expression;
    return blob;
}

std::string buildEntitlementsBlob(const std::string& plistXml) {
    if (plistXml.empty()) return std::string();
    std::string blob;
    uint32_t magic = swap32(kCsMagicEmbeddedEntitlements);
    uint32_t length = swap32(static_cast<uint32_t>(plistXml.size()) + 8);
    blob.append(reinterpret_cast<const char*>(&magic), sizeof(magic));
    blob.append(reinterpret_cast<const char*>(&length), sizeof(length));
    blob += plistXml;
    return blob;
}

std::string buildDerEntitlementsBlob(plist_t entitlements) {
    if (entitlements == nullptr) return std::string();
    std::string body;
    derAppend(body, 0x02, std::string(1, '\x01'));  // version 1
    derEncodePlist(entitlements, body);

    std::string payload;
    derAppend(payload, 0x70, body);

    std::string blob;
    uint32_t magic = swap32(kCsMagicEmbeddedDerEntitlements);
    uint32_t length = swap32(static_cast<uint32_t>(payload.size()) + 8);
    blob.append(reinterpret_cast<const char*>(&magic), sizeof(magic));
    blob.append(reinterpret_cast<const char*>(&length), sizeof(length));
    blob += payload;
    return blob;
}

// ---------------------------------------------------------------------------
// Signing identity (certificate + provisioning profile)
// ---------------------------------------------------------------------------

X509* loadPemCertificate(const char* pem) {
    BIO* bio = BIO_new_mem_buf(pem, -1);
    if (bio == nullptr) return nullptr;
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

struct SigningIdentity {
    X509* leaf = nullptr;
    EVP_PKEY* key = nullptr;
    std::vector<X509*> chain;
    std::vector<X509*> owned;
    std::string teamId;
    std::string subjectCn;
    std::string applicationId;
    std::string entitlementsXml;
    plist_t entitlements = nullptr;
    std::string profileData;

    SigningIdentity() = default;
    // Owns raw OpenSSL and plist handles; copying would free them twice.
    SigningIdentity(const SigningIdentity&) = delete;
    SigningIdentity& operator=(const SigningIdentity&) = delete;

    ~SigningIdentity() {
        // The leaf certificate is tracked in owned, so it is released there.
        for (X509* cert : chain) X509_free(cert);
        for (X509* cert : owned) X509_free(cert);
        if (key != nullptr) EVP_PKEY_free(key);
        if (entitlements != nullptr) plist_free(entitlements);
    }

    void load(const fs::path& p12Path, const fs::path& profilePath, const std::string& password) {
        // Explicitly load both providers: touching the legacy provider disables
        // the automatic default provider registration.
        OSSL_PROVIDER_load(nullptr, "default");
        OSSL_PROVIDER_load(nullptr, "legacy");

        // --- provisioning profile -----------------------------------------
        profileData = readFile(profilePath);
        std::string profileContent = extractCmsContent(profileData);
        if (profileContent.empty()) die("'" + profilePath.string() + "' is not a valid provisioning profile");

        PlistHolder profile(parsePlist(profileContent));
        if (profile.node == nullptr) die("cannot parse the provisioning profile payload");

        plist_t teamArray = plist_dict_get_item(profile.node, "TeamIdentifier");
        if (teamArray != nullptr && plist_array_get_size(teamArray) > 0) {
            char* value = nullptr;
            plist_get_string_val(plist_array_get_item(teamArray, 0), &value);
            teamId = value != nullptr ? value : "";
            std::free(value);
        }
        if (teamId.empty()) die("the provisioning profile has no TeamIdentifier");

        plist_t entitlements = plist_dict_get_item(profile.node, "Entitlements");
        if (entitlements == nullptr) die("the provisioning profile has no Entitlements");
        entitlementsXml = plistToString(entitlements);
        this->entitlements = plist_copy(entitlements);
        applicationId = plistString(entitlements, "application-identifier");

        // --- certificate and key ------------------------------------------
        BIO* bio = BIO_new_file(p12Path.string().c_str(), "rb");
        if (bio == nullptr) die("cannot open '" + p12Path.string() + "'");

        PKCS12* p12 = d2i_PKCS12_bio(bio, nullptr);
        if (p12 == nullptr) {
            BIO_free(bio);
            die("'" + p12Path.string() + "' is not a valid .p12 file");
        }

        STACK_OF(X509)* caCerts = nullptr;
        X509* cert = nullptr;
        EVP_PKEY* pkey = nullptr;
        if (PKCS12_parse(p12, password.c_str(), &pkey, &cert, &caCerts) != 1) {
            PKCS12_free(p12);
            BIO_free(bio);
            die("cannot unlock '" + p12Path.string() + "' (wrong password?)");
        }
        PKCS12_free(p12);
        BIO_free(bio);

        if (pkey == nullptr) die("the .p12 file contains no private key");

        // Keep only certificates that actually belong to the private key.
        if (cert != nullptr && X509_check_private_key(cert, pkey) != 1) {
            X509_free(cert);
            cert = nullptr;
        }
        if (cert == nullptr && caCerts != nullptr) {
            for (int i = 0; i < sk_X509_num(caCerts); ++i) {
                X509* candidate = sk_X509_value(caCerts, i);
                if (X509_check_private_key(candidate, pkey) == 1) {
                    cert = candidate;
                    X509_up_ref(cert);
                    break;
                }
            }
        }

        if (cert == nullptr && profile.node != nullptr) {
            plist_t certs = plist_dict_get_item(profile.node, "DeveloperCertificates");
            if (certs != nullptr) {
                for (uint32_t i = 0; i < plist_array_get_size(certs) && cert == nullptr; ++i) {
                    std::string der;
                    char* value = nullptr;
                    uint64_t length = 0;
                    plist_get_data_val(plist_array_get_item(certs, i), &value, &length);
                    if (value != nullptr) der.assign(value, static_cast<size_t>(length));
                    std::free(value);
                    const unsigned char* cursor =
                        reinterpret_cast<const unsigned char*>(der.data());
                    X509* candidate = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
                    if (candidate != nullptr) {
                        if (X509_check_private_key(candidate, pkey) == 1) {
                            cert = candidate;
                        } else {
                            X509_free(candidate);
                        }
                    }
                }
            }
        }

        if (cert == nullptr) die("no certificate in the .p12 matches the private key");

        subjectCn = certificateCommonName(cert);
        if (subjectCn.empty()) die("the signing certificate has no common name");

        leaf = cert;
        key = pkey;
        owned.push_back(cert);

        if (caCerts != nullptr) {
            // sk_X509_free releases only the stack; ownership of each
            // certificate moves to owned, so no extra reference is taken.
            for (int i = 0; i < sk_X509_num(caCerts); ++i) {
                owned.push_back(sk_X509_value(caCerts, i));
            }
            sk_X509_free(caCerts);
        }

        buildChain();
        warnAboutChainExpiry();
    }

    static std::string certificateCommonName(X509* cert) {
        const X509_NAME* name = X509_get_subject_name(cert);
        if (name == nullptr) return std::string();
        const int index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if (index < 0) return std::string();
        const X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, index);
        if (entry == nullptr) return std::string();
        const ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if (data == nullptr) return std::string();
        unsigned char* utf8 = nullptr;
        const int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (length < 0) return std::string();
        std::string out(reinterpret_cast<const char*>(utf8), static_cast<size_t>(length));
        OPENSSL_free(utf8);
        return out;
    }

    static std::string extractCmsContent(const std::string& data) {
        BIO* in = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
        if (in == nullptr) return std::string();
        CMS_ContentInfo* cms = d2i_CMS_bio(in, nullptr);
        BIO_free(in);
        if (cms == nullptr) return std::string();

        std::string content;
        ASN1_OCTET_STRING** position = CMS_get0_content(cms);
        if (position != nullptr && *position != nullptr) {
            content.assign(
                reinterpret_cast<const char*>(ASN1_STRING_get0_data(*position)),
                static_cast<size_t>(asn1StringLength(*position)));
        }
        CMS_ContentInfo_free(cms);
        return content;
    }

    // Builds the intermediate/root chain that gets embedded in the CMS blob.
    void buildChain() {
        std::vector<X509*> candidates;
        for (X509* cert : owned) {
            if (cert != leaf) candidates.push_back(cert);
        }
        for (const char* pem : kIntermediatePems) {
            X509* cert = loadPemCertificate(pem);
            if (cert != nullptr) {
                candidates.push_back(cert);
                owned.push_back(cert);
            }
        }
        for (const char* pem : kRootPems) {
            X509* cert = loadPemCertificate(pem);
            if (cert != nullptr) {
                candidates.push_back(cert);
                owned.push_back(cert);
            }
        }

        X509* current = leaf;
        for (int depth = 0; depth < 4; ++depth) {
            X509* issuer = nullptr;
            for (X509* candidate : candidates) {
                if (candidate == current) continue;
                if (X509_check_issued(candidate, current) != X509_V_OK) continue;
                bool alreadyPresent = false;
                for (X509* existing : chain) {
                    if (X509_cmp(existing, candidate) == 0) alreadyPresent = true;
                }
                if (!alreadyPresent) {
                    issuer = candidate;
                    break;
                }
            }
            if (issuer == nullptr) break;
            X509_up_ref(issuer);
            chain.push_back(issuer);
            current = issuer;
            if (X509_check_issued(issuer, issuer) == X509_V_OK) break;  // self-signed root
        }
    }

    // Reports anchors that are expired or about to expire, so a signing chain
    // never silently goes stale.
    void warnAboutChainExpiry() const {
        for (X509* cert : chain) {
            int days = 0;
            int seconds = 0;
            if (ASN1_TIME_diff(&days, &seconds, nullptr, X509_get0_notAfter(cert)) != 1) {
                continue;
            }
            const std::string name = certificateCommonName(cert);
            if (days < 0) {
                std::fprintf(stderr,
                             "warning: bundled Apple certificate '%s' has expired; "
                             "update csign\n",
                             name.c_str());
            } else if (days < 90) {
                std::fprintf(stderr,
                             "warning: bundled Apple certificate '%s' expires in %d days; "
                             "update csign\n",
                             name.c_str(), days);
            }
        }
    }

    std::string buildCmsSignature(const std::string& codeDirectory,
                                  const std::string& alternateCodeDirectory) const {
        const bool hasAlternate = !alternateCodeDirectory.empty();

        const std::string primarySha1 = sha1(codeDirectory);
        const std::string primarySha256 = sha256(codeDirectory);
        const std::string alternateSha256 =
            hasAlternate ? sha256(alternateCodeDirectory) : std::string();

        // The cdhashes attribute carries the first 20 bytes of each directory hash.
        std::string cdHashes;
        cdHashes.push_back('\0');  // placeholder, replaced below
        {
            PlistHolder list(plist_new_dict());
            plist_t hashes = plist_new_array();
            const std::string& first = hasAlternate ? primarySha1 : primarySha256;
            plist_array_append_item(hashes, plist_new_data(first.data(), 20));
            if (hasAlternate) {
                plist_array_append_item(hashes, plist_new_data(alternateSha256.data(), 20));
            }
            plist_dict_set_item(list.node, "cdhashes", hashes);
            cdHashes = plistToString(list.node);
        }

        STACK_OF(X509)* others = sk_X509_new_null();
        if (others == nullptr) die("out of memory");
        for (X509* cert : chain) {
            if (X509_up_ref(cert) != 1) die("out of memory");
            if (sk_X509_push(others, cert) == 0) {
                X509_free(cert);
                die("out of memory");
            }
        }

        BIO* content = BIO_new_mem_buf(codeDirectory.data(),
                                       static_cast<int>(codeDirectory.size()));
        if (content == nullptr) die("out of memory");

        const int flags = CMS_PARTIAL | CMS_DETACHED | CMS_NOSMIMECAP | CMS_BINARY;
        CMS_ContentInfo* cms = CMS_sign(nullptr, nullptr, others, nullptr, flags);
        if (cms == nullptr) {
            BIO_free(content);
            die("cannot create the CMS signature");
        }

        CMS_SignerInfo* signer = CMS_add1_signer(cms, leaf, key, EVP_sha256(), flags);
        if (signer == nullptr) {
            CMS_ContentInfo_free(cms);
            BIO_free(content);
            die("cannot add the signing certificate");
        }

        ASN1_OBJECT* hashListOid = OBJ_txt2obj("1.2.840.113635.100.9.1", 1);
        if (hashListOid == nullptr ||
            CMS_signed_add1_attr_by_OBJ(signer, hashListOid, V_ASN1_OCTET_STRING,
                                        cdHashes.data(),
                                        static_cast<int>(cdHashes.size())) != 1) {
            ASN1_OBJECT_free(hashListOid);
            CMS_ContentInfo_free(cms);
            BIO_free(content);
            die("cannot attach the cdhashes attribute");
        }
        ASN1_OBJECT_free(hashListOid);

        // Attribute 1.2.840.113635.100.9.2 carries the full digest of the signed
        // code directory as SET { SEQUENCE { OID sha256, OCTET STRING digest } }.
        {
            const std::string& digest = primarySha256;
            static const unsigned char kSha256Oid[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                                                       0x03, 0x04, 0x02, 0x01};
            static const unsigned char kAttributeOid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                          0x63, 0x64, 0x09, 0x02};
            std::string sequenceContent;
            derAppend(sequenceContent, 0x06,
                      std::string(reinterpret_cast<const char*>(kSha256Oid), sizeof(kSha256Oid)));
            derAppend(sequenceContent, 0x04, digest);

            std::string sequence;
            derAppend(sequence, 0x30, sequenceContent);
            std::string attributeSet;
            derAppend(attributeSet, 0x31, sequence);
            std::string attributeContent;
            derAppend(attributeContent, 0x06,
                      std::string(reinterpret_cast<const char*>(kAttributeOid),
                                  sizeof(kAttributeOid)));
            attributeContent += attributeSet;
            std::string attributeDer;
            derAppend(attributeDer, 0x30, attributeContent);

            const unsigned char* cursor =
                reinterpret_cast<const unsigned char*>(attributeDer.data());
            X509_ATTRIBUTE* attribute =
                d2i_X509_ATTRIBUTE(nullptr, &cursor, static_cast<long>(attributeDer.size()));
            // CMS_signed_add1_attr takes ownership on success.
            if (attribute == nullptr || CMS_signed_add1_attr(signer, attribute) != 1) {
                X509_ATTRIBUTE_free(attribute);
                CMS_ContentInfo_free(cms);
                BIO_free(content);
                die("cannot attach the cdhash attribute");
            }
        }

        if (CMS_final(cms, content, nullptr, flags) != 1) {
            CMS_ContentInfo_free(cms);
            BIO_free(content);
            die("cannot finalize the CMS signature");
        }
        BIO_free(content);

        BIO* out = BIO_new(BIO_s_mem());
        if (out == nullptr) die("out of memory");
        if (i2d_CMS_bio(out, cms) != 1) {
            BIO_free(out);
            CMS_ContentInfo_free(cms);
            die("cannot serialize the CMS signature");
        }
        BUF_MEM* memory = nullptr;
        BIO_get_mem_ptr(out, &memory);
        std::string signature;
        if (memory != nullptr) signature.assign(memory->data, memory->length);

        BIO_free(out);
        CMS_ContentInfo_free(cms);
        sk_X509_pop_free(others, X509_free);
        return signature;
    }
};

// ---------------------------------------------------------------------------
// Mach-O signing
// ---------------------------------------------------------------------------

struct SignRequest {
    const SigningIdentity* identity = nullptr;
    std::string identifier;
    std::string infoPlistData;
    std::string codeResourcesData;
    bool mainExecutable = false;
    bool adhoc = false;
    // Used when identifier is empty: the bundle executable name.
    std::string fallbackIdentifier;
};

std::string buildSignatureBlob(const MachOSlice& slice, const SignRequest& request) {
    const SigningIdentity& identity = *request.identity;

    const std::string infoSha1 =
        request.infoPlistData.empty() ? std::string(20, '\0') : sha1(request.infoPlistData);
    const std::string infoSha256 =
        request.infoPlistData.empty() ? std::string(32, '\0') : sha256(request.infoPlistData);

    const std::string requirements =
        buildRequirementsBlob(request.identifier, identity.subjectCn);
    const std::string codeResources =
        request.codeResourcesData.empty() ? std::string() : request.codeResourcesData;

    // Entitlements belong to executables only. Attaching the application's
    // entitlements to a dynamic library makes the device reject the bundle.
    const bool attachEntitlements = request.mainExecutable && slice.fileType == kMhExecute;
    const std::string entitlementsXml =
        attachEntitlements ? identity.entitlementsXml : std::string();
    const std::string entitlementsBlob = buildEntitlementsBlob(entitlementsXml);
    const std::string derEntitlementsBlob =
        attachEntitlements ? buildDerEntitlementsBlob(identity.entitlements) : std::string();

    const uint64_t execSegFlags =
        slice.fileType == kMhExecute ? kCsExecSegMainBinary : 0;

    auto specialHashesFor = [&](bool useSha256) {
        std::map<uint32_t, std::string> hashes;
        if (!request.infoPlistData.empty()) {
            hashes[kCsSlotInfoPlist] = useSha256 ? infoSha256 : infoSha1;
        }
        if (!requirements.empty()) {
            hashes[kCsSlotRequirements] =
                useSha256 ? sha256(requirements) : sha1(requirements);
        }
        if (!codeResources.empty()) {
            hashes[kCsSlotResourceDir] =
                useSha256 ? sha256(codeResources) : sha1(codeResources);
        }
        if (!entitlementsBlob.empty()) {
            hashes[kCsSlotEntitlements] =
                useSha256 ? sha256(entitlementsBlob) : sha1(entitlementsBlob);
        }
        if (!derEntitlementsBlob.empty()) {
            hashes[kCsSlotDerEntitlements] =
                useSha256 ? sha256(derEntitlementsBlob) : sha1(derEntitlementsBlob);
        }
        return hashes;
    };

    // A SHA256 code directory is what current Apple tooling emits, and it is the
    // one the CMS signature covers.
    const std::string primary = buildCodeDirectory(
        true, slice, request.identifier, identity.teamId, specialHashesFor(true),
        execSegFlags, request.adhoc);

    std::string cmsBlob;
    if (!request.adhoc) {
        const std::string cms = identity.buildCmsSignature(primary, std::string());
        uint32_t magic = swap32(kCsMagicBlobWrapper);
        uint32_t length = swap32(static_cast<uint32_t>(cms.size()) + 8);
        cmsBlob.append(reinterpret_cast<const char*>(&magic), sizeof(magic));
        cmsBlob.append(reinterpret_cast<const char*>(&length), sizeof(length));
        cmsBlob += cms;
    }

    std::vector<std::pair<uint32_t, std::string>> blobs;
    blobs.emplace_back(kCsSlotCodeDirectory, primary);
    blobs.emplace_back(kCsSlotRequirements, requirements);
    if (!entitlementsBlob.empty()) blobs.emplace_back(kCsSlotEntitlements, entitlementsBlob);
    if (!derEntitlementsBlob.empty()) {
        blobs.emplace_back(kCsSlotDerEntitlements, derEntitlementsBlob);
    }
    if (!cmsBlob.empty()) blobs.emplace_back(kCsSlotSignature, cmsBlob);

    const uint32_t headerLength =
        static_cast<uint32_t>(sizeof(cs_super_blob_t) + blobs.size() * sizeof(cs_blob_index_t));

    uint32_t totalLength = headerLength;
    for (const auto& blob : blobs) totalLength += static_cast<uint32_t>(blob.second.size());

    std::string out;
    out.reserve(totalLength);
    uint32_t value = swap32(kCsMagicEmbeddedSignature);
    out.append(reinterpret_cast<const char*>(&value), sizeof(value));
    value = swap32(totalLength);
    out.append(reinterpret_cast<const char*>(&value), sizeof(value));
    value = swap32(static_cast<uint32_t>(blobs.size()));
    out.append(reinterpret_cast<const char*>(&value), sizeof(value));

    uint32_t offset = headerLength;
    for (const auto& blob : blobs) {
        value = swap32(blob.first);
        out.append(reinterpret_cast<const char*>(&value), sizeof(value));
        value = swap32(offset);
        out.append(reinterpret_cast<const char*>(&value), sizeof(value));
        offset += static_cast<uint32_t>(blob.second.size());
    }
    for (const auto& blob : blobs) out += blob.second;

    return out;
}

// Grows the file so the code signature fits, injecting LC_CODE_SIGNATURE when
// the binary has none yet.
void growSlice(MachOSlice& slice, uint32_t neededBlobSize) {
    if (slice.linkEditCommandOffset == 0) die("Mach-O file has no __LINKEDIT segment");
    // The segment has to start inside the file, otherwise the size arithmetic
    // below would wrap.
    if (slice.linkEditFileOffset > slice.data.size()) {
        die("Mach-O file has a __LINKEDIT segment that starts past the end of the file");
    }

    const uint32_t commandEnd = slice.headerSize() + slice.rd32(20);
    // The injected command lives inside the hashed code region, so the code
    // limit has to cover it.
    const uint32_t limit = slice.sigCommandOffset != 0
                               ? slice.codeLimit
                               : alignUp32(std::max(static_cast<uint32_t>(slice.data.size()),
                                                    commandEnd + 16),
                                           16);
    const uint32_t wanted = neededBlobSize > 0 ? neededBlobSize : 128u * 1024u;
    const uint32_t wantedSize = limit + alignUp32(wanted + 4096, 4096);
    const uint32_t oldSize = static_cast<uint32_t>(slice.data.size());

    // A signature blob is at most a few hundred kilobytes, so growth beyond
    // the current size plus a generous slack means the file is lying about
    // where the signature goes.
    constexpr uint32_t kMaxGrowthSlack = 8u * 1024u * 1024u;
    if (wantedSize > oldSize && wantedSize - oldSize > kMaxGrowthSlack) {
        die("Mach-O file requests an unreasonable code signature area");
    }

    const uint32_t newSize = std::max(wantedSize, oldSize);

    if (!slice.sigCommandOffset) {
        if (slice.loadCommandsFreeSpace < 16) {
            die("not enough load command space to add LC_CODE_SIGNATURE");
        }
        slice.data.resize(newSize, 0);
        slice.wr32(commandEnd, kLcCodeSignature);
        slice.wr32(commandEnd + 4, 16);
        slice.wr32(commandEnd + 8, limit);
        slice.wr32(commandEnd + 12, newSize - limit);
        slice.wr32(16, slice.rd32(16) + 1);
        slice.wr32(20, slice.rd32(20) + 16);
    } else {
        slice.data.resize(newSize, 0);
        slice.wr32(slice.sigCommandOffset + 12, newSize - limit);
    }

    const uint64_t grownFileSize = static_cast<uint64_t>(newSize) - slice.linkEditFileOffset;
    // Derived from the file size so a smaller signature can never wrap the
    // unsigned arithmetic, and never shrink an existing allocation.
    const uint64_t grownVmSize =
        std::max(slice.linkEditVmSize, alignUp64(grownFileSize, 16384));
    if (slice.is64) {
        slice.wr64(slice.linkEditCommandOffset + 32, grownVmSize);
        slice.wr64(slice.linkEditCommandOffset + 48, grownFileSize);
    } else {
        slice.wr32(slice.linkEditCommandOffset + 28, static_cast<uint32_t>(grownVmSize));
        slice.wr32(slice.linkEditCommandOffset + 36, static_cast<uint32_t>(grownFileSize));
    }

    if (!slice.parse()) die("Mach-O file became unreadable after growing");
}

enum class SliceSignResult { Ok, NeedSpace, Failed };

SliceSignResult signSlice(MachOSlice& slice, const SignRequest& request, uint32_t& needed) {
    needed = 0;
    if (!slice.parsed) return SliceSignResult::Failed;

    // Without LC_CODE_SIGNATURE the command must be injected first.
    if (slice.sigCommandOffset == 0) return SliceSignResult::NeedSpace;
    if (slice.codeLimit > slice.data.size()) return SliceSignResult::NeedSpace;

    const std::string blob = buildSignatureBlob(slice, request);
    const uint32_t spare = static_cast<uint32_t>(slice.data.size()) - slice.codeLimit;
    // The load command sits inside the hashed code region, so its datasize must
    // already be final before the code directory is built. Grow when it is not.
    if (blob.size() > slice.signatureSize || blob.size() > spare) {
        needed = static_cast<uint32_t>(blob.size());
        return SliceSignResult::NeedSpace;
    }

    std::memcpy(slice.data.data() + slice.codeLimit, blob.data(), blob.size());
    const uint32_t used = static_cast<uint32_t>(blob.size());
    const uint32_t allocated = std::min(slice.signatureSize, spare);
    if (allocated > used) {
        std::memset(slice.data.data() + slice.codeLimit + used, 0, allocated - used);
    }
    return SliceSignResult::Ok;
}

std::string embeddedIdentifier(const MachOSlice& slice, const std::string& fallback) {
    if (!slice.embeddedInfoPlist.empty()) {
        PlistHolder plist(parsePlist(slice.embeddedInfoPlist));
        if (plist.node != nullptr) {
            const std::string identifier = plistString(plist.node, "CFBundleIdentifier");
            if (!identifier.empty()) return identifier;
        }
    }
    return fallback;
}

void signMachOFile(const fs::path& path, const SignRequest& request) {
    const std::string contents = readFile(path);
    std::vector<uint8_t> bytes(contents.begin(), contents.end());

    MachOImage image;
    image.load(bytes);

    // The identifier is derived here so callers never have to parse the file a
    // second time just to read it.
    SignRequest effective = request;
    if (effective.identifier.empty()) {
        effective.identifier =
            embeddedIdentifier(image.slices.front(), effective.fallbackIdentifier);
    }

    for (MachOSlice& slice : image.slices) {
        // A corrupt code signature command must never be "repaired" by writing
        // the blob over the Mach-O header or over another part of the image.
        if (slice.sigCommandOffset != 0) {
            const uint64_t commandsEnd =
                static_cast<uint64_t>(slice.headerSize()) + slice.rd32(20);
            if (slice.codeLimit < commandsEnd) {
                die("cannot sign '" + path.string() +
                    "': LC_CODE_SIGNATURE points inside the load commands");
            }
            if (static_cast<uint64_t>(slice.codeLimit) + slice.signatureSize >
                slice.data.size()) {
                die("cannot sign '" + path.string() +
                    "': LC_CODE_SIGNATURE extends past the end of the file");
            }
        }

        SliceSignResult result = SliceSignResult::NeedSpace;
        for (int attempt = 0; attempt < 4 && result == SliceSignResult::NeedSpace; ++attempt) {
            uint32_t needed = 0;
            result = signSlice(slice, effective, needed);
            if (result == SliceSignResult::NeedSpace) growSlice(slice, needed);
        }
        if (result == SliceSignResult::Failed) {
            die("cannot sign '" + path.string() + "': the Mach-O image could not be read");
        }
        if (result != SliceSignResult::Ok) {
            die("cannot sign '" + path.string() + "': not enough room for the code signature");
        }
    }

    const std::vector<uint8_t> rebuilt = image.serialize();
    writeFile(path, rebuilt.data(), rebuilt.size());
    // Some archives record a non-executable mode for Mach-O files. The device
    // needs them executable, and the mode is carried into the output archive.
    chmod(path.string().c_str(), 0755);
}

// ---------------------------------------------------------------------------
// Bundle sealing
// ---------------------------------------------------------------------------

struct BundleNode {
    fs::path dir;
    std::string relativePath;
    std::string bundleId;
    std::string executable;
    std::string name;
    std::string version;
    std::string infoPlist;
    std::vector<BundleNode> children;
};

bool endsWithIgnoreCase(const std::string& text, const std::string& suffix) {
    if (text.size() <= suffix.size()) return false;
    const size_t offset = text.size() - suffix.size();
    for (size_t i = 0; i < suffix.size(); ++i) {
        const unsigned char left = static_cast<unsigned char>(text[offset + i]);
        const unsigned char right = static_cast<unsigned char>(suffix[i]);
        if (std::tolower(left) != std::tolower(right)) return false;
    }
    return true;
}

bool hasBundleSuffix(const std::string& name) {
    static const char* const kSuffixes[] = {".app", ".appex", ".framework", ".xctest"};
    for (const char* suffix : kSuffixes) {
        if (endsWithIgnoreCase(name, suffix)) return true;
    }
    return false;
}

void loadBundleInfo(BundleNode& node) {
    std::string info;
    if (!readFileIfExists(node.dir / "Info.plist", info)) {
        node.bundleId.clear();
        return;
    }
    node.infoPlist = info;
    PlistHolder plist(parsePlist(info));
    if (plist.node == nullptr) return;
    node.bundleId = plistString(plist.node, "CFBundleIdentifier");
    node.executable = plistString(plist.node, "CFBundleExecutable");
    node.version = plistString(plist.node, "CFBundleVersion");
    node.name = plistString(plist.node, "CFBundleDisplayName");
    if (node.name.empty()) node.name = plistString(plist.node, "CFBundleName");
    if (node.name.empty()) node.name = node.executable;
}

void scanBundles(const fs::path& dir, BundleNode& node, const fs::path& appRoot) {
    std::error_code ec;
    std::vector<fs::path> entries;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        entries.push_back(it->path());
    }
    std::sort(entries.begin(), entries.end());

    for (const fs::path& entry : entries) {
        std::error_code statusError;
        if (!fs::is_directory(entry, statusError) || fs::is_symlink(entry, statusError)) continue;
        if (!hasBundleSuffix(entry.filename().string())) {
            // Plain directory: keep looking for bundles inside it.
            scanBundles(entry, node, appRoot);
            continue;
        }
        BundleNode child;
        child.dir = entry;
        child.relativePath = fs::relative(entry, appRoot, statusError).string();
        if (statusError) child.relativePath = entry.filename().string();
        loadBundleInfo(child);
        scanBundles(entry, child, appRoot);
        node.children.push_back(std::move(child));
    }
}

void collectNestedBundleDirs(const BundleNode& node, std::set<fs::path>& dirs) {
    for (const BundleNode& child : node.children) {
        dirs.insert(child.dir);
        collectNestedBundleDirs(child, dirs);
    }
}

void collectSymlinks(const fs::path& dir, const std::set<fs::path>& skip,
                     std::vector<fs::path>& links) {
    std::error_code ec;
    std::vector<fs::path> entries;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        entries.push_back(it->path());
    }
    std::sort(entries.begin(), entries.end());

    for (const fs::path& entry : entries) {
        if (skip.count(entry) > 0) continue;
        std::error_code statusError;
        if (fs::is_symlink(entry, statusError)) {
            links.push_back(entry);
        } else if (fs::is_directory(entry, statusError)) {
            collectSymlinks(entry, skip, links);
        }
    }
}

void collectFiles(const fs::path& dir, const std::set<fs::path>& skip,
                  std::vector<fs::path>& files) {
    std::error_code ec;
    std::vector<fs::path> entries;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        entries.push_back(it->path());
    }
    std::sort(entries.begin(), entries.end());

    for (const fs::path& entry : entries) {
        if (skip.count(entry) > 0) continue;
        std::error_code statusError;
        // Symbolic links are sealed by target and must never be followed.
        if (fs::is_symlink(entry, statusError)) continue;
        if (fs::is_directory(entry, statusError)) {
            collectFiles(entry, skip, files);
        } else {
            files.push_back(entry);
        }
    }
}

bool isMachOFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    unsigned char header[4] = {0, 0, 0, 0};
    in.read(reinterpret_cast<char*>(header), 4);
    if (in.gcount() != 4) return false;
    return MachOImage::looksLikeMachO(header, 4);
}


struct BundleSigner {
    SigningIdentity* identity = nullptr;
    bool adhoc = false;
    // Set once the app's own executable has been signed, so callers can refuse
    // to report success for a bundle that contains nothing to sign.
    bool sealedMainExecutable = false;

    void signNode(const BundleNode& node) {
        const bool isRoot = node.relativePath.empty() || node.relativePath == ".";
        std::set<fs::path> nested;
        collectNestedBundleDirs(node, nested);

        // Loose Mach-O files that belong to this bundle are signed first, so
        // their final bytes are what the seal hashes below.
        std::vector<fs::path> files;
        collectFiles(node.dir, nested, files);
        for (const fs::path& file : files) {
            if (!isMachOFile(file)) continue;
            if (!node.executable.empty() && file.filename().string() == node.executable) {
                continue;  // signed last, with the Info.plist hash
            }
            SignRequest request;
            request.identity = identity;
            request.adhoc = adhoc;
            request.mainExecutable = false;
            request.fallbackIdentifier = file.filename().string();
            signMachOFile(file, request);
        }

        for (const BundleNode& child : node.children) signNode(child);

        // The provisioning profile must be inside the app bundle before the
        // seal is generated. Without it the device cannot authorize the
        // entitlements, so the app installs but is killed the moment it starts.
        // Extensions carry no entitlements here, so they get no profile either.
        const bool isAppBundle = node.relativePath.empty() || node.relativePath == "." ||
                                 endsWithIgnoreCase(node.relativePath, ".app");
        if (identity != nullptr && !identity->profileData.empty() && isAppBundle) {
            writeFile(node.dir / "embedded.mobileprovision", identity->profileData);
        }

        const std::string codeResources = generateCodeResources(node.dir, node.executable);
        if (!codeResources.empty()) {
            fs::path signatureDir = node.dir / "_CodeSignature";
            std::error_code ec;
            fs::create_directories(signatureDir, ec);
            writeFile(signatureDir / "CodeResources", codeResources);
        }

        if (node.executable.empty()) {
            if (isRoot) die("the app bundle has no CFBundleExecutable");
            return;
        }
        // CFBundleExecutable comes from an untrusted Info.plist. It names a
        // file inside the bundle, never a path, so separators are rejected.
        if (node.executable == "." || node.executable == ".." ||
            node.executable.find('/') != std::string::npos ||
            node.executable.find('\\') != std::string::npos) {
            const std::string bundleLabel = (node.relativePath.empty() || node.relativePath == ".")
                                                 ? node.dir.filename().string()
                                                 : node.relativePath;
            die("bundle '" + bundleLabel + "' has an unsafe CFBundleExecutable: '" +
                node.executable + "'");
        }
        fs::path executablePath = node.dir / node.executable;
        std::error_code ec;
        if (!fs::is_regular_file(executablePath, ec)) {
            if (isRoot) {
                die("the app bundle executable '" + node.executable + "' is missing");
            }
            return;
        }

        SignRequest request;
        request.identity = identity;
        request.adhoc = adhoc;
        // Entitlements belong to the app itself. An app extension is a separate
        // process with its own bundle identifier, and the single profile loaded
        // here cannot authorize it, so it is sealed like any other nested code.
        request.mainExecutable = node.relativePath.empty() || node.relativePath == ".";
        request.identifier = node.bundleId.empty() ? node.executable : node.bundleId;
        request.infoPlistData = node.infoPlist;
        request.codeResourcesData = codeResources;
        signMachOFile(executablePath, request);
        if (isRoot) sealedMainExecutable = true;
    }

    std::string generateCodeResources(const fs::path& bundleDir,
                                     const std::string& executableName) {
        std::vector<fs::path> files;
        std::set<fs::path> empty;
        collectFiles(bundleDir, empty, files);

        std::vector<std::string> relativePaths;
        relativePaths.reserve(files.size());
        for (const fs::path& file : files) {
            const fs::path relative = file.lexically_relative(bundleDir);
            if (relative.empty()) continue;
            relativePaths.push_back(relative.generic_string());
        }
        std::sort(relativePaths.begin(), relativePaths.end());

        std::vector<fs::path> links;
        collectSymlinks(bundleDir, empty, links);

        PlistHolder root(plist_new_dict());
        if (root.node == nullptr) die("out of memory");
        plist_t filesV1 = plist_new_dict();
        plist_t filesV2 = plist_new_dict();
        plist_dict_set_item(root.node, "files", filesV1);
        plist_dict_set_item(root.node, "files2", filesV2);

        for (const std::string& relative : relativePaths) {
            if (relative == "_CodeSignature/CodeResources") continue;
            // The bundle's own main binary is sealed through the code directory
            // instead of the resource list.
            if (!executableName.empty() && relative == executableName) continue;
            const fs::path fullPath = bundleDir / relative;

            std::string contents;
            if (!readFileIfExists(fullPath, contents)) continue;

            const std::string hash1 = sha1(contents);
            const std::string hash256 = sha256(contents);

            const bool isLocalized = relative.find(".lproj/") != std::string::npos;
            static const std::string kLocVersionSuffix = ".lproj/locversion.plist";
            const bool isLocVersion =
                relative.size() >= kLocVersionSuffix.size() &&
                relative.compare(relative.size() - kLocVersionSuffix.size(),
                                 kLocVersionSuffix.size(), kLocVersionSuffix) == 0;
            const std::string baseName = fs::path(relative).filename().string();
            // Mirrors the rules2 table below, which marks these as omitted.
            const bool omitFromV2 =
                baseName == ".DS_Store" || relative == "Info.plist" || relative == "PkgInfo" ||
                isLocVersion;

            // Both resource directories store raw digests as data blobs.
            if (!isLocVersion) {
                if (isLocalized) {
                    plist_t entry = plist_new_dict();
                    plist_dict_set_item(entry, "hash", plist_new_data(hash1.data(), 20));
                    plist_dict_set_item(entry, "optional", plist_new_bool(1));
                    plist_dict_set_item(filesV1, relative.c_str(), entry);
                } else {
                    plist_dict_set_item(filesV1, relative.c_str(),
                                        plist_new_data(hash1.data(), 20));
                }
            }

            if (!omitFromV2) {
                plist_t entry = plist_new_dict();
                plist_dict_set_item(entry, "hash", plist_new_data(hash1.data(), 20));
                plist_dict_set_item(entry, "hash2", plist_new_data(hash256.data(), 32));
                if (isLocalized) plist_dict_set_item(entry, "optional", plist_new_bool(1));
                plist_dict_set_item(filesV2, relative.c_str(), entry);
            }
        }

        // Symbolic links are recorded by target, never hashed.
        for (const fs::path& link : links) {
            const fs::path relative = link.lexically_relative(bundleDir);
            if (relative.empty()) continue;
            std::error_code readError;
            const fs::path target = fs::read_symlink(link, readError);
            if (readError) continue;
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "symlink",
                                plist_new_string(target.generic_string().c_str()));
            plist_dict_set_item(filesV2, relative.generic_string().c_str(), entry);
        }

        // Legacy rule table.
        plist_t rules = plist_new_dict();
        plist_dict_set_item(root.node, "rules", rules);
        plist_dict_set_item(rules, "^.*", plist_new_bool(1));
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "optional", plist_new_bool(1));
            plist_dict_set_item(entry, "weight", plist_new_real(1000.0));
            plist_dict_set_item(rules, "^.*\\.lproj/", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "omit", plist_new_bool(1));
            plist_dict_set_item(entry, "weight", plist_new_real(1100.0));
            plist_dict_set_item(rules, "^.*\\.lproj/locversion.plist$", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "weight", plist_new_real(1010.0));
            plist_dict_set_item(rules, "^Base\\.lproj/", entry);
        }
        plist_dict_set_item(rules, "^version.plist$", plist_new_bool(1));

        // Modern rule table (used together with files2).
        plist_t rules2 = plist_new_dict();
        plist_dict_set_item(root.node, "rules2", rules2);
        plist_dict_set_item(rules2, "^.*", plist_new_bool(1));
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "weight", plist_new_real(11.0));
            plist_dict_set_item(rules2, ".*\\.dSYM($|/)", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "omit", plist_new_bool(1));
            plist_dict_set_item(entry, "weight", plist_new_real(2000.0));
            plist_dict_set_item(rules2, "^(.*/)?\\.DS_Store$", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "optional", plist_new_bool(1));
            plist_dict_set_item(entry, "weight", plist_new_real(1000.0));
            plist_dict_set_item(rules2, "^.*\\.lproj/", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "omit", plist_new_bool(1));
            plist_dict_set_item(entry, "weight", plist_new_real(1100.0));
            plist_dict_set_item(rules2, "^.*\\.lproj/locversion.plist$", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "weight", plist_new_real(1010.0));
            plist_dict_set_item(rules2, "^Base\\.lproj/", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "omit", plist_new_bool(1));
            plist_dict_set_item(entry, "weight", plist_new_real(20.0));
            plist_dict_set_item(rules2, "^Info\\.plist$", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "omit", plist_new_bool(1));
            plist_dict_set_item(entry, "weight", plist_new_real(20.0));
            plist_dict_set_item(rules2, "^PkgInfo$", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "weight", plist_new_real(20.0));
            plist_dict_set_item(rules2, "^embedded\\.provisionprofile$", entry);
        }
        {
            plist_t entry = plist_new_dict();
            plist_dict_set_item(entry, "weight", plist_new_real(20.0));
            plist_dict_set_item(rules2, "^version\\.plist$", entry);
        }

        return plistToString(root.node);
    }
};

// ---------------------------------------------------------------------------
// Zip archive helpers
// ---------------------------------------------------------------------------

struct ZipArchive {
    zip_t* handle = nullptr;

    ZipArchive() = default;
    ~ZipArchive() { close(); }
    ZipArchive(const ZipArchive&) = delete;
    ZipArchive& operator=(const ZipArchive&) = delete;

    void openRead(const fs::path& path) {
        int error = 0;
        handle = zip_open(path.string().c_str(), ZIP_RDONLY, &error);
        if (handle == nullptr) die("cannot open '" + path.string() + "' as a zip archive");
    }

    void openWrite(const fs::path& path) {
        int error = 0;
        handle = zip_open(path.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &error);
        if (handle == nullptr) die("cannot create '" + path.string() + "'");
    }

    // Returns false when libzip could not finalize the archive. Callers that
    // produced output must treat that as a failure: the file on disk is not a
    // usable archive.
    bool close() {
        if (handle == nullptr) return true;
        zip_t* closing = handle;
        handle = nullptr;
        return zip_close(closing) == 0;
    }

    bool readEntry(const std::string& name, std::string& out) const {
        zip_int64_t index = zip_name_locate(handle, name.c_str(), 0);
        if (index < 0) return false;
        zip_file_t* file = zip_fopen_index(handle, static_cast<zip_uint64_t>(index), 0);
        if (file == nullptr) return false;
        out.clear();
        char buffer[65536];
        zip_int64_t count = 0;
        while ((count = zip_fread(file, buffer, sizeof(buffer))) > 0) {
            out.append(buffer, static_cast<size_t>(count));
        }
        zip_fclose(file);
        return count >= 0;
    }

    bool hasEntry(const std::string& name) const {
        return zip_name_locate(handle, name.c_str(), 0) >= 0;
    }
};

// True when candidate is base itself or lies below it.
bool pathIsWithin(const fs::path& base, const fs::path& candidate) {
    auto b = base.begin();
    auto c = candidate.begin();
    for (; b != base.end(); ++b, ++c) {
        if (c == candidate.end() || *b != *c) return false;
    }
    return true;
}

void extractArchive(const fs::path& archivePath, const fs::path& destination) {
    ZipArchive archive;
    archive.openRead(archivePath);

    const zip_int64_t count = zip_get_num_entries(archive.handle, 0);
    for (zip_int64_t i = 0; i < count; ++i) {
        const char* name = zip_get_name(archive.handle, static_cast<zip_uint64_t>(i), 0);
        if (name == nullptr) continue;
        std::string entryName = name;
        const bool declaredDirectory = !entryName.empty() && entryName.back() == '/';

        // Reject absolute paths and parent escapes.
        if (entryName.empty() || entryName[0] == '/') continue;
        bool unsafe = false;
        {
            size_t start = 0;
            while (start <= entryName.size()) {
                size_t end = entryName.find('/', start);
                if (end == std::string::npos) end = entryName.size();
                if (entryName.compare(start, end - start, "..") == 0) unsafe = true;
                start = end + 1;
            }
        }
        if (unsafe) continue;
        while (!entryName.empty() && entryName.back() == '/') entryName.pop_back();
        if (entryName.empty()) continue;

        const fs::path target = destination / entryName;
        std::error_code ec;

        // An entry may sit below a symbolic link created earlier in the same
        // archive. Resolving the parent catches that, so nothing is ever
        // written through a link that points out of the staging directory.
        const fs::path resolvedBase = fs::weakly_canonical(destination, ec);
        if (ec) die("cannot resolve '" + destination.string() + "'");
        const fs::path resolvedParent = fs::weakly_canonical(target.parent_path(), ec);
        if (ec) die("cannot resolve '" + target.parent_path().string() + "'");
        if (!pathIsWithin(resolvedBase, resolvedParent)) {
            die("refusing to extract '" + entryName + "' outside the staging directory");
        }

        fs::create_directories(target.parent_path(), ec);

        zip_uint8_t opsys = 0;
        zip_uint32_t attributes = 0;
        zip_file_get_external_attributes(archive.handle, static_cast<zip_uint64_t>(i), 0,
                                        &opsys, &attributes);
        const mode_t mode = (opsys == ZIP_OPSYS_UNIX) ? static_cast<mode_t>(attributes >> 16)
                                                      : static_cast<mode_t>(0644);

        if (declaredDirectory || S_ISDIR(mode)) {
            fs::create_directories(target, ec);
            continue;
        }

        zip_file_t* file = zip_fopen_index(archive.handle, static_cast<zip_uint64_t>(i), 0);
        if (file == nullptr) die("cannot read '" + entryName + "' from the archive");

        std::string contents;
        char buffer[65536];
        zip_int64_t got = 0;
        while ((got = zip_fread(file, buffer, sizeof(buffer))) > 0) {
            contents.append(buffer, static_cast<size_t>(got));
        }
        zip_fclose(file);
        if (got < 0) die("cannot read '" + entryName + "' from the archive");

        if (S_ISLNK(mode)) {
            fs::remove(target, ec);
            if (symlink(contents.c_str(), target.string().c_str()) != 0) {
                die("cannot create symbolic link '" + target.string() + "'");
            }
            continue;
        }

        writeFile(target, contents);
        // Setuid, setgid and sticky bits are dropped: they mean nothing inside
        // an app bundle and must not survive into the signed package.
        const mode_t permissions = (mode & 0777) != 0 ? (mode & 0777) : 0644;
        chmod(target.string().c_str(), permissions);
    }
}

void addDirectoryToArchive(zip_t* archive, const fs::path& root, const fs::path& current) {
    std::error_code ec;
    std::vector<fs::path> entries;
    for (fs::directory_iterator it(current, fs::directory_options::skip_permission_denied, ec),
         end;
         !ec && it != end; it.increment(ec)) {
        entries.push_back(it->path());
    }
    std::sort(entries.begin(), entries.end());

    for (const fs::path& entry : entries) {
        // Lexical names only: resolving links would rename the entry after its
        // target and collide with the real file.
        const fs::path relative = entry.lexically_relative(root);
        if (relative.empty()) continue;
        const std::string name = relative.generic_string();

        std::error_code statusError;
        if (fs::is_symlink(entry, statusError)) {
            std::error_code readError;
            const fs::path target = fs::read_symlink(entry, readError);
            if (readError) continue;
            const std::string linkTarget = target.generic_string();
            if (linkTarget.empty()) continue;

            // libzip keeps this buffer until the archive is closed, so it gets a
            // heap copy and takes over releasing it.
            char* buffer = static_cast<char*>(std::malloc(linkTarget.size()));
            if (buffer == nullptr) die("out of memory");
            std::memcpy(buffer, linkTarget.data(), linkTarget.size());
            zip_source_t* source = zip_source_buffer(archive, buffer, linkTarget.size(), 1);
            if (source == nullptr) {
                std::free(buffer);
                die("cannot add symbolic link '" + name + "'");
            }
            const zip_int64_t index =
                zip_file_add(archive, name.c_str(), source, ZIP_FL_ENC_UTF_8);
            if (index < 0) {
                zip_source_free(source);
                die("cannot add '" + name + "' to the archive");
            }
            zip_file_set_external_attributes(archive, static_cast<zip_uint64_t>(index), 0,
                                             ZIP_OPSYS_UNIX, (S_IFLNK | 0777) << 16);
        } else if (fs::is_directory(entry, statusError)) {
            addDirectoryToArchive(archive, root, entry);
        } else {
            zip_source_t* source = zip_source_file(archive, entry.string().c_str(), 0, -1);
            if (source == nullptr) die("cannot add '" + name + "' to the archive");
            const zip_int64_t index =
                zip_file_add(archive, name.c_str(), source, ZIP_FL_ENC_UTF_8);
            if (index < 0) {
                zip_source_free(source);
                die("cannot add '" + name + "' to the archive");
            }
            struct stat info {};
            if (stat(entry.string().c_str(), &info) == 0) {
                zip_file_set_external_attributes(
                    archive, static_cast<zip_uint64_t>(index), 0, ZIP_OPSYS_UNIX,
                    static_cast<zip_uint32_t>(info.st_mode & 0777) << 16);
            }
        }
    }
}

void createArchive(const fs::path& source, const fs::path& archivePath) {
    std::error_code ec;
    if (!archivePath.parent_path().empty()) fs::create_directories(archivePath.parent_path(), ec);
    ZipArchive archive;
    archive.openWrite(archivePath);
    addDirectoryToArchive(archive.handle, source, source);
    if (!archive.close()) {
        std::error_code removeError;
        fs::remove(archivePath, removeError);
        die("cannot finalize '" + archivePath.string() + "'");
    }
}

// ---------------------------------------------------------------------------
// .ipa inspection
// ---------------------------------------------------------------------------

struct IpaInfo {
    std::string appDirectory;  // "Payload/Foo.app"
    std::string infoPlist;
    std::string bundleId;
    std::string executable;
    std::string displayName;
    std::string version;
    bool hasCodeResources = false;
    bool signatureValid = false;
};

// Recomputes every hash the signature commits to. A signature that is merely
// present is not a valid one: the sealed bytes have to match it.
bool sliceHasSignature(const MachOSlice& slice, const std::string& infoPlist,
                       const std::string& codeResources) {
    if (!slice.parsed || slice.sigCommandOffset == 0) return false;
    if (slice.signatureSize < sizeof(cs_super_blob_t)) return false;
    const uint64_t end = static_cast<uint64_t>(slice.codeLimit) + slice.signatureSize;
    if (end > slice.data.size()) return false;

    const uint8_t* base = slice.data.data() + slice.codeLimit;
    if (readBe32(base) != kCsMagicEmbeddedSignature) return false;

    const uint32_t length = readBe32(base + 4);
    const uint32_t count = readBe32(base + 8);
    if (length < 12 || length > slice.signatureSize || count > 32) return false;

    bool hasDirectory = false;
    bool hasCms = false;

    for (uint32_t i = 0; i < count; ++i) {
        const size_t indexOffset = 12 + static_cast<size_t>(i) * 8;
        if (indexOffset + 8 > length) return false;
        const uint32_t type = readBe32(base + indexOffset);
        const uint32_t offset = readBe32(base + indexOffset + 4);
        if (offset + 8 > length) return false;
        const uint32_t blobMagic = readBe32(base + offset);
        const uint32_t blobLength = readBe32(base + offset + 4);
        if (blobLength < 8 || offset + blobLength > length) return false;

        if (type == kCsSlotSignature && blobMagic == kCsMagicBlobWrapper) hasCms = true;
        if ((type != kCsSlotCodeDirectory && type != kCsSlotAlternateCodeDirectories) ||
            blobMagic != kCsMagicCodeDirectory) {
            continue;
        }
        if (blobLength < sizeof(cs_code_directory_t)) return false;

        cs_code_directory_t header {};
        std::memcpy(&header, base + offset, sizeof(header));
        const uint32_t hashOffset = swap32(header.hashOffset);
        const uint32_t nCodeSlots = swap32(header.nCodeSlots);
        const uint32_t nSpecialSlots = swap32(header.nSpecialSlots);
        const uint32_t codeLimit = swap32(header.codeLimit);
        const uint32_t hashSize = header.hashSize;
        const uint32_t hashType = header.hashType;

        if (hashType != 1 && hashType != 2) return false;
        if (hashSize != (hashType == 1 ? 20u : 32u)) return false;
        if (codeLimit > slice.data.size()) return false;
        if (static_cast<uint64_t>(hashOffset) + static_cast<uint64_t>(nCodeSlots) * hashSize >
            blobLength) {
            return false;
        }
        if (static_cast<uint64_t>(nSpecialSlots) * hashSize > hashOffset) return false;

        const uint8_t* directory = base + offset;
        Digest digest(hashType == 1 ? EVP_sha1() : EVP_sha256());

        for (uint32_t page = 0; page < nCodeSlots; ++page) {
            const uint32_t start = page * kCodePageSize;
            if (start >= codeLimit) return false;
            const uint32_t size = std::min(kCodePageSize, codeLimit - start);
            const std::string expected = digest(slice.data.data() + start, size);
            const uint8_t* stored = directory + hashOffset + static_cast<size_t>(page) * hashSize;
            if (std::memcmp(stored, expected.data(), hashSize) != 0) return false;
        }

        for (uint32_t slot = 1; slot <= nSpecialSlots; ++slot) {
            const uint8_t* stored = directory + hashOffset - static_cast<size_t>(slot) * hashSize;
            std::string expected;
            if (slot == kCsSlotInfoPlist) {
                expected = digest(infoPlist.data(), infoPlist.size());
            } else if (slot == kCsSlotResourceDir) {
                expected = digest(codeResources.data(), codeResources.size());
            } else {
                const uint8_t* blob = nullptr;
                uint32_t blobLen = 0;
                for (uint32_t j = 0; j < count; ++j) {
                    const size_t otherIndex = 12 + static_cast<size_t>(j) * 8;
                    if (readBe32(base + otherIndex) != slot) continue;
                    const uint32_t otherOffset = readBe32(base + otherIndex + 4);
                    if (otherOffset + 8 > length) return false;
                    blob = base + otherOffset;
                    blobLen = readBe32(blob + 4);
                    break;
                }
                if (blob == nullptr) {
                    // An unused slot is expected to be all zeroes.
                    static const uint8_t zeros[32] = {0};
                    if (std::memcmp(stored, zeros, hashSize) != 0) return false;
                    continue;
                }
                expected = digest(blob, blobLen);
            }
            if (std::memcmp(stored, expected.data(), hashSize) != 0) return false;
        }

        hasDirectory = true;
    }

    return hasDirectory && hasCms;
}

// Compares the sealed resource list against the files that are actually in the
// archive, so a modified payload no longer looks signed.
bool verifySealedResources(const ZipArchive& archive, const std::string& appDirectory,
                           const std::string& codeResourcesData) {
    PlistHolder root(parsePlist(codeResourcesData));
    if (root.node == nullptr) return false;

    // files2 carries SHA-256 digests and covers the files that matter; the
    // legacy list is only used when no modern one is present.
    const char* sectionName = "files2";
    plist_t entries = plist_dict_get_item(root.node, sectionName);
    if (entries == nullptr) {
        sectionName = "files";
        entries = plist_dict_get_item(root.node, sectionName);
    }
    if (entries == nullptr) return false;

    auto dataOf = [](plist_t node) {
        std::string out;
        char* raw = nullptr;
        uint64_t length = 0;
        plist_get_data_val(node, &raw, &length);
        if (raw != nullptr) out.assign(raw, static_cast<size_t>(length));
        std::free(raw);
        return out;
    };

    plist_dict_iter iter = nullptr;
    plist_dict_new_iter(entries, &iter);
    if (iter == nullptr) return false;

    bool ok = true;
    char* key = nullptr;
    plist_t value = nullptr;
    do {
        key = nullptr;
        value = nullptr;
        plist_dict_next_item(entries, iter, &key, &value);
        if (key != nullptr && value != nullptr) {
            const std::string name = key;
            std::string contents;
            const bool present = archive.readEntry(appDirectory + "/" + name, contents);

            if (plist_get_node_type(value) == PLIST_DICT) {
                plist_t symlink = plist_dict_get_item(value, "symlink");
                if (symlink != nullptr) {
                    char* target = nullptr;
                    plist_get_string_val(symlink, &target);
                    const std::string expected = target != nullptr ? target : "";
                    std::free(target);
                    if (!present || contents != expected) ok = false;
                } else if (!present) {
                    ok = false;
                } else {
                    plist_t hash1 = plist_dict_get_item(value, "hash");
                    plist_t hash2 = plist_dict_get_item(value, "hash2");
                    if (hash1 != nullptr && sha1(contents) != dataOf(hash1)) ok = false;
                    if (hash2 != nullptr && sha256(contents) != dataOf(hash2)) ok = false;
                }
            } else if (plist_get_node_type(value) == PLIST_DATA) {
                if (!present || sha1(contents) != dataOf(value)) ok = false;
            }
        }
        std::free(key);
    } while (value != nullptr);

    std::free(iter);
    return ok;
}

bool binaryHasSignature(const std::string& bytes, const std::string& infoPlist,
                        const std::string& codeResources) {
    if (bytes.size() < 8) return false;
    const uint32_t magic = readBe32(reinterpret_cast<const uint8_t*>(bytes.data()));
    if (magic == kFatMagic || magic == kFatCigam) {
        const bool bigEndian = (magic == kFatMagic);
        auto read32 = [&](size_t offset) -> uint32_t {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(bytes.data()) + offset;
            uint32_t value = 0;
            std::memcpy(&value, p, sizeof(value));
            return bigEndian ? swap32(value) : value;
        };
        const uint32_t count = read32(4);
        if (count == 0 || count > 64) return false;
        bool any = false;
        for (uint32_t i = 0; i < count; ++i) {
            const size_t entry = 8 + static_cast<size_t>(i) * 20;
            if (entry + 20 > bytes.size()) return false;
            const uint32_t offset = read32(entry + 8);
            const uint32_t size = read32(entry + 12);
            if (static_cast<size_t>(offset) + size > bytes.size()) return false;
            MachOSlice slice;
            slice.data.assign(bytes.begin() + offset, bytes.begin() + offset + size);
            if (!slice.parse() || !sliceHasSignature(slice, infoPlist, codeResources)) {
                return false;
            }
            any = true;
        }
        return any;
    }

    MachOSlice slice;
    slice.data.assign(bytes.begin(), bytes.end());
    if (!slice.parse()) return false;
    return sliceHasSignature(slice, infoPlist, codeResources);
}

IpaInfo inspectIpa(const fs::path& ipaPath) {
    ZipArchive archive;
    archive.openRead(ipaPath);

    IpaInfo info;
    const zip_int64_t count = zip_get_num_entries(archive.handle, 0);
    for (zip_int64_t i = 0; i < count; ++i) {
        const char* name = zip_get_name(archive.handle, static_cast<zip_uint64_t>(i), 0);
        if (name == nullptr) continue;
        const std::string entryName = name;
        if (entryName.compare(0, 8, "Payload/") != 0) continue;
        const size_t slash = entryName.find('/', 8);
        if (slash == std::string::npos) continue;
        const std::string candidate = entryName.substr(0, slash);
        if (endsWithIgnoreCase(candidate, ".app")) {
            info.appDirectory = candidate;
            break;
        }
    }
    if (info.appDirectory.empty()) die("no Payload/*.app bundle found in '" + ipaPath.string() + "'");

    if (!archive.readEntry(info.appDirectory + "/Info.plist", info.infoPlist)) {
        die("'" + ipaPath.string() + "' has no Info.plist");
    }
    PlistHolder plist(parsePlist(info.infoPlist));
    if (plist.node == nullptr) die("cannot parse the Info.plist inside '" + ipaPath.string() + "'");

    info.bundleId = plistString(plist.node, "CFBundleIdentifier");
    info.executable = plistString(plist.node, "CFBundleExecutable");
    info.displayName = plistString(plist.node, "CFBundleDisplayName");
    if (info.displayName.empty()) info.displayName = plistString(plist.node, "CFBundleName");
    if (info.displayName.empty()) info.displayName = info.executable;
    info.version = plistString(plist.node, "CFBundleShortVersionString");
    if (info.version.empty()) info.version = plistString(plist.node, "CFBundleVersion");

    info.hasCodeResources = archive.hasEntry(info.appDirectory + "/_CodeSignature/CodeResources");

    if (!info.executable.empty()) {
        std::string binary;
        std::string codeResources;
        archive.readEntry(info.appDirectory + "/_CodeSignature/CodeResources", codeResources);
        if (archive.readEntry(info.appDirectory + "/" + info.executable, binary)) {
            info.signatureValid =
                binaryHasSignature(binary, info.infoPlist, codeResources);
        }
        if (info.signatureValid && !codeResources.empty()) {
            info.signatureValid =
                verifySealedResources(archive, info.appDirectory, codeResources);
        }
    }

    return info;
}

// ---------------------------------------------------------------------------
// Device installation
// ---------------------------------------------------------------------------

struct DeviceSession {
    idevice_t device = nullptr;
    lockdownd_client_t lockdown = nullptr;
    instproxy_client_t instproxy = nullptr;
    afc_client_t afc = nullptr;
    std::string name;

    ~DeviceSession() {
        if (afc != nullptr) afc_client_free(afc);
        if (instproxy != nullptr) instproxy_client_free(instproxy);
        if (lockdown != nullptr) lockdownd_client_free(lockdown);
        if (device != nullptr) idevice_free(device);
    }

    void open() {
        const enum idevice_options options = static_cast<enum idevice_options>(
            IDEVICE_LOOKUP_USBMUX | IDEVICE_LOOKUP_NETWORK);
        if (idevice_new_with_options(&device, nullptr, options) != IDEVICE_E_SUCCESS) {
            die("no iOS device found (connect it over USB or make sure Wi-Fi sync is enabled)");
        }

        if (lockdownd_client_new_with_handshake(device, &lockdown, "csign") !=
            LOCKDOWN_E_SUCCESS) {
            die("cannot connect to lockdownd (is the device paired and trusted?)");
        }

        plist_t deviceName = nullptr;
        if (lockdownd_get_value(lockdown, nullptr, "DeviceName", &deviceName) ==
                LOCKDOWN_E_SUCCESS &&
            deviceName != nullptr) {
            char* value = nullptr;
            plist_get_string_val(deviceName, &value);
            if (value != nullptr) name = value;
            std::free(value);
            plist_free(deviceName);
        }
        if (name.empty()) name = "device";
    }

    void startInstallProxy() {
        lockdownd_service_descriptor_t service = nullptr;
        if (lockdownd_start_service(lockdown, "com.apple.mobile.installation_proxy", &service) !=
                LOCKDOWN_E_SUCCESS ||
            service == nullptr) {
            die("cannot start the installation proxy service");
        }
        const instproxy_error_t error = instproxy_client_new(device, service, &instproxy);
        lockdownd_service_descriptor_free(service);
        if (error != INSTPROXY_E_SUCCESS) die("cannot connect to the installation proxy");
    }

    void startAfc() {
        lockdownd_service_descriptor_t service = nullptr;
        if (lockdownd_start_service(lockdown, "com.apple.afc", &service) !=
                LOCKDOWN_E_SUCCESS ||
            service == nullptr) {
            die("cannot start the AFC service");
        }
        const afc_error_t error = afc_client_new(device, service, &afc);
        lockdownd_service_descriptor_free(service);
        if (error != AFC_E_SUCCESS) die("cannot connect to AFC");
    }

    void uploadFile(const fs::path& local, const std::string& remote) {
        FILE* file = std::fopen(local.string().c_str(), "rb");
        if (file == nullptr) die("cannot read '" + local.string() + "'");

        uint64_t handle = 0;
        if (afc_file_open(afc, remote.c_str(), AFC_FOPEN_WRONLY, &handle) != AFC_E_SUCCESS) {
            std::fclose(file);
            die("cannot open '" + remote + "' on the device");
        }

        char buffer[1 << 20];
        size_t read = 0;
        while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
            size_t written = 0;
            while (written < read) {
                uint32_t chunk = 0;
                if (afc_file_write(afc, handle, buffer + written,
                                   static_cast<uint32_t>(read - written),
                                   &chunk) != AFC_E_SUCCESS ||
                    chunk == 0) {
                    afc_file_close(afc, handle);
                    std::fclose(file);
                    // Leave no partial package behind on the device.
                    afc_remove_path(afc, remote.c_str());
                    die("cannot upload '" + local.filename().string() + "' to the device");
                }
                written += chunk;
            }
        }
        afc_file_close(afc, handle);
        std::fclose(file);
    }
};

struct InstallProgress {
    std::string label;
    std::string device;
    std::mutex mutex;
    bool completed = false;
    bool failed = false;
    std::string error;
};

// Runs on the installation proxy's status thread.
void installStatusCallback(plist_t command, plist_t status, void* userData) {
    (void)command;
    InstallProgress* progress = static_cast<InstallProgress*>(userData);
    if (progress == nullptr || status == nullptr) return;

    char* errorName = nullptr;
    char* errorDescription = nullptr;
    uint64_t errorCode = 0;
    instproxy_status_get_error(status, &errorName, &errorDescription, &errorCode);
    (void)errorCode;

    if (errorName != nullptr) {
        std::lock_guard<std::mutex> lock(progress->mutex);
        progress->failed = true;
        progress->error = errorName;
        if (errorDescription != nullptr) {
            progress->error += ": ";
            progress->error += errorDescription;
        }
        std::free(errorName);
        std::free(errorDescription);
        return;
    }

    char* statusName = nullptr;
    instproxy_status_get_name(status, &statusName);
    const bool complete = statusName != nullptr && std::strcmp(statusName, "Complete") == 0;
    std::free(statusName);

    int percent = -1;
    instproxy_status_get_percent_complete(status, &percent);
    if (percent >= 0) {
        std::printf("\rInstalling %s to %s: %d%%", progress->label.c_str(),
                    progress->device.c_str(), percent);
        std::fflush(stdout);
    }

    if (complete) {
        std::lock_guard<std::mutex> lock(progress->mutex);
        progress->completed = true;
    }
}

void installIpa(const fs::path& ipaPath, const std::string& label) {
    const IpaInfo info = inspectIpa(ipaPath);
    if (info.bundleId.empty()) {
        die("'" + ipaPath.string() + "' has no CFBundleIdentifier");
    }

    // Declared before the session so it outlives it: the installation proxy
    // keeps a status thread that writes here until the session is closed.
    InstallProgress progress;
    progress.label = label;

    DeviceSession session;
    session.open();
    session.startInstallProxy();
    session.startAfc();

    char** entries = nullptr;
    if (afc_get_file_info(session.afc, "PublicStaging", &entries) != AFC_E_SUCCESS) {
        if (afc_make_directory(session.afc, "PublicStaging") != AFC_E_SUCCESS) {
            die("cannot create the staging directory on the device");
        }
    }
    if (entries != nullptr) {
        for (int i = 0; entries[i] != nullptr; ++i) std::free(entries[i]);
        std::free(entries);
    }

    const std::string staging = "PublicStaging/" + info.bundleId;
    std::printf("Installing %s to %s: 0%%", label.c_str(), session.name.c_str());
    std::fflush(stdout);

    session.uploadFile(ipaPath, staging);

    progress.device = session.name;

    plist_t options = instproxy_client_options_new();
    if (!info.bundleId.empty()) {
        instproxy_client_options_add(options, "CFBundleIdentifier", info.bundleId.c_str(),
                                     nullptr);
    }
    const instproxy_error_t installError =
        instproxy_install(session.instproxy, staging.c_str(), options, installStatusCallback,
                          &progress);
    instproxy_client_options_free(options);

    if (installError != INSTPROXY_E_SUCCESS) {
        std::printf("\n");
        die("installation failed (installation proxy error " +
            std::to_string(static_cast<int>(installError)) + ")");
    }

    // A status callback switches the installation proxy into asynchronous mode,
    // so the result has to be collected from the status thread.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(15);
    bool completed = false;
    bool failed = false;
    std::string error;
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lock(progress.mutex);
            completed = progress.completed;
            failed = progress.failed;
            error = progress.error;
        }
        if (completed || failed) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    if (failed) {
        std::printf("\n");
        die("installation failed: " + error);
    }
    if (!completed) {
        std::printf("\n");
        die("timed out waiting for the installation to finish");
    }

    // Best effort: the staged package is no longer needed once installed.
    afc_remove_path(session.afc, staging.c_str());

    std::printf("\n%s successfully installed to %s\n", label.c_str(), session.name.c_str());
}

// ---------------------------------------------------------------------------
// Saved certificate store (~/.csign)
// ---------------------------------------------------------------------------

fs::path certificateDirectory() {
    const char* home = std::getenv("HOME");
    if (home == nullptr) die("HOME is not set");
    return fs::path(home) / ".csign";
}

struct SavedCertificate {
    std::string version;
    std::string name;
    std::string pkey;
    std::string prov;
    std::string password;
};

std::string jsonEscape(const std::string& value) {
    std::string out;
    for (char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

bool jsonReadString(const std::string& source, const std::string& key, std::string& out) {
    const std::string needle = "\"" + key + "\"";
    size_t position = 0;
    while ((position = source.find(needle, position)) != std::string::npos) {
        size_t cursor = position + needle.size();
        while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor]))) {
            ++cursor;
        }
        if (cursor >= source.size() || source[cursor] != ':') {
            position = cursor;
            continue;
        }
        ++cursor;
        while (cursor < source.size() && std::isspace(static_cast<unsigned char>(source[cursor]))) {
            ++cursor;
        }
        if (cursor >= source.size() || source[cursor] != '"') {
            position = cursor;
            continue;
        }
        ++cursor;
        std::string value;
        while (cursor < source.size() && source[cursor] != '"') {
            if (source[cursor] == '\\' && cursor + 1 < source.size()) {
                const char escaped = source[cursor + 1];
                switch (escaped) {
                    case 'n': value.push_back('\n'); break;
                    case 'r': value.push_back('\r'); break;
                    case 't': value.push_back('\t'); break;
                    default: value.push_back(escaped); break;
                }
                cursor += 2;
            } else {
                value.push_back(source[cursor]);
                ++cursor;
            }
        }
        out = value;
        return true;
    }
    return false;
}

// Returns the text inside the object that follows "key", so a field is never
// picked up from the wrong nesting level.
bool jsonObjectSlice(const std::string& source, const std::string& key, std::string& out) {
    const std::string needle = "\"" + key + "\"";
    const size_t keyPos = source.find(needle);
    if (keyPos == std::string::npos) return false;
    const size_t start = source.find('{', keyPos + needle.size());
    if (start == std::string::npos) return false;

    int depth = 0;
    bool inString = false;
    for (size_t i = start; i < source.size(); ++i) {
        const char c = source[i];
        if (inString) {
            if (c == '\\') {
                ++i;
            } else if (c == '"') {
                inString = false;
            }
            continue;
        }
        if (c == '"') {
            inString = true;
        } else if (c == '{') {
            ++depth;
        } else if (c == '}') {
            if (--depth == 0) {
                out = source.substr(start + 1, i - start - 1);
                return true;
            }
        }
    }
    return false;
}

bool loadSavedCertificate(SavedCertificate& certificate) {
    const fs::path path = certificateDirectory() / "csign.json";
    std::string contents;
    if (!readFileIfExists(path, contents)) return false;

    // The file exists, so a missing field is a broken configuration rather than
    // an absent one.
    const std::string malformed = "'" + path.string() + "' is malformed";
    std::string certificateBlock;
    if (!jsonObjectSlice(contents, "certificate", certificateBlock)) {
        die(malformed + ": no certificate object");
    }
    if (!jsonReadString(certificateBlock, "name", certificate.name) ||
        certificate.name.empty()) {
        die(malformed + ": no certificate name");
    }
    jsonReadString(contents, "version", certificate.version);
    jsonReadString(certificateBlock, "pkey", certificate.pkey);
    jsonReadString(certificateBlock, "prov", certificate.prov);
    jsonReadString(certificateBlock, "password", certificate.password);
    if (certificate.pkey.empty() || certificate.prov.empty()) {
        die(malformed + ": no certificate paths");
    }
    return true;
}

void saveCertificateFile(const SavedCertificate& certificate) {
    const fs::path directory = certificateDirectory();
    std::error_code ec;
    fs::create_directories(directory, ec);

    std::string json = "{\n";
    json += "    \"version\": \"" + jsonEscape(kVersion) + "\",\n";
    json += "    \"certificate\": {\n";
    json += "        \"name\": \"" + jsonEscape(certificate.name) + "\",\n";
    json += "        \"pkey\": \"" + jsonEscape(certificate.pkey) + "\",\n";
    json += "        \"prov\": \"" + jsonEscape(certificate.prov) + "\",\n";
    json += "        \"password\": \"" + jsonEscape(certificate.password) + "\"\n";
    json += "    }\n";
    json += "}\n";
    writeFile(directory / "csign.json", json);
}

// True when the dotted version in a is strictly newer than the one in b.
bool versionIsNewer(const std::string& a, const std::string& b) {
    size_t aPos = 0;
    size_t bPos = 0;
    while (aPos < a.size() || bPos < b.size()) {
        auto next = [](const std::string& text, size_t& pos) -> long {
            if (pos >= text.size()) return 0;
            const size_t end = text.find('.', pos);
            const std::string part = text.substr(pos, end == std::string::npos ? std::string::npos
                                                                              : end - pos);
            pos = end == std::string::npos ? text.size() : end + 1;
            return std::strtol(part.c_str(), nullptr, 10);
        };
        const long left = next(a, aPos);
        const long right = next(b, bPos);
        if (left != right) return left > right;
    }
    return false;
}

// Keeps the stored schema version in step with the running binary, so an older
// file is upgraded the first time this build touches it. A file written by a
// newer build is left alone.
void refreshSavedCertificateVersion(const SavedCertificate& certificate) {
    if (certificate.version == kVersion) return;
    if (versionIsNewer(certificate.version, kVersion)) return;
    SavedCertificate updated = certificate;
    updated.version = kVersion;
    saveCertificateFile(updated);
}

std::string randomIdentifier() {
    static const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char buffer[8];
    if (RAND_bytes(buffer, static_cast<int>(sizeof(buffer))) != 1) {
        die("cannot generate a random certificate name");
    }
    std::string out;
    out.reserve(sizeof(buffer));
    for (unsigned char byte : buffer) {
        out.push_back(kAlphabet[byte % (sizeof(kAlphabet) - 1)]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

void printVersion() { std::printf("csign %s\n", kVersion); }

void printUsage(std::FILE* stream) {
    std::fprintf(stream,
        "csign %s - sign and install iOS apps directly to your device\n"
        "\n"
        "Usage:\n"
        "  csign sign <ipa-path> [--pkey <p12>] [--prov <profile>] [--password <pw>]\n"
        "                        [--output <path>] [-i]\n"
        "  csign install <ipa-path>\n"
        "  csign cert\n"
        "  csign check <ipa-path>\n"
        "\n"
        "Options:\n"
        "  --pkey <p12>          signing certificate (.p12)\n"
        "  --prov <profile>      provisioning profile (.mobileprovision)\n"
        "  --password <pw>       certificate password (prompted when omitted)\n"
        "  -o, --output <path>   output path (default: <name>-signed.ipa)\n"
        "  -i, --install         install right after signing\n"
        "  -v, --version         print the version and exit\n",
        kVersion);
}

struct TempDirectory {
    fs::path path;

    TempDirectory() {
        std::string pattern = (fs::temp_directory_path() / "csign-XXXXXX").string();
        std::vector<char> buffer(pattern.begin(), pattern.end());
        buffer.push_back('\0');
        if (mkdtemp(buffer.data()) == nullptr) die("cannot create a temporary directory");
        path = fs::path(buffer.data());
    }
    ~TempDirectory() {
        if (!path.empty()) {
            std::error_code ec;
            fs::remove_all(path, ec);
        }
    }
    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;
};

int commandSign(int argc, char** argv) {
    std::string ipaPath;
    std::string pkeyPath;
    std::string provPath;
    std::string password;
    std::string outputPath;
    bool havePassword = false;
    bool installAfter = false;

    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        auto takeValue = [&](const char* name) -> std::string {
            if (i + 1 >= argc) die(std::string("missing value for ") + name);
            return argv[++i];
        };
        if (argument == "--pkey") {
            pkeyPath = takeValue("--pkey");
        } else if (argument == "--prov") {
            provPath = takeValue("--prov");
        } else if (argument == "--password") {
            password = takeValue("--password");
            havePassword = true;
        } else if (argument == "--output" || argument == "-o") {
            outputPath = takeValue("--output");
        } else if (argument == "-i" || argument == "--install") {
            installAfter = true;
        } else if (!argument.empty() && argument[0] == '-') {
            die("unknown option: " + argument);
        } else if (ipaPath.empty()) {
            ipaPath = argument;
        } else {
            die("unexpected argument: " + argument);
        }
    }

    if (ipaPath.empty()) die("missing .ipa path");

    SavedCertificate saved;
    bool usingSaved = false;
    if (pkeyPath.empty() && provPath.empty()) {
        if (!loadSavedCertificate(saved)) {
            die("no certificate saved yet, run 'csign cert' or pass --pkey and --prov");
        }
        pkeyPath = expandHome(saved.pkey);
        provPath = expandHome(saved.prov);
        password = saved.password;
        havePassword = true;
        usingSaved = true;
    } else if (pkeyPath.empty() || provPath.empty()) {
        die("--pkey and --prov must be used together");
    }

    if (!havePassword) password = promptHidden("Input Password : ");
    if (usingSaved) std::printf("Signing using \"%s\" certificate...\n", saved.name.c_str());

    const fs::path input(expandHome(ipaPath));
    if (!fs::is_regular_file(input)) die("cannot find '" + ipaPath + "'");

    if (outputPath.empty()) {
        fs::path parent = input.parent_path();
        if (parent.empty()) parent = ".";
        outputPath = (parent / (input.stem().string() + "-signed.ipa")).string();
    }
    const fs::path output(expandHome(outputPath));

    SigningIdentity identity;
    identity.load(fs::path(expandHome(pkeyPath)), fs::path(expandHome(provPath)), password);
    if (usingSaved) refreshSavedCertificateVersion(saved);

    TempDirectory temporary;
    const fs::path staging = temporary.path / "payload";
    fs::create_directories(staging);
    extractArchive(input, staging);

    fs::path appBundle;
    {
        std::error_code ec;
        fs::path payload = staging / "Payload";
        if (!fs::is_directory(payload, ec)) die("the .ipa has no Payload directory");
        for (fs::directory_iterator it(payload, ec), end; !ec && it != end; it.increment(ec)) {
            const std::string name = it->path().filename().string();
            if (endsWithIgnoreCase(name, ".app")) {
                appBundle = it->path();
                break;
            }
        }
    }
    if (appBundle.empty()) die("the .ipa has no Payload/*.app bundle");

    BundleNode root;
    root.dir = appBundle;
    root.relativePath = ".";
    loadBundleInfo(root);
    scanBundles(appBundle, root, appBundle);

    BundleSigner signer;
    signer.identity = &identity;
    signer.signNode(root);
    if (!signer.sealedMainExecutable) die("the app bundle was not sealed");

    createArchive(staging, output);

    if (!installAfter) {
        std::printf("Successfully signed `%s` to `%s`!\n", ipaPath.c_str(), outputPath.c_str());
    } else {
        installIpa(output, fs::path(ipaPath).filename().string());
    }
    return 0;
}

int commandInstall(int argc, char** argv) {
    if (argc < 3) die("missing .ipa path");
    if (argc > 3) die("unexpected argument: " + std::string(argv[3]));
    const fs::path ipaPath(expandHome(argv[2]));
    if (!fs::is_regular_file(ipaPath)) die("cannot find '" + std::string(argv[2]) + "'");
    installIpa(ipaPath, ipaPath.filename().string());
    return 0;
}

int commandCert(int argc, char** argv) {
    (void)argc;
    (void)argv;

    const fs::path directory = certificateDirectory();

    SavedCertificate previous;
    const bool hasPrevious = loadSavedCertificate(previous);
    if (hasPrevious) {
        std::printf(
            "There is already a certificate saved named \"%s\", do you want to replace it? "
            "(y/n) > ",
            previous.name.c_str());
        std::fflush(stdout);
        const std::string answer = trimmed(readLine());
        if (answer != "y" && answer != "Y" && answer != "yes" && answer != "YES" &&
            answer != "Yes") {
            return 0;
        }
    }

    const std::string pkeyInput = trimmed(promptLine("Input .p12 file : "));
    if (pkeyInput.empty()) die("no .p12 file given");
    const std::string provInput = trimmed(promptLine("Input .mobileprovision file : "));
    if (provInput.empty()) die("no .mobileprovision file given");
    const std::string password = promptHidden("Input password : ");
    std::string name = trimmed(promptLine(
        "Name (for identification only, leave it blank if you want it random) : "));
    if (name.empty()) {
        name = randomIdentifier();
    } else {
        // The name becomes a file name inside ~/.csign, so it must not be able
        // to escape that directory.
        const bool valid = name.front() != '.' &&
                           std::all_of(name.begin(), name.end(), [](unsigned char c) {
                               return std::isalnum(c) != 0 || c == '-' || c == '_';
                           });
        if (!valid) {
            die("the name may only contain letters, digits, '-' and '_'");
        }
    }

    const fs::path pkeySource(expandHome(pkeyInput));
    const fs::path provSource(expandHome(provInput));
    if (!fs::is_regular_file(pkeySource)) die("cannot find '" + pkeyInput + "'");
    if (!fs::is_regular_file(provSource)) die("cannot find '" + provInput + "'");

    // Validate before touching anything in ~/.csign.
    SigningIdentity identity;
    identity.load(pkeySource, provSource, password);

    // The directory is only created once the input is known to be good.
    std::error_code ec;
    fs::create_directories(directory, ec);

    const fs::path pkeyTarget = directory / (name + ".p12");
    const fs::path provTarget = directory / (name + ".mobileprovision");
    const std::string pkeyData = readFile(pkeySource);
    const std::string provData = readFile(provSource);
    writeFile(pkeyTarget, pkeyData);
    try {
        writeFile(provTarget, provData);
    } catch (...) {
        // Do not leave a certificate without its profile behind.
        std::error_code cleanupError;
        fs::remove(pkeyTarget, cleanupError);
        throw;
    }

    SavedCertificate certificate;
    certificate.name = name;
    certificate.pkey = "~/.csign/" + name + ".p12";
    certificate.prov = "~/.csign/" + name + ".mobileprovision";
    certificate.password = password;
    saveCertificateFile(certificate);

    if (hasPrevious) {
        // Paths come from the stored file, so only remove what really lives in
        // the certificate directory.
        std::error_code resolveError;
        const fs::path resolvedDirectory = fs::weakly_canonical(directory, resolveError);
        for (const std::string& oldPath : {previous.pkey, previous.prov}) {
            const fs::path expanded(expandHome(oldPath));
            if (expanded == pkeyTarget || expanded == provTarget) continue;
            std::error_code entryError;
            const fs::path resolved = fs::weakly_canonical(expanded, entryError);
            if (entryError || !pathIsWithin(resolvedDirectory, resolved)) continue;
            std::error_code removeError;
            fs::remove(expanded, removeError);
        }
    }

    std::printf("\nSuccess! Saved to ~/.csign/\n");
    return 0;
}
int commandCheck(int argc, char** argv) {
    if (argc < 3) die("missing .ipa path");
    if (argc > 3) die("unexpected argument: " + std::string(argv[3]));
    const fs::path ipaPath(expandHome(argv[2]));
    if (!fs::is_regular_file(ipaPath)) die("cannot find '" + std::string(argv[2]) + "'");

    const IpaInfo info = inspectIpa(ipaPath);
    const bool signedState = info.hasCodeResources && info.signatureValid;

    std::printf("App Name : %s\n", info.displayName.c_str());
    std::printf("App Version : %s\n", info.version.c_str());
    std::printf("Bundle Id : %s\n", info.bundleId.c_str());
    std::printf("Signed : %s\n", signedState ? "True" : "False");
    return 0;
}
}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            printUsage(stderr);
            return 1;
        }
        const std::string command = argv[1];
        if (command == "sign") return commandSign(argc, argv);
        if (command == "install") return commandInstall(argc, argv);
        if (command == "cert") return commandCert(argc, argv);
        if (command == "check") return commandCheck(argc, argv);
        if (command == "-v" || command == "--version") {
            printVersion();
            return 0;
        }
        if (command == "-h" || command == "--help" || command == "help") {
            printUsage(stdout);
            return 0;
        }
        std::fprintf(stderr, "error: unknown command '%s'\n", command.c_str());
        printUsage(stderr);
        return 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "error: %s\n", error.what());
        return 1;
    }
}
