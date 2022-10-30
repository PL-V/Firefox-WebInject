typedef enum {
    siBuffer = 0,
    siClearDataBuffer = 1,
    siCipherDataBuffer = 2,
    siDERCertBuffer = 3,
    siEncodedCertBuffer = 4,
    siDERNameBuffer = 5,
    siEncodedNameBuffer = 6,
    siAsciiNameString = 7,
    siAsciiString = 8,
    siDEROID = 9,
    siUnsignedInteger = 10,
    siUTCTime = 11,
    siGeneralizedTime = 12,
    siVisibleString = 13,
    siUTF8String = 14,
    siBMPString = 15
} SECItemType;
typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;
typedef enum PRDirFlags {
    PR_SKIP_NONE = 0x0,
    PR_SKIP_DOT = 0x1,
    PR_SKIP_DOT_DOT = 0x2,
    PR_SKIP_BOTH = 0x3,
    PR_SKIP_HIDDEN = 0x4
} PRDirFlags;
typedef enum _SECStatus {
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
} SECStatus;
typedef enum CERTGeneralNameTypeEnum {
    certOtherName = 1,
    certRFC822Name = 2,
    certDNSName = 3,
    certX400Address = 4,
    certDirectoryName = 5,
    certEDIPartyName = 6,
    certURI = 7,
    certIPAddress = 8,
    certRegisterID = 9
} CERTGeneralNameType;
typedef enum {
    nullKey = 0,
    rsaKey = 1,
    dsaKey = 2,
    fortezzaKey = 3, /* deprecated */
    dhKey = 4,
    keaKey = 5, /* deprecated */
    ecKey = 6,
    rsaPssKey = 7,
    rsaOaepKey = 8
} KeyType;

typedef enum PRNetAddrValue
{
    PR_IpAddrNull,      /* do NOT overwrite the IP address */
    PR_IpAddrAny,       /* assign logical INADDR_ANY to IP address */
    PR_IpAddrLoopback,  /* assign logical INADDR_LOOPBACK  */
    PR_IpAddrV4Mapped   /* IPv4 mapped address */
} PRNetAddrValue;