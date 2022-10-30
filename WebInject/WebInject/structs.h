#include "enums.h";

typedef unsigned long int CK_ULONG;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef unsigned __int64 PRUint64;
typedef PRUint64 PRUword;
typedef unsigned int PRUint32;
typedef unsigned short PRUint16;
typedef unsigned char PRUint8;


typedef struct SECItemStr SECItem;
typedef struct CERTCertTrustStr CERTCertTrust;
typedef struct CERTCertificateStr CERTCertificate;
typedef struct NSSTrustDomainStr  CERTCertDBHandle;
typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef struct PLArena  PLArena;
typedef struct CERTSignedDataStr    CERTSignedData;
typedef struct SECAlgorithmIDStr SECAlgorithmID;
typedef struct CERTNameStr CERTName;
typedef struct CERTRDNStr CERTRDN;
typedef struct CERTAVAStr CERTAVA;
typedef struct CERTValidityStr CERTValidity;
typedef struct CERTSubjectPublicKeyInfoStr CERTSubjectPublicKeyInfo;
typedef struct CERTCertExtensionStr CERTCertExtension;
typedef struct CERTOKDomainNameStr CERTOKDomainName;
typedef struct CERTSubjectListStr CERTSubjectList;
typedef struct CERTSubjectNodeStr CERTSubjectNode;
typedef struct CERTAuthKeyIDStr CERTAuthKeyID;
typedef struct CERTGeneralNameStr CERTGeneralName;
typedef struct PRCListStr PRCList;
typedef struct SECKEYPrivateKeyStr SECKEYPrivateKey;
typedef struct PRFileDesc       PRFileDesc;
typedef PRUint32 PRIntervalTime;
typedef union  PRNetAddr  PRNetAddr;
typedef struct PRIPv6Addr PRIPv6Addr;


struct SECItemStr {
    SECItemType type;
    unsigned char* data;
    unsigned int len;
};


struct SECAlgorithmIDStr {
    SECItem algorithm;
    SECItem parameters;
};


struct CERTCertTrustStr {
    unsigned int sslFlags;
    unsigned int emailFlags;
    unsigned int objectSigningFlags;
};



struct PLArena {
    PLArena* next;          /* next arena for this lifetime */
    PRUword     base;           /* aligned base address, follows this header */
    PRUword     limit;          /* one beyond last byte in arena */
    PRUword     avail;          /* points to next available byte */
};


struct PLArenaPool {
    PLArena     first;          /* first arena in pool list */
    PLArena* current;       /* arena from which to allocate space */
    PRUint32    arenasize;      /* net exact size of a new arena */
    PRUword     mask;           /* alignment mask (power-of-2 - 1) */
#ifdef PL_ARENAMETER
    PLArenaStats stats;
#endif
};





struct CERTSignedDataStr {
    SECItem data;
    SECAlgorithmID signatureAlgorithm;
    SECItem signature;
};

struct CERTAVAStr {
    SECItem type;
    SECItem value;
};


struct CERTRDNStr {
    CERTAVA** avas;
};

struct CERTNameStr {
    PLArenaPool* arena;
    CERTRDN** rdns;
};



struct CERTValidityStr {
    PLArenaPool* arena;
    SECItem notBefore;
    SECItem notAfter;
};


struct CERTSubjectPublicKeyInfoStr {
    PLArenaPool* arena;
    SECAlgorithmID algorithm;
    SECItem subjectPublicKey;
};



struct CERTCertExtensionStr {
    SECItem id;
    SECItem critical;
    SECItem value;
};




struct CERTOKDomainNameStr {
    CERTOKDomainName* next;
    char* name;
};


struct CERTSubjectNodeStr {
    struct CERTSubjectNodeStr* next;
    struct CERTSubjectNodeStr* prev;
    SECItem certKey;
    SECItem keyID;
};

struct CERTSubjectListStr {
    PLArenaPool* arena;
    int ncerts;
    char* emailAddr;
    CERTSubjectNode* head;
    CERTSubjectNode* tail; 
    void* entry;
};


struct CERTAuthKeyIDStr {
    SECItem keyID;
    CERTGeneralName* authCertIssuer;
    SECItem authCertSerialNumber;
    SECItem** DERAuthCertIssuer;
};

typedef struct OtherNameStr {
    SECItem name;
    SECItem oid;
} OtherName;



struct PRCListStr {
    PRCList* next;
    PRCList* prev;
};

struct CERTGeneralNameStr {
    CERTGeneralNameType type;
    union {
        CERTName directoryName;
        OtherName OthName;
        SECItem other;
    } name;
    SECItem derDirectoryName; 
    PRCList l;
};



struct CERTCertificateStr {

    PLArenaPool* arena;
    char* subjectName;
    char* issuerName;
    CERTSignedData signatureWrap;	/* XXX */
    SECItem derCert;			/* original DER for the cert */
    SECItem derIssuer;			/* DER for issuer name */
    SECItem derSubject;			/* DER for subject name */
    SECItem derPublicKey;		/* DER for the public key */
    SECItem certKey;			/* database key for this cert */
    SECItem version;
    SECItem serialNumber;
    SECAlgorithmID signature;
    CERTName issuer;
    CERTValidity validity;
    CERTName subject;
    CERTSubjectPublicKeyInfo subjectPublicKeyInfo;
    SECItem issuerID;
    SECItem subjectID;
    CERTCertExtension** extensions;
    char* emailAddr;
    CERTCertDBHandle* dbhandle;
    SECItem subjectKeyID;	/* x509v3 subject key identifier */
    bool keyIDGenerated;	/* was the keyid generated? */
    unsigned int keyUsage;	/* what uses are allowed for this cert */
    unsigned int rawKeyUsage;	/* value of the key usage extension */
    bool keyUsagePresent;	/* was the key usage extension present */
    PRUint32 nsCertType;
    bool keepSession;			/* keep this cert for entire session*/
    bool timeOK;			/* is the bad validity time ok? */
    CERTOKDomainName* domainOK;
    bool isperm;
    bool istemp;
    char* nickname;
    char* dbnickname;
    struct NSSCertificateStr* nssCertificate;	/* This is Stan stuff. */
    CERTCertTrust* trust;
    int referenceCount;
    CERTSubjectList* subjectList;
    CERTAuthKeyID* authKeyID;  /* x509v3 authority key identifier */
    bool isRoot;

    union {
        void* apointer;
        struct {
            unsigned int hasUnsupportedCriticalExt : 1;

        } bits;
    } options;
    int series;
    PK11SlotInfo* slot;		
    CK_OBJECT_HANDLE pkcs11ID;	
    bool ownSlot;		
};



struct SECKEYPrivateKeyStr {
    PLArenaPool* arena;
    KeyType keyType;
    PK11SlotInfo* pkcs11Slot;  
    CK_OBJECT_HANDLE pkcs11ID; 
    bool pkcs11IsTemp;       
    void* wincx;               
    PRUint32 staticflags;      
};

struct PRIPv6Addr {
    union {
        PRUint8  _S6_u8[16];
        PRUint16 _S6_u16[8];
        PRUint32 _S6_u32[4];
        PRUint64 _S6_u64[2];
    } _S6_un;
};






union PRNetAddr {
    struct {
        PRUint16 family;                /* address family (0x00ff maskable) */
        char data[14];                  /* raw address data */
    } raw;
    struct  {
        PRUint16 family;                /* address family (AF_INET) */
        PRUint16 port;                  /* port number */
        PRUint32 ip;                    /* The actual 32 bits of address */
        char pad[8];
    } inet;
    struct {
        PRUint16 family;                /* address family (AF_INET6) */
        PRUint16 port;                  /* port number */
        PRUint32 flowinfo;              /* routing information */
        PRIPv6Addr ip;                  /* the actual 128 bits of address */
        PRUint32 scope_id;              /* set of interfaces for a scope */
    } ipv6;
#if defined(XP_UNIX) || defined(XP_OS2) || defined(XP_WIN)
    struct {                            /* Unix domain socket address */
        PRUint16 family;                /* address family (AF_UNIX) */
#ifdef XP_OS2
        char path[108];                 /* null-terminated pathname */
        /* bind fails if size is not 108. */
#else
        char path[104];                 /* null-terminated pathname */
#endif
    } local;
#endif
};
