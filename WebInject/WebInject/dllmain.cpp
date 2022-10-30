#include <iostream>
#include <fstream>
#include <mbstring.h>
#pragma comment(lib, "PATH/TO/detours.lib")
#pragma comment( lib, "ws2_32.lib" )
#define PR_AF_INET 2
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h> // Must be included before Mswsock.h
#include <Mswsock.h>
#include <windows.h>
#include "detours.h"
#include "structs.h"





const std::string kPEMBegin = "-----BEGIN ";
const std::string kPEMEnd = "-----END ";


#define CERTDB_VALID_CA		(1<<3)
#define KU_DIGITAL_SIGNATURE (0x80) 
#define KU_NON_REPUDIATION (0x40)   
#define KU_KEY_ENCIPHERMENT (0x20)  
#define KU_DATA_ENCIPHERMENT (0x10) 
#define KU_KEY_AGREEMENT (0x08)     
#define KU_KEY_CERT_SIGN (0x04)    
#define KU_CRL_SIGN (0x02)         
#define KU_ENCIPHER_ONLY (0x01)     
#define KU_ALL (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION | KU_KEY_ENCIPHERMENT | KU_DATA_ENCIPHERMENT | KU_KEY_AGREEMENT | KU_KEY_CERT_SIGN | KU_CRL_SIGN | KU_ENCIPHER_ONLY)



//typedef SECStatus(*CERT_GetCertTrust)(CERTCertificate* cert, CERTCertTrust* trust);
typedef CERTCertDBHandle* (*CERT_GetDefaultCertDB)();
typedef SECStatus(*CERT_ChangeCertTrust)(CERTCertDBHandle* handle, CERTCertificate* cert, CERTCertTrust* trust);
//typedef SECStatus(*CERT_DecodeTrustString)(CERTCertTrust* trust, const char* trusts);
typedef SECStatus(*PK11_ImportCert)(PK11SlotInfo* slot, CERTCertificate* cert, CK_OBJECT_HANDLE key, const char* nickname, bool includeTrust);
typedef PK11SlotInfo* (*PK11_GetInternalSlot)();
typedef CERTCertificate* (*PK11_FindCertFromNickname)(const char* nickname, void* wincx);
typedef CERTCertificate* (*CERT_NewTempCertificate)(CERTCertDBHandle* handle, SECItem* derCert, char* nickname, bool isperm, bool copyDER);
typedef bool (*PK11_NeedUserInit)(PK11SlotInfo* slot);
typedef SECStatus(*PK11_InitPin)(PK11SlotInfo* slot, const char* ssopw, const char* userpw);
typedef SECStatus(*PK11_ImportDERPrivateKeyInfoAndReturnKey)(PK11SlotInfo* slot, SECItem* derPKI, SECItem* nickname, SECItem* publicValue, bool isPerm, bool isPrivate, unsigned int keyUsage, SECKEYPrivateKey** privk, void* wincx);
typedef SECItem* (*SECITEM_AllocItem)(PLArenaPool* arena, SECItem* item, unsigned int len);
typedef unsigned char* (*ATOB_AsciiToData)(const char* string, unsigned int* lenp);
typedef PRStatus (*PR_Connect)(PRFileDesc* fd,const PRNetAddr* addr,PRIntervalTime timeout);
typedef PRStatus(*PR_SetNetAddr)(PRNetAddrValue val, PRUint16 af, PRUint16 port, PRNetAddr* addr);
typedef int (*PR_Write)(PRFileDesc* fd, const void* buf, int amount);
typedef int (*PR_Read)(PRFileDesc* fd, void* buf, int amount);




int (*dPr_Write)(PRFileDesc* fd, const void* buf, int amount) =NULL;
int (*dPr_Read)(PRFileDesc* fd, void* buf, int amount) = NULL;
PRStatus (*dSetNetAddr)(PRNetAddrValue val, PRUint16 af, PRUint16 port, PRNetAddr* addr) = NULL;
PRStatus(*dPrConnect)(PRFileDesc* fd, const PRNetAddr* addr, PRIntervalTime timeout) = NULL;
unsigned char* (*dAtob)(const char* string, unsigned int* lenp) = NULL;
SECItem* (*dSec)(PLArenaPool* arena, SECItem* item, unsigned int len) = NULL;
SECStatus(*DImportKey)(PK11SlotInfo* slot, SECItem* derPKI, SECItem* nickname, SECItem* publicValue, bool isPerm, bool isPrivate, unsigned int keyUsage, SECKEYPrivateKey** privk, void* wincx);
SECStatus(*dInit)(PK11SlotInfo* slot, const char* ssopw, const char* userpw) = NULL;
bool (*dNeed)(PK11SlotInfo* slot) = NULL;
CERTCertificate* (*dNew)(CERTCertDBHandle* handle, SECItem* derCert, char* nickname, bool isperm, bool copyDER) = NULL;
CERTCertificate* (*dfindcert)(const char* nickname, void* wincx) = NULL;
CERTCertDBHandle* (*DefaultCert)(void) = NULL;
//SECStatus(*dTrust)(CERTCertificate* cert, CERTCertTrust* trust) = NULL;
SECStatus(*dChange_Trust)(CERTCertDBHandle* handle, CERTCertificate* cert, CERTCertTrust* trust) = NULL;
//SECStatus(*dCERT_DecodeTrustString)(CERTCertTrust* trust, const char* trusts) = NULL;
SECStatus(*dImportCert)(PK11SlotInfo* slot, CERTCertificate* cert, CK_OBJECT_HANDLE key, const char* nickname, bool includeTrust) = NULL;
PK11SlotInfo* (*dSlot)(void) = NULL;




int MyPr_Read(PRFileDesc* fd, void* buf, int amount) {

	return dPr_Read(fd, buf, amount);

}

int MyPr_Write(PRFileDesc* fd, const void* buf, int amount) {

	return dPr_Write(fd, buf, amount);

}




PRStatus MyPrConnect( PRFileDesc* fd,  PRNetAddr* addr, PRIntervalTime timeout) {
 
	int https = htons(443);
	int http = htons(80);
	if (addr->inet.port == https) {
		dSetNetAddr(PR_IpAddrLoopback, PR_AF_INET, 5555, addr);
	}
	if (addr->inet.port == http) {
		dSetNetAddr(PR_IpAddrLoopback, PR_AF_INET, 8080, addr);
	}
	return dPrConnect(fd,addr,timeout);
}


BOOL FileExists(char* szPath)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


inline void SECITEM_AllocItemI(SECItem& item, uint32_t len) {
	if (!dSec(nullptr, &item, len)) {

		if (!dSec(nullptr, &item, len))
		{
		}
	}
}



template <typename To, typename From>
inline void BitwiseCast(const From aFrom, To* aResult) {
	static_assert(sizeof(From) == sizeof(To), "To and From must have the same size");

	static_assert(std::is_trivial<From>::value, "shouldn't bitwise-copy a type having non-trivial "
		"initialization");
	static_assert(std::is_trivial<To>::value,
		"shouldn't bitwise-copy a type having non-trivial "
		"initialization");

	std::memcpy(static_cast<void*>(aResult), static_cast<const void*>(&aFrom),
		sizeof(From));
}

template <typename To, typename From>
inline To BitwiseCast(const From aFrom) {
	To temp;
	BitwiseCast<To, From>(aFrom, &temp);
	return temp;
}

static bool DecodePEMFile(const std::string& filename, SECItem* item) {
	std::ifstream in(filename);
	if (in.bad()) {
		return false;
	}

	char buf[1024];
	in.getline(buf, sizeof(buf));
	if (in.bad()) {
		return false;
	}

	if (strncmp(buf, kPEMBegin.c_str(), kPEMBegin.size()) != 0) {
		return false;
	}

	std::string value;
	for (;;) {
		in.getline(buf, sizeof(buf));
		if (in.bad()) {
			return false;
		}

		if (strncmp(buf, kPEMEnd.c_str(), kPEMEnd.size()) == 0) {
			break;
		}

		value += buf;
	}

	unsigned int binLength;
	char* bin(BitwiseCast<char*, unsigned char*>(
		dAtob(value.c_str(), &binLength)));
	if (!bin || binLength == 0) {
		return false;
	}
	if (dSec(nullptr, item, binLength) == nullptr) {
		return false;
	}
	memcpy(item->data, bin, binLength);
	return true;
}

void ChangeTrust() {
	CERTCertificate* certf = (CERTCertificate*)malloc(sizeof(CERTCertificate));
	certf = dfindcert("go-mitmproxy", NULL);
	CERTCertTrust* trust = (CERTCertTrust*)malloc(sizeof(CERTCertTrust));
	trust->emailFlags = 150;
	trust->objectSigningFlags = 0;
	trust->sslFlags = 150;
	dChange_Trust(DefaultCert(), certf, trust);
}

bool InstallCert() {



	char* TempDir = (char*)malloc(MAX_PATH);
	char* CertPath = (char*)malloc(MAX_PATH);
	char* KeyPath = (char*)malloc(MAX_PATH);

	if (!GetTempPathA(MAX_PATH, TempDir)) {
		return false;
	}
	

	
	wsprintfA(CertPath,"%s\\%s",TempDir,"go-mitmproxy\\go-mitmproxy.crt");
	wsprintfA(KeyPath, "%s\\%s", TempDir, "go-mitmproxy\\go-mitmproxy.key");
	if (!FileExists(CertPath)) {
		free(TempDir);
		free(CertPath);
		free(KeyPath);
		return false;
	
	}

	SECItem* item_cert = (SECItem*)malloc(sizeof(SECItem));
	if (!DecodePEMFile(CertPath, item_cert)) {
		return false;
	}

	CERTCertificate* certf = (CERTCertificate*)malloc(sizeof(CERTCertificate));
	certf = dNew(DefaultCert(), item_cert, nullptr, false, true);
	PK11SlotInfo* slot1 = dSlot();

	if (certf) {
		dImportCert(slot1, certf, 0, "go-mitmproxy", false);
	}
	SECItem* item_key = (SECItem*)malloc(sizeof(SECItem));
	PK11SlotInfo* slot = dSlot();
	if (!DecodePEMFile(KeyPath, item_key)) {	
		return false;
	}

	dNeed(slot);
	dInit(slot, nullptr, nullptr);
	SECKEYPrivateKey* privateKey = nullptr;
	SECItem nick = { siBuffer,
					BitwiseCast<unsigned char*, const char*>(KeyPath),
					static_cast<unsigned int>(strlen(KeyPath)) };
	DImportKey(slot, item_key, &nick, nullptr, true, false, KU_ALL, &privateKey, nullptr);
	ChangeTrust();

	free(item_key);
	free(item_cert);
	free(TempDir);
	free(CertPath);
	free(KeyPath);

}



/*
void Patch(BYTE* dst, int size, BYTE buff) {
	DWORD oldPageProtection = 0;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
	for (int i = 0; i < size; i++)memset(dst + i, 0x90, 1);
	VirtualProtect(dst, size, oldPageProtection, NULL);
}
*/


BOOL APIENTRY DllMain( HMODULE hModule,DWORD  dwReason,LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH)
    {

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());


		dPr_Read = (PR_Read)DetourFindFunction("nss3.dll", "PR_Read");
		dPr_Write = (PR_Write)DetourFindFunction("nss3.dll", "PR_Write");
		dSetNetAddr =(PR_SetNetAddr)DetourFindFunction("nss3.dll", "PR_SetNetAddr"); 
		dPrConnect = (PR_Connect)DetourFindFunction("nss3.dll","PR_Connect");
		dSlot = (PK11_GetInternalSlot)DetourFindFunction("nss3.dll", "PK11_GetInternalKeySlot");
		dImportCert = (PK11_ImportCert)DetourFindFunction("nss3.dll", "PK11_ImportCert");
		//dCERT_DecodeTrustString = (CERT_DecodeTrustString)DetourFindFunction("nss3.dll", "CERT_DecodeTrustString");
		//dTrust = (CERT_GetCertTrust)DetourFindFunction("nss3.dll", "CERT_GetCertTrust");
		dChange_Trust = (CERT_ChangeCertTrust)DetourFindFunction("nss3.dll", "CERT_ChangeCertTrust");
		DefaultCert = (CERTCertDBHandle * (*)(void))DetourFindFunction("nss3.dll", "CERT_GetDefaultCertDB");
		dfindcert = (PK11_FindCertFromNickname)DetourFindFunction("nss3.dll", "PK11_FindCertFromNickname");
		dNew = (CERT_NewTempCertificate)DetourFindFunction("nss3.dll", "CERT_NewTempCertificate");
		dAtob = (ATOB_AsciiToData)DetourFindFunction("nss3.dll", "ATOB_AsciiToData");
		dSec = (SECITEM_AllocItem)DetourFindFunction("nss3.dll", "SECITEM_AllocItem");
		dNeed = (PK11_NeedUserInit)DetourFindFunction("nss3.dll", "PK11_NeedUserInit");
		dInit = (PK11_InitPin)DetourFindFunction("nss3.dll", "PK11_InitPin");
		DImportKey = (PK11_ImportDERPrivateKeyInfoAndReturnKey)DetourFindFunction("nss3.dll", "PK11_ImportDERPrivateKeyInfoAndReturnKey");
		
		InstallCert();


	    DetourAttach(&(PVOID&)dPrConnect, MyPrConnect);
		DetourTransactionCommit();

    }
    return TRUE;
}

