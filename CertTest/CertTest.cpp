// CertTest.cpp : Defines the entry point for the console application.
// A more complete example for accessing the Cert store and working
// with certificate properties can be found here:
// Getting and Setting Certificate Properties
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa382361(v=vs.85).aspx
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <Wincrypt.h>
#include <winerror.h>
#include <iostream>
#include <tchar.h>

#pragma comment(lib, "crypt32.lib")

///<summary>
/// Defines the usage types relevant for determining if a certificate can be used for client
/// authentication
///</summary>
enum EnhancedKeyUsageType
{
	///<summary>
	/// Not a known enhanced key usage
	///</summary>
	EnhancedKeyUsageUnknown,

	///<summary>
	/// The enhanced key usage indicates that the certificate can be used for client authentication
	///</summary>
	EnhancedKeyUsageClientAuth,

	///<summary>
	/// The enhanced key usage indicates that the certificate is the Genuine Windows Phone one
	///</summary>
	EnhancedKeyUsageGWP
};

/// <summary>
/// MyHandleError
/// The MyHandleError function is an example of a tool function used to print an error message
/// and exit the calling program.The examples for several CryptoAPI functions in Cryptography Reference 
/// and the more extended examples in Using Cryptography implement this function.
/// Real applications may require more complex error handling capability.
/// See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa386990(v=vs.85).aspx
/// </summary>
void MyHandleError(LPTSTR psz)
{
	_ftprintf(stderr, TEXT("An error occurred in the program. \n"));
	_ftprintf(stderr, TEXT("%s\n"), psz);
	_ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
	_ftprintf(stderr, TEXT("Program terminating. \n"));
	exit(1);
} 


///<summary>
/// Gets the enhanced key usage type corresponding to the given usage identifier
///</summary>
///<param name="pUsageIdentifier">
/// The usage identifier
///</param>
///<returns>
/// The enhanced key usage type corresponding to the given usage identifier
///</returns>
static EnhancedKeyUsageType GetEnhancedKeyUsageType(
	_In_ LPCSTR pUsageIdentifier)
{
	static const struct EnhancedKeyUsageMap
	{
		LPCSTR pUsageIdentifier;
		EnhancedKeyUsageType usageType;
	} keyUsageMap[] =
	{
		// The Client Auth key usage OID
		// for this little sample is all we care about...
		{
			szOID_PKIX_KP_CLIENT_AUTH,
			EnhancedKeyUsageClientAuth
		},

	};

	for (int i = 0; i < _countof(keyUsageMap); ++i)
	{
		if (0 == strcmp(keyUsageMap[i].pUsageIdentifier, pUsageIdentifier))
		{
			return keyUsageMap[i].usageType;
		}
	}

	return EnhancedKeyUsageUnknown;
}



static HRESULT GetEnhancedKeyUsage(_In_ PCCERT_CONTEXT pCertContext, _Outptr_result_maybenull_ PCERT_ENHKEY_USAGE *ppKeyUsage)
{
	
	// First print out Cert Details:
	
	// print out the cert name:

	LPTSTR pszString;
	LPTSTR pszName;
	DWORD cbSize;
	CERT_BLOB blobEncodedName;

	//-----------------------------------------------------------
	//        Get and display 
	//        the name of subject of the certificate.
    
	//printf("Getting Cert details \n");

	if (!(cbSize = CertGetNameString(
		pCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		NULL,
		0)))
	{
		MyHandleError(TEXT("CertGetName failed before memory allocated."));
	}

	if (!(pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR))))
	{
		MyHandleError(TEXT("Memory allocation for certname failed."));
	}

	if (CertGetNameString(
		pCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		pszName,
		cbSize))

	{
		_tprintf(TEXT("\nSubject -> %s.\n"), pszName);

		//-------------------------------------------------------
		//       Free the memory allocated for the string.
		free(pszName);
	}
	else
	{
		MyHandleError(TEXT("CertGetName failed."));
	}

	// then check the usage types, will allow us to check if there is a case where cert returns with
	// buffer, even if no policy defined
	
	DWORD bufferSize = 0;
	CertGetEnhancedKeyUsage(pCertContext, 0, nullptr, &bufferSize);
	


	PCERT_ENHKEY_USAGE keyUsage;
	if (0 != bufferSize)
	{
		keyUsage = reinterpret_cast<PCERT_ENHKEY_USAGE>(LocalAlloc(LPTR, bufferSize));
		// IF_NULLRETURN(keyUsage);

		bool IF_FALSERETURN = CertGetEnhancedKeyUsage(pCertContext, 0, keyUsage, &bufferSize);

		if (!IF_FALSERETURN)
		{
			printf("We should have returned\n");
		}
		
		/*
		If the cUsageIdentifier member is zero, the certificate might be valid for all uses or the certificate might have no valid uses.
		The return from a call to GetLastError can be used to determine whether the certificate is good for all uses or for none.
		If GetLastError returns CRYPT_E_NOT_FOUND, the certificate is good for all uses. If it returns zero, the certificate has no valid uses.
		*/

		bool canBeUsedForClientAuthentication = false;
		if (keyUsage->cUsageIdentifier == 0)
		{
			printf("No Enhanced Key Usage specified.\n");
			wprintf(L"Last error is 0x%x\n", GetLastError());
		}

		if (nullptr != keyUsage)
		{
			// from: https://msdn.microsoft.com/en-us/library/windows/desktop/aa382040(v=vs.85).aspx
			// The certificate has valid uses. Inspect all usages to see if it can be used for client auth and
			// is not a GWP certificate
			for (DWORD i = 0; i < keyUsage->cUsageIdentifier; ++i)
			{
				EnhancedKeyUsageType usageType = GetEnhancedKeyUsageType(keyUsage->rgpszUsageIdentifier[i]);

				printf("Usage Type : ");
				printf(keyUsage->rgpszUsageIdentifier[i]);
				// printf("\n");

				if (EnhancedKeyUsageGWP == usageType)
				{
					// GWP certificates cannot be used for client auth and there's no point in inspecting
					// the remaining usages
					canBeUsedForClientAuthentication = FALSE;
					printf("\nGWP Certificates cannot be used for client Auth, skipping further checks\n");
					break;
				}

				if (EnhancedKeyUsageClientAuth == usageType)
				{
					// Remember that it can be used for client auth but continue inspecting the other
					// usages to make sure it's not a GWP certificate
					canBeUsedForClientAuthentication = TRUE;

					printf(" <- Can be used for client Auth\n");
					continue;
				}
				else
				{
					printf(" <- Cannot be used\n");
					continue;
				}


			}

			printf("##################################################################\n\n");

		}
	}

	return S_OK;
}


int main()
{
	//--------------------------------------------------------------------
	// Declare and initialize variables.
	HANDLE          hStoreHandle = NULL;
	PCCERT_CONTEXT  pCertContext = NULL;
	char * pszStoreName = "MY";
	//--------------------------------------------------------------------
	// Open a system certificate store.
	if (hStoreHandle = CertOpenStore(
		CERT_STORE_PROV_SYSTEM_W,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		L"MY"))
	{
		printf("The %s store has been opened. \n", pszStoreName);
	}
	else
	{
		printf("The store was not opened.\n");
		exit(1);
	}

	//-------------------------------------------------------------------
	// Find the certificates in the system store. 
	while (pCertContext = CertEnumCertificatesInStore(
		hStoreHandle,
		pCertContext)) // on the first call to the function,
					   // this parameter is NULL 
					   // on all subsequent calls, 
					   // this parameter is the last pointer 
					   // returned by the function
	{
		//----------------------------------------------------------------
		// Do whatever is needed for a current certificate.
		// ...

		byte ClientCertHash[20] = {};
		DWORD cbClientCertHash = sizeof ClientCertHash;
		if (CertGetCertificateContextProperty(pCertContext,
			CERT_HASH_PROP_ID,
			ClientCertHash,
			&cbClientCertHash))
		{
			// if you want, do something here...
		}


		if (pCertContext != nullptr)
		{

			byte ClientCertHash[20] = {};
			DWORD cbClientCertHash = sizeof ClientCertHash;
			if (CertGetCertificateContextProperty(pCertContext,
				CERT_HASH_PROP_ID,
				ClientCertHash,
				&cbClientCertHash))
			{
				// if you want, do something here...
			}

			// also try to get the key usage...
			PCERT_ENHKEY_USAGE * pPointer = nullptr;
			GetEnhancedKeyUsage(pCertContext, pPointer);

		}
		else
		{
			wprintf(L"Last error is 0x%x\n", GetLastError());
			// https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396

		}


	} // End of while.

	/*
	The CertFindCertificateInStore function finds the first or next certificate context in a certificate store
	that matches a search criteria established by the dwFindType and its associated pvFindPara.
	This function can be used in a loop to find all of the certificates in a certificate store that match the specified find criteria.
	https://msdn.microsoft.com/en-us/library/windows/desktop/aa376064%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
	*/
	//pCertContext = CertFindCertificateInStore(
	//	hStoreHandle,
	//	X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	//	0,
	//	CERT_FIND_ANY,
	//	&pCertHashBlob,
	//	NULL);

	/*
	Interestingly CERT_FIND_SHA1_HASH looks for a cert that matches the hash blob, but if we don't have one, this will not return anything
	If we want to use that, we first need to have a specific cert & hash blob we are looking for...

	CERT_FIND_SHA1_HASH
	Data type of pvFindPara: CRYPT_HASH_BLOB structure.

	Searches for a certificate with a SHA1 hash that matches the hash in the CRYPT_HASH_BLOB structure.
	*/

	//  CERT_FIND_ANY returns any cert... which is easier to use, but requires that we iterate for certs.
	//--------------------------------------------------------------------
	//   Clean up.
	if (!CertCloseStore(
		hStoreHandle,
		0))
	{
		MyHandleError(TEXT("Failed CertCloseStore\n")); 
		exit(1);
	}

	return 0;
}

