//
// HomeOwnUtil - recursive take ownership and change ACL on a homedir
// Version 1.0 by tenox@ntinternals.net
// Most code bellow is taken from MSDN examples 
//

#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
  
#define ADMINGRP "Domain Admins"

#ifndef PROTECTED_DACL_SECURITY_INFORMATION
#define PROTECTED_DACL_SECURITY_INFORMATION 0x80000000
#endif 
#ifndef UNPROTECTED_DACL_SECURITY_INFORMATION
#define UNPROTECTED_DACL_SECURITY_INFORMATION 0x20000000
#endif

// This is for recursive procedure: we're changing ACL and Owner SID
int changes;
int verbose;
PACL pACL;
PACL empACL;
PSID pSIDAdmin;
PSID pSIDUser;


DWORD (__stdcall *ConvertSidToStringSidA)(PSID ,LPSTR *StringSid );

char *basename(const char *name) {
	const char *base=name;

	while (*name) 
		if (*name++ == '\\') 
			base=name;
		
	return (char *)base;
}

HRESULT GetSid(LPCSTR szAccName, PSID *ppSid){
  // Validate the input parameters.
  if (szAccName == NULL || ppSid == NULL) 
    return FALSE;

  // Create buffers that may be large enough.
  // If a buffer is too small, the count parameter will be set to the size needed.
  const DWORD INITIAL_SIZE = 32;
  DWORD cbSid = 0;
  DWORD dwSidBufferSize = INITIAL_SIZE;
  DWORD cchDomainName = 0;
  DWORD dwDomainBufferSize = INITIAL_SIZE;
  CHAR * szDomainName = NULL;
  SID_NAME_USE eSidType;
  DWORD dwErrorCode = 0;
  HRESULT hr = TRUE;
  LPTSTR *fndsid;

  // Create buffers for the SID and the domain name.
  *ppSid = (PSID) malloc(dwSidBufferSize);
  if (*ppSid == NULL)  
    return FALSE;
    
  memset(*ppSid, 0, dwSidBufferSize);
  szDomainName = malloc(dwDomainBufferSize*sizeof(CHAR));
  if (szDomainName == NULL)  
    return FALSE;
    
  memset(szDomainName, 0, dwDomainBufferSize*sizeof(CHAR));

  // Obtain the SID for the account name passed.
  for (;;){
    // Set the count variables to the buffer sizes and retrieve the SID.
    cbSid = dwSidBufferSize;
    cchDomainName = dwDomainBufferSize;
    if (LookupAccountName(NULL, szAccName, *ppSid, &cbSid, szDomainName, &cchDomainName, &eSidType)) {
      if (IsValidSid(*ppSid) == FALSE){
         printf("The SID for %s is invalid.\n", szAccName);
         dwErrorCode = FALSE;
      }
      break;
    }
    dwErrorCode = GetLastError();

    // Check if one of the buffers was too small.
    if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER){
      if (cbSid > dwSidBufferSize){

        // Reallocate memory for the SID buffer.
        printf("The SID buffer was too small. It will be reallocated.\n");
        FreeSid(*ppSid);
        *ppSid = (PSID) malloc(cbSid);
        if (*ppSid == NULL){
          return FALSE;
        }
        memset(*ppSid, 0, cbSid);
        dwSidBufferSize = cbSid;
      }
      if (cchDomainName > dwDomainBufferSize){

        // Reallocate memory for the domain name buffer.
        printf("The domain name buffer was too small. It will be reallocated.\n");
        free(szDomainName);
        szDomainName = malloc(cchDomainName*sizeof(WCHAR));
        if (szDomainName == NULL){
          return FALSE;
        }
        memset(szDomainName, 0, cchDomainName*sizeof(WCHAR));
        dwDomainBufferSize = cchDomainName;
      }
    }
    else {
      printf("LookupAccountNameW failed. GetLastError returned: %d\n", dwErrorCode);
      hr = HRESULT_FROM_WIN32(dwErrorCode);
      break;
    }
  }

  ConvertSidToStringSidA(*ppSid, &fndsid);
  if(verbose) printf("DOMAIN:%s NAME:%s TYPE:%d\nSID:%s\n", szDomainName, szAccName, eSidType, (char*)fndsid);
  free(szDomainName);
  return hr; 
}


// Enable or disable privileges
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)){
      printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
      return FALSE; 
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
      tp.Privileges[0].Attributes = 0;
  
  if ( !AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) { 
        printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return FALSE; 
  } 
  
  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
  } 

  return TRUE;
}

// Recursively takeown & acl apply
int RecursiveChange(char *dir) {
  WIN32_FIND_DATA fnd;
  char obj[MAX_PATH];
  HANDLE hFind = INVALID_HANDLE_VALUE;
    
  if(verbose) printf("--> %s - scanning\n", dir);
  snprintf(obj, MAX_PATH, "%s\\*", dir);
  hFind=FindFirstFile(obj, &fnd);
  if(hFind==INVALID_HANDLE_VALUE) {
    printf("ERROR: unable to open specified directory %s\n", dir);
    return 0;
  }

  do {
    if(fnd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      if(strcmp(fnd.cFileName, ".")!=0 && strcmp(fnd.cFileName, "..")!=0) {
        snprintf(obj, MAX_PATH, "%s\\%s", dir, fnd.cFileName);
        if(verbose) printf("    DIR: %s\n", obj);
        if(SetNamedSecurityInfo(obj, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,  pSIDAdmin, NULL, NULL, NULL)!=ERROR_SUCCESS)
          printf("Unable to Take Ownership of %s\n", dir);
        if(SetNamedSecurityInfo(obj, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, empACL, NULL)!=ERROR_SUCCESS)
          printf("Unable to set ACL of %s\n", dir);
        if(SetNamedSecurityInfo(obj, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,  pSIDUser, NULL, NULL, NULL)!=ERROR_SUCCESS)
          printf("Unable to Give Away Ownership of %s\n", dir);
        changes++;
        RecursiveChange(obj);
      }
    }
    else {
      snprintf(obj, MAX_PATH, "%s\\%s", dir, fnd.cFileName);
      SetNamedSecurityInfo(obj, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,  pSIDAdmin, NULL, NULL, NULL);
      SetNamedSecurityInfo(obj, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, empACL, NULL);
      SetNamedSecurityInfo(obj, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,  pSIDUser, NULL, NULL, NULL);
      changes++;
      if(verbose) printf("    FILE: %s\n", obj);
    }
  } while(FindNextFile(hFind, &fnd)!=0);
  
  FindClose(hFind);

  return 0;
}



int main(int argc, char **argv) {
  WIN32_FIND_DATA fnd;
  HANDLE hFind = INVALID_HANDLE_VALUE;
  char newname[MAX_PATH];
  char *homedir, *username;
  HANDLE hToken = NULL; 
  SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
  SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
  const int NUM_ACES  = 2;
  EXPLICIT_ACCESS ea[NUM_ACES];
  EXPLICIT_ACCESS eea[1];
  int n=0;

  if(argc<2 || argc>3) {
    usage:
    printf("Set ownership and standard ACL to a user home directory.\n"
           "Version 1.0, Build: %s / %s by tenox@ntinternals.net\n\n"
           "Usage: %s [-v] \"\\\\full\\path\\homedir\"\n\n"
           "Assuming that the homedir is same as username\n"
           "Onwer: Modify\nDomain Admins: Full Controll\n"
           "Inheritance: Do not inherit from above, propagate inheritance downwards\n"
           "Recursive: yes\n", __DATE__, __TIME__, argv[0]);
    return 0;
  }

  if(strcmp("-v", argv[1])==0) {
    homedir=argv[2];
    verbose=1;
  } else {
    homedir=argv[1];
    verbose=0;
  }
  
  username=basename(homedir);

  // Find the specified home
  if(!username) {
    printf("ERROR: Username not specified\n");
    return 0;
  }
  
  if(strlen(username)<3) {
    printf("ERROR: Username %s too short\n", username);
    return 0;
  }
  if(strchr(username, '*') || strchr(username, '?')) {
    printf("ERROR: You cant use * or ? in the username\n");
    return 0;
  }
  
  if(verbose) {
    printf("Homedir: %s\nUsername: %s\n", homedir, username);
  }
  
  hFind=FindFirstFile(homedir, &fnd);
  if(hFind==INVALID_HANDLE_VALUE) {
    printf("ERROR: unable to find specified directory %s\n", homedir);
    return 0;
  }
  
  if(fnd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    if(verbose) printf("Found %s, processing ...\n", homedir);
  }
  else {
    printf("ERROR: specified file [%s] is not a directory\n", homedir);
    return 0;
  }
  
  FindClose(hFind);

  ConvertSidToStringSidA = (void *) GetProcAddress(GetModuleHandle("advapi32.dll"), "ConvertSidToStringSidA");
  
  if(GetSid(ADMINGRP, &pSIDAdmin)!=TRUE) {
    printf("ERROR: unable to resolve %s group\n", ADMINGRP);
    return 0;
  }

  if(GetSid(username, &pSIDUser)!=TRUE) {
    printf("ERROR: unable to resolve %s user\n", username);
    return 0;
  }

  // Create ACE and ACL
  ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));
  ea[0].grfAccessPermissions = GENERIC_ALL;
  ea[0].grfAccessMode = SET_ACCESS;
  ea[0].grfInheritance = NO_INHERITANCE | SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  ea[0].Trustee.ptstrName = (LPTSTR) pSIDAdmin;
  ea[1].grfAccessPermissions = GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE | DELETE;
  ea[1].grfAccessMode = SET_ACCESS;
  ea[1].grfInheritance = NO_INHERITANCE | SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  ea[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
  ea[1].Trustee.ptstrName = (LPTSTR) pSIDUser;

  pACL=NULL;
  if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES, ea, NULL, &pACL)){
    printf("ERROR: Failed SetEntriesInAcl\n");
    goto Cleanup;
  }

  // Create an empty ACL so it will only inherit parent ACL
  empACL = (ACL*)LocalAlloc(LPTR, sizeof(ACL));
  if(!InitializeAcl(empACL, sizeof(ACL), ACL_REVISION)) {
    printf("Unable to initialize empty ACL\n");
    goto Cleanup;
  }
  

  // Open a handle to the access token for the calling process.
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
    printf("ERROR: OpenProcessToken failed: %u\n", GetLastError()); 
    goto Cleanup; 
  } 

  // Enable the required privileges.
  if (!SetPrivilege(hToken, SE_RESTORE_NAME, TRUE) || !SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE)) {
      printf("ERROR: You must be logged on as Administrator.\n");
      goto Cleanup; 
  }
  
  changes=1;
  
  if(SetNamedSecurityInfo(homedir, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,  pSIDAdmin, NULL, NULL, NULL)!=ERROR_SUCCESS)
    printf("Unable to Take Ownership of %s\n", homedir);
  if(SetNamedSecurityInfo(homedir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL)!=ERROR_SUCCESS)
    printf("Unable to set ACL of %s\n", homedir);
  if(SetNamedSecurityInfo(homedir, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,  pSIDUser, NULL, NULL, NULL)!=ERROR_SUCCESS)
    printf("Unable to Give Away Ownership of %s\n", homedir);
  
  RecursiveChange(homedir);
  printf("%d objects altered\n", changes);


  // Loose all pivileges
  SetPrivilege(hToken, SE_RESTORE_NAME, FALSE);
  SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE);

  
  Cleanup:
    if (pSIDAdmin)
      FreeSid(pSIDAdmin); 
    if (pACL)
      LocalFree(pACL);
    if (empACL)
      LocalFree(empACL);
    if (hToken)
      CloseHandle(hToken);
  
  return 0;
}

