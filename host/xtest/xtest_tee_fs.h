#ifndef __XTEST_TEE_FS_H__
#define __XTEST_TEE_FS_H__

#ifdef CFG_TEE_FS_SUBPATH
#define TEE_FS_SUBPATH	CFG_TEE_FS_SUBPATH
#else
#define TEE_FS_SUBPATH	"/data"
#endif

#endif /* __XTEST_TEE_FS_H__ */
