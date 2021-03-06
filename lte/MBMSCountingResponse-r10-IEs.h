/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "36331-ac0.asn"
 * 	`asn1c -S /home/nyee/srsLTE/srslte/examples/src/asn1c/skeletons -fcompound-names -fskeletons-copy -gen-PER -pdu=auto`
 */

#ifndef	_MBMSCountingResponse_r10_IEs_H_
#define	_MBMSCountingResponse_r10_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CountingResponseList_r10;

/* MBMSCountingResponse-r10-IEs */
typedef struct MBMSCountingResponse_r10_IEs {
	long	*mbsfn_AreaIndex_r10	/* OPTIONAL */;
	struct CountingResponseList_r10	*countingResponseList_r10	/* OPTIONAL */;
	OCTET_STRING_t	*lateNonCriticalExtension	/* OPTIONAL */;
	struct MBMSCountingResponse_r10_IEs__nonCriticalExtension {
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *nonCriticalExtension;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MBMSCountingResponse_r10_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MBMSCountingResponse_r10_IEs;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CountingResponseList-r10.h"

#endif	/* _MBMSCountingResponse_r10_IEs_H_ */
#include <asn_internal.h>
