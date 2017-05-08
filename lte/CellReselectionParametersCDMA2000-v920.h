/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "36331-ac0.asn"
 * 	`asn1c -S /home/nyee/srsLTE/srslte/examples/src/asn1c/skeletons -fcompound-names -fskeletons-copy -gen-PER -pdu=auto`
 */

#ifndef	_CellReselectionParametersCDMA2000_v920_H_
#define	_CellReselectionParametersCDMA2000_v920_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NeighCellListCDMA2000-v920.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CellReselectionParametersCDMA2000-v920 */
typedef struct CellReselectionParametersCDMA2000_v920 {
	NeighCellListCDMA2000_v920_t	 neighCellList_v920;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CellReselectionParametersCDMA2000_v920_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CellReselectionParametersCDMA2000_v920;

#ifdef __cplusplus
}
#endif

#endif	/* _CellReselectionParametersCDMA2000_v920_H_ */
#include <asn_internal.h>