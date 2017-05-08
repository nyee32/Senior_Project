#include "converter-sample.h"

int
main(int ac, char *av[]) {
	static asn_TYPE_descriptor_t *pduType = &PDU_Type;
	ssize_t suggested_bufsize = 8192;  /* close or equal to stdio buffer */
	int number_of_iterations = 1;
	int num;
	int ch;

	/* Figure out if Unaligned PER needs to be default */
	if(pduType->uper_decoder)
		iform = INP_PER;

	/*
	 * Pocess the command-line argments.
	 */
	while((ch = getopt(ac, av, "i:o:1b:cdn:p:hs:" JUNKOPT)) != -1)
	switch(ch) {
	case 'i':
		if(optarg[0] == 'b') { iform = INP_BER; break; }
		if(optarg[0] == 'x') { iform = INP_XER; break; }
		if(pduType->uper_decoder
		&& optarg[0] == 'p') { iform = INP_PER; break; }
		fprintf(stderr, "-i<format>: '%s': improper format selector\n",
			optarg);
		exit(EX_UNAVAILABLE);
	case 'o':
		if(optarg[0] == 'd') { oform = OUT_DER; break; }
		if(pduType->uper_encoder
		&& optarg[0] == 'p') { oform = OUT_PER; break; }
		if(optarg[0] == 'x') { oform = OUT_XER; break; }
		if(optarg[0] == 't') { oform = OUT_TEXT; break; }
		if(optarg[0] == 'n') { oform = OUT_NULL; break; }
		fprintf(stderr, "-o<format>: '%s': improper format selector\n",
			optarg);
		exit(EX_UNAVAILABLE);
	case '1':
		opt_onepdu = 1;
		break;
	case 'b':
		suggested_bufsize = atoi(optarg);
		if(suggested_bufsize < 1
			|| suggested_bufsize > 16 * 1024 * 1024) {
			fprintf(stderr,
				"-b %s: Improper buffer size (1..16M)\n",
				optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
	case 'c':
		opt_check = 1;
		break;
	case 'd':
		opt_debug++;	/* Double -dd means ASN.1 debug */
		break;
	case 'n':
		number_of_iterations = atoi(optarg);
		if(number_of_iterations < 1) {
			fprintf(stderr,
				"-n %s: Improper iterations count\n", optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
	case 'p':
		if(strcmp(optarg, "er-nopad") == 0) {
			opt_nopad = 1;
			break;
		}
#ifdef	ASN_PDU_COLLECTION
		if(strcmp(optarg, "list") == 0) {
			asn_TYPE_descriptor_t **pdu = asn_pdu_collection;
			fprintf(stderr, "Available PDU types:\n");
			for(; *pdu; pdu++) printf("%s\n", (*pdu)->name);
			exit(0);
		} else if(optarg[0] >= 'A' && optarg[0] <= 'Z') {
			asn_TYPE_descriptor_t **pdu = asn_pdu_collection;
			while(*pdu && strcmp((*pdu)->name, optarg)) pdu++;
			if(*pdu) { pduType = *pdu; break; }
			fprintf(stderr, "-p %s: Unrecognized PDU\n", optarg);
		}
#endif	/* ASN_PDU_COLLECTION */
		fprintf(stderr, "-p %s: Unrecognized option\n", optarg);
		exit(EX_UNAVAILABLE);
	case 's':
		opt_stack = atoi(optarg);
		if(opt_stack < 0) {
			fprintf(stderr,
				"-s %s: Non-negative value expected\n",
				optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
#ifdef	JUNKTEST
	case 'J':
		opt_jprob = strtod(optarg, 0);
		if(opt_jprob <= 0.0 || opt_jprob > 1.0) {
			fprintf(stderr,
				"-J %s: Probability range 0..1 expected \n",
				optarg);
			exit(EX_UNAVAILABLE);
		}
		break;
#endif	/* JUNKTEST */
	case 'h':
	default:
#ifdef	ASN_CONVERTER_TITLE
#define	_AXS(x)	#x
#define	_ASX(x)	_AXS(x)
		fprintf(stderr, "%s\n", _ASX(ASN_CONVERTER_TITLE));
#endif
		fprintf(stderr, "Usage: %s [options] <data.ber> ...\n", av[0]);
		fprintf(stderr, "Where options are:\n");
		if(pduType->uper_decoder)
		fprintf(stderr,
		"  -iper        Input is in Unaligned PER (Packed Encoding Rules) (DEFAULT)\n");
		fprintf(stderr,
		"  -iber        Input is in BER (Basic Encoding Rules)%s\n",
			iform == INP_PER ? "" : " (DEFAULT)");
		fprintf(stderr,
		"  -ixer        Input is in XER (XML Encoding Rules)\n");
		if(pduType->uper_encoder)
		fprintf(stderr,
		"  -oper        Output in Unaligned PER (Packed Encoding Rules)\n");
		fprintf(stderr,
		"  -oder        Output in DER (Distinguished Encoding Rules)\n"
		"  -oxer        Output in XER (XML Encoding Rules) (DEFAULT)\n"
		"  -otext       Output in plain semi-structured text (dump)\n"
		"  -onull       Verify (decode) input, but do not output\n");
		if(pduType->uper_decoder)
		fprintf(stderr,
		"  -per-nopad   Assume PER PDUs are not padded (-iper)\n");
#ifdef	ASN_PDU_COLLECTION
		fprintf(stderr,
		"  -p <PDU>     Specify PDU type to decode\n"
		"  -p list      List available PDUs\n");
#endif	/* ASN_PDU_COLLECTION */
		fprintf(stderr,
		"  -1           Decode only the first PDU in file\n"
		"  -b <size>    Set the i/o buffer size (default is %ld)\n"
		"  -c           Check ASN.1 constraints after decoding\n"
		"  -d           Enable debugging (-dd is even better)\n"
		"  -n <num>     Process files <num> times\n"
		"  -s <size>    Set the stack usage limit (default is %d)\n"
#ifdef	JUNKTEST
		"  -J <prob>    Set random junk test bit garbaging probability\n"
#endif
		, (long)suggested_bufsize, ASN__DEFAULT_STACK_MAX);
		exit(EX_USAGE);
	}

	ac -= optind;
	av += optind;

	if(ac < 1) {
		fprintf(stderr, "%s: No input files specified. "
				"Try '-h' for more information\n",
				av[-optind]);
		exit(EX_USAGE);
	}

	setvbuf(stdout, 0, _IOLBF, 0);

	for(num = 0; num < number_of_iterations; num++) {
	  int ac_i;
	  /*
	   * Process all files in turn.
	   */
	  for(ac_i = 0; ac_i < ac; ac_i++) {
		asn_enc_rval_t erv;
		void *structure;	/* Decoded structure */
		FILE *file = argument_to_file(av, ac_i);
		char *name = argument_to_name(av, ac_i);
		int first_pdu;

		for(first_pdu = 1; first_pdu || !opt_onepdu; first_pdu = 0) {
		/*
		 * Decode the encoded structure from file.
		 */
		structure = data_decode_from_file(pduType,
				file, name, suggested_bufsize, first_pdu);
		if(!structure) {
			if(errno) {
				/* Error message is already printed */
				exit(EX_DATAERR);
			} else {
				/* EOF */
				break;
			}
		}

		/* Check ASN.1 constraints */
		if(opt_check) {
			char errbuf[128];
			size_t errlen = sizeof(errbuf);
			if(asn_check_constraints(pduType, structure,
				errbuf, &errlen)) {
				fprintf(stderr, "%s: ASN.1 constraint "
					"check failed: %s\n", name, errbuf);
				exit(EX_DATAERR);
			}
		}

		switch(oform) {
		case OUT_NULL:
#ifdef	JUNKTEST
			if(opt_jprob == 0.0)
#endif
			fprintf(stderr, "%s: decoded successfully\n", name);
			break;
		case OUT_TEXT:	/* -otext */
			asn_fprint(stdout, pduType, structure);
			break;
		case OUT_XER:	/* -oxer */
			if(xer_fprint(stdout, pduType, structure)) {
				fprintf(stderr,
					"%s: Cannot convert %s into XML\n",
					name, pduType->name);
				exit(EX_UNAVAILABLE);
			}
			break;
		case OUT_DER:
			erv = der_encode(pduType, structure, write_out, stdout);
			if(erv.encoded < 0) {
				fprintf(stderr,
					"%s: Cannot convert %s into DER\n",
					name, pduType->name);
				exit(EX_UNAVAILABLE);
			}
			DEBUG("Encoded in %ld bytes of DER", (long)erv.encoded);
			break;
		case OUT_PER:
			erv = uper_encode(pduType, structure, write_out, stdout);
			if(erv.encoded < 0) {
				fprintf(stderr,
				"%s: Cannot convert %s into Unaligned PER\n",
					name, pduType->name);
				exit(EX_UNAVAILABLE);
			}
			DEBUG("Encoded in %ld bits of UPER", (long)erv.encoded);
			break;
		}

		ASN_STRUCT_FREE(*pduType, structure);
		}

		if(file && file != stdin)
		fclose(file);
	  }
	}

#ifdef	JUNKTEST
	if(opt_jprob > 0.0) {
		fprintf(stderr, "Junked %f OK (%d/%d)\n",
			opt_jprob, junk_failures, number_of_iterations);
	}
#endif	/* JUNKTEST */

	return 0;
}
