/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2019 Joyent, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <fm/libtopo.h>
#include <fm/topo_list.h>
#include <fm/topo_sas.h>
#include <sys/fm/protocol.h>
#include <topo_prop.h>
#include <topo_tree.h>

#define	EXIT_USAGE	2

#define	SAS_INITIATOR_PORT	"SAS Initiator Port"
#define	SAS_EXPANDER_PORT	"SAS Expander Port"
#define	SAS_TARGET_PORT		"SAS Target Port"

#define	SASPORT_INV_DWORD	"invalid-dword"
#define	SASPORT_RUN_DISP	"running-disp-errs"
#define	SASPORT_LOSS_SYNC	"loss-dword-sync"
#define	SASPORT_RESET_PROB	"reset-problems"


static const char *pname;
static const char optstr[] = "Cdf:hl:pR:Vx";

static void
usage()
{
	(void) fprintf(stderr,
	    "Usage:\n\n"
	    "Print all nodes on the SAS fabric:\n"
	    "  %s [-d][-V][-R root][FMRI pattern]\n\n"
	    "Print all the paths between SAS initiators and targets:\n"
	    "  %s -p [-d][-V][-R root][-l location|logical-disk]\n\n"
	    "Dump SAS topology snapshot to XML\n"
	    "  %s -x [-d][-R root]\n\n"
	    "Read in SAS topology snapshot from XML\n"
	    "  %s -f <XML file> [-d][-R root]\n\n"
	    "-C\t\tdump core at exit\n"
	    "-d\t\tenable debug messages\n"
	    "-l\t\tfilter results based on FRU location or target CTD\n"
	    "-h\t\tprint this usage message\n"
	    "-R\t\toperate against alternate root directory\n"
	    "-V\t\tverbose mode\n\n", pname, pname, pname, pname);
}

struct sastopo_vertex {
	topo_list_t link;
	topo_vertex_t *vtx;
};

struct cb_arg {
	topo_list_t ini_list;
	topo_list_t tgt_list;
	boolean_t verbose;
	boolean_t do_paths;
	const char *fmri_pattern;
	const char *location;
};

static int
print_prop_val(topo_hdl_t *thp, tnode_t *tn, topo_propval_t *pv,
    const char *pgname)
{
	topo_type_t type = pv->tp_type;
	const char *pname = pv->tp_name;
	int err;

	switch (type) {
		case TOPO_TYPE_INT32: {
			int32_t val;

			if (topo_prop_get_int32(tn, pgname, pname, &val, &err)
			    != 0)
				return (-1);

			(void) printf("%-10u\n", val);
			break;
		}
		case TOPO_TYPE_UINT32: {
			uint32_t val;

			if (topo_prop_get_uint32(tn, pgname, pname, &val, &err)
			    != 0)
				return (-1);

			(void) printf("%-10d\n", val);
			break;
		}
		case TOPO_TYPE_INT64: {
			int64_t val;

			if (topo_prop_get_int64(tn, pgname, pname, &val, &err)
			    != 0)
				return (-1);

			(void) printf("%-10" PRIi64 "\n", val);
			break;
		}
		case TOPO_TYPE_UINT64: {
			uint64_t val;

			if (topo_prop_get_uint64(tn, pgname, pname, &val, &err)
			    != 0) {
				(void) printf("%s", topo_strerror(err));
				return (-1);
			}

			(void) printf("0x%-10" PRIx64 "\n", val);
			break;
		}
		case TOPO_TYPE_STRING: {
			char *val;

			if (topo_prop_get_string(tn, pgname, pname, &val, &err)
			    != 0)
				return (-1);

			(void) printf("%-10s\n", val);
			topo_hdl_strfree(thp, val);
			break;
		}
		case TOPO_TYPE_FMRI: {
			nvlist_t *nvl;
			char *fmri;

			if (topo_prop_get_fmri(tn, pgname, pname, &nvl, &err)
			    != 0)
				return (-1);

			if (topo_fmri_nvl2str(thp, nvl, &fmri, &err) != 0) {
				nvlist_print(stdout, nvl);
				break;
			}
			(void) printf("%10s\n", fmri);
			topo_hdl_strfree(thp, fmri);
			nvlist_free(nvl);
			break;
		}
		case TOPO_TYPE_INT32_ARRAY: {
			uint_t nelem;
			int32_t *val;

			if (topo_prop_get_int32_array(tn, pgname, pname, &val,
			    &nelem, &err) != 0)
				return (-1);

			(void) printf(" [ ");
			for (uint_t i = 0; i < nelem; i++)
				(void) printf("%d ", val[i]);

			(void) printf("]\n");

			topo_hdl_free(thp, val, nelem * sizeof (int32_t));
			break;
		}
		case TOPO_TYPE_UINT32_ARRAY: {
			uint_t nelem;
			uint32_t *val;

			if (topo_prop_get_uint32_array(tn, pgname, pname, &val,
			    &nelem, &err) != 0)
				return (-1);

			(void) printf(" [ ");
			for (uint_t i = 0; i < nelem; i++)
				(void) printf("%u ", val[i]);
			(void) printf("]\n");

			topo_hdl_free(thp, val, nelem * sizeof (uint32_t));
			break;
		}
		case TOPO_TYPE_INT64_ARRAY: {
			uint_t nelem;
			int64_t *val;

			if (topo_prop_get_int64_array(tn, pgname, pname, &val,
			    &nelem, &err) != 0)
				return (-1);

			(void) printf(" [ ");
			for (uint_t i = 0; i < nelem; i++)
				(void) printf("%" PRIi64 " ", val[i]);
			(void) printf("]\n");

			topo_hdl_free(thp, val, nelem * sizeof (int64_t));
			break;
		}
		case TOPO_TYPE_UINT64_ARRAY: {
			uint_t nelem;
			uint64_t *val;

			if (topo_prop_get_uint64_array(tn, pgname, pname, &val,
			    &nelem, &err) != 0)
				return (-1);

			(void) printf(" [ ");
			for (uint_t i = 0; i < nelem; i++)
				(void) printf("0x%" PRIx64 " ", val[i]);
			(void) printf("]\n");

			topo_hdl_free(thp, val, nelem * sizeof (uint64_t));
			break;
		}
		case TOPO_TYPE_STRING_ARRAY: {
			uint_t nelem;
			char **val;

			if (topo_prop_get_string_array(tn, pgname, pname, &val,
			    &nelem, &err) != 0)
				return (-1);

			(void) printf(" [ ");
			for (uint_t i = 0; i < nelem; i++)
				(void) printf("\"%s\" ", val[i]);
			(void) printf("]\n");

			topo_hdl_strfreev(thp, val, nelem);
			break;
		}
		default:
			(void) fprintf(stderr, "Invalid nvpair data type: %d\n",
			    type);
			return (-1);
	}
	return (0);
}

static void
print_node_props(topo_hdl_t *thp, tnode_t *tn)
{
	topo_pgroup_t *pg;

	for (pg = topo_list_next(&tn->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {

		topo_proplist_t *pvl;

		(void) printf("  %-8s: %s\n",  "group", pg->tpg_info->tpi_name);

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl)) {

			topo_propval_t *pv = pvl->tp_pval;
			char *tstr;

			switch (pv->tp_type) {
			case TOPO_TYPE_BOOLEAN: tstr = "boolean"; break;
			case TOPO_TYPE_INT32: tstr = "int32"; break;
			case TOPO_TYPE_UINT32: tstr = "uint32"; break;
			case TOPO_TYPE_INT64: tstr = "int64"; break;
			case TOPO_TYPE_UINT64: tstr = "uint64"; break;
			case TOPO_TYPE_DOUBLE: tstr = "double"; break;
			case TOPO_TYPE_STRING: tstr = "string"; break;
			case TOPO_TYPE_FMRI: tstr = "fmri"; break;
			case TOPO_TYPE_INT32_ARRAY: tstr = "int32[]"; break;
			case TOPO_TYPE_UINT32_ARRAY: tstr = "uint32[]"; break;
			case TOPO_TYPE_INT64_ARRAY: tstr = "int64[]"; break;
			case TOPO_TYPE_UINT64_ARRAY: tstr = "uint64[]"; break;
			case TOPO_TYPE_STRING_ARRAY: tstr = "string[]"; break;
			case TOPO_TYPE_FMRI_ARRAY: tstr = "fmri[]"; break;
			default: tstr = "unknown type";
			}

			(void) printf("    %-20s %-10s", pv->tp_name, tstr);

			if (print_prop_val(thp, tn, pv, pg->tpg_info->tpi_name)
			    != 0) {
				(void) printf("failed to get prop val!\n");
			}
		}
	}
	(void) printf("\n");
}

static void
print_vertex(topo_hdl_t *thp, topo_vertex_t *vtx, struct cb_arg *cbarg)
{
	tnode_t *tn;
	nvlist_t *fmri = NULL;
	char *fmristr = NULL;
	int err;

	/*
	 * Generate a string representation of the FMRI.
	 */
	tn = topo_vertex_node(vtx);
	if (topo_node_resource(tn, &fmri, &err) != 0 ||
	    topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0) {
		(void) fprintf(stderr, "failed to convert FMRI for %s=%"
		    PRIx64 " to a string\n", topo_node_name(tn),
		    topo_node_instance(tn));
		nvlist_print(stderr, fmri);
		goto out;
	}

	/*
	 * If an FMRI pattern was specified on the command line, then check if
	 * this node matches that pattern.  If not, skip printing it.
	 */
	if (cbarg->fmri_pattern != NULL &&
	    fnmatch(cbarg->fmri_pattern, fmristr, 0) != 0) {
		goto out;
	}

	(void) printf("%s\n", fmristr);
	if (cbarg->verbose)
		print_node_props(thp, tn);
out:
	topo_hdl_strfree(thp, fmristr);
	nvlist_free(fmri);
}

static void
print_path_port(topo_hdl_t *thp, tnode_t *tn)
{
	uint64_t *invdword = NULL, *rundisp = NULL, *losssync = NULL;
	uint64_t *resetprob = NULL;
	nvlist_t *fmri = NULL, *auth;
	uint32_t start_phy, end_phy;
	uint_t nphys, phy, idx;
	int err;

	if (topo_prop_get_uint64_array(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_INV_DWORD, &invdword, &nphys, &err) != 0 ||
	    topo_prop_get_uint64_array(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_RUN_DISP, &rundisp, &nphys, &err) != 0 ||
	    topo_prop_get_uint64_array(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_LOSS_SYNC, &losssync, &nphys, &err) != 0 ||
	    topo_prop_get_uint64_array(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_RESET_PROB, &resetprob, &nphys, &err) != 0) {
		(void) printf("prop lookup failed\n");
		goto err;
	}

	/*
	 * Get the SAS FMRI and then lookup the authority portion in order to
	 * get the start and end PHY numbers.
	 */
	if (topo_node_resource(tn, &fmri, &err) != 0) {
		(void) printf("failed to get SAS FMRI\n");
		goto err;
	}
	if (nvlist_lookup_nvlist(fmri, FM_FMRI_AUTHORITY, &auth) != 0 ||
	    nvlist_lookup_uint32(auth, FM_FMRI_SAS_START_PHY, &start_phy) !=
	    0 ||
	    nvlist_lookup_uint32(auth, FM_FMRI_SAS_END_PHY, &end_phy) != 0) {
		(void) printf("malformed FMRI authority\n");
		goto err;
	}
	(void) printf("  PHY Error Counters:\n");
	(void) printf("  %-5s %-20s %-20s %-20s %-20s\n", "PHY#",
	    SASPORT_INV_DWORD, SASPORT_RUN_DISP, SASPORT_LOSS_SYNC,
	    SASPORT_RESET_PROB);
	for (phy = start_phy, idx = 0; phy <= end_phy; phy++, idx++) {
		(void) printf("  %-5u %-20" PRIu64 " %-20" PRIu64 " %-20"
		    PRIu64 " %-20" PRIu64 "\n", phy, invdword[idx],
		    rundisp[idx], losssync[idx], resetprob[idx]);
	}
	(void) printf("\n");

err:
	nvlist_free(fmri);
	if (invdword != NULL) {
		topo_hdl_free(thp, invdword, sizeof (uint64_t) * nphys);
	}
	if (rundisp != NULL) {
		topo_hdl_free(thp, rundisp, sizeof (uint64_t) * nphys);
	}
	if (losssync != NULL) {
		topo_hdl_free(thp, losssync, sizeof (uint64_t) * nphys);
	}
	if (resetprob != NULL) {
		topo_hdl_free(thp, resetprob, sizeof (uint64_t) * nphys);
	}
}

/*
 * This function returns B_TRUE if either the initiator or the target node in
 * the specified path has a location value that matches the one passed in.  For
 * target nodes, the "location" can either be the FRU location (label) or the
 * logical disk name (i.e. c#t#d#).  It returns B_FALSE if there is none of the
 * nodes match or if an error is encountered.
 */
static boolean_t
path_matches_location(topo_hdl_t *thp, topo_path_t *path, const char *location)
{
	topo_path_component_t *comp;
	boolean_t ret = B_FALSE;
	char *pval1, *pval2;

	for (comp = topo_list_next(&path->tsp_components); comp != NULL;
	    comp = topo_list_next(comp)) {

		topo_vertex_t *vtx = comp->tspc_vertex;
		tnode_t *tn = topo_vertex_node(vtx);
		char *name = topo_node_name(tn);
		int err, r;

		pval1 = pval2 = NULL;

		if (strcmp(name, TOPO_VTX_EXPANDER) == 0 ||
		    strcmp(name, TOPO_VTX_PORT) == 0) {
			continue;
		} else if (strcmp(name, TOPO_VTX_INITIATOR) == 0) {
			r = topo_prop_get_string(tn, TOPO_PGROUP_INITIATOR,
			    TOPO_PROP_INITIATOR_LABEL, &pval1, &err);
		} else if (strcmp(name, TOPO_VTX_TARGET) == 0) {
			r = topo_prop_get_string(tn, TOPO_PGROUP_TARGET,
			    TOPO_PROP_TARGET_LABEL, &pval1, &err);
			r += topo_prop_get_string(tn, TOPO_PGROUP_TARGET,
			    TOPO_PROP_TARGET_LOGICAL_DISK, &pval2, &err);
		} else {
			goto out;
		}

		if (r != 0) {
			(void) fprintf(stderr, "fail to lookup up prop on %s=%"
			    PRIx64 " (%s)\n", name, topo_node_instance(tn),
			    topo_strerror(err));
			goto out;
		}

		if (strcasecmp(pval1, location) == 0 ||
		    (pval2 != NULL && strcasecmp(pval2, location) == 0)) {
			ret = B_TRUE;
			goto out;
		}
		topo_hdl_strfree(thp, pval1);
		topo_hdl_strfree(thp, pval2);
	}
	return (ret);

out:
	topo_hdl_strfree(thp, pval1);
	topo_hdl_strfree(thp, pval2);
	return (ret);
}

static void
print_path(topo_hdl_t *thp, topo_path_t *path, struct cb_arg *cbarg)
{
	topo_path_component_t *comp, *prev_comp = NULL;

	if (cbarg->location != NULL &&
	    ! path_matches_location(thp, path, cbarg->location))
		return;

	(void) printf("%s\n", path->tsp_fmristr);

	if (! cbarg->verbose)
		return;

	for (comp = topo_list_next(&path->tsp_components); comp != NULL;
	    prev_comp = comp, comp = topo_list_next(comp)) {

		topo_path_component_t *next_comp;
		topo_vertex_t *vtx = comp->tspc_vertex;
		tnode_t *tn = topo_vertex_node(vtx);
		char *name = topo_node_name(tn);
		int err;

		(void) printf("\n");
		next_comp = topo_list_next(comp);

		if (strcmp(name, TOPO_VTX_INITIATOR) == 0) {
			char *location = NULL, *manuf = NULL, *model = NULL;

			(void) topo_prop_get_string(tn, TOPO_PGROUP_INITIATOR,
			    TOPO_PROP_INITIATOR_LABEL, &location, &err);
			(void) topo_prop_get_string(tn, TOPO_PGROUP_INITIATOR,
			    TOPO_PROP_INITIATOR_MANUF, &manuf, &err);
			(void) topo_prop_get_string(tn, TOPO_PGROUP_INITIATOR,
			    TOPO_PROP_INITIATOR_MODEL, &model, &err);

			(void) printf("  %-20s %s\n", "Node Type:",
			    "SAS Initiator");
			(void) printf("  %-20s %s\n", "Location:",
			    location ? location : "Unknown");
			(void) printf("  %-20s %s\n", "Manufacturer:",
			    manuf ? manuf : "Unknown");
			(void) printf("  %-20s %s\n", "Model:",
			    model ? model : "Unknown");
			(void) printf("\n");

			topo_hdl_strfree(thp, location);
			topo_hdl_strfree(thp, manuf);
			topo_hdl_strfree(thp, model);

		} else if (strcmp(name, TOPO_VTX_PORT) == 0) {
			tnode_t *prev_node =
			    topo_vertex_node(prev_comp->tspc_vertex);
			char *prev_name = topo_node_name(prev_node);
			tnode_t *next_node =
			    topo_vertex_node(next_comp->tspc_vertex);
			char *next_name = topo_node_name(next_node);

			/*
			 * We look at the previous and next components in the
			 * path to determine the type of SAS port.
			 */
			if (strcmp(prev_name, TOPO_VTX_INITIATOR) == 0) {
				(void) printf("  %-20s %s\n", "Node Type:",
				    SAS_INITIATOR_PORT);
			} else if (strcmp(prev_name, TOPO_VTX_EXPANDER) == 0) {
				(void) printf("  %-20s %s\n", "Node Type:",
				    SAS_EXPANDER_PORT);
			} else if (strcmp(prev_name, TOPO_VTX_PORT) == 0) {
				if (strcmp(next_name, TOPO_VTX_EXPANDER) == 0) {
					(void) printf("  %-20s %s\n",
					    "Node Type:", SAS_EXPANDER_PORT);
				} else if (strcmp(next_name, TOPO_VTX_TARGET)
				    == 0) {
					(void) printf("  %-20s %s\n",
					    "Node Type:", SAS_TARGET_PORT);
				}
			}

			print_path_port(thp, tn);
		} else if (strcmp(name, TOPO_VTX_EXPANDER) == 0) {
			char *manuf = NULL, *model = NULL;

			(void) topo_prop_get_string(tn, TOPO_PGROUP_EXPANDER,
			    TOPO_PROP_EXPANDER_MANUF, &manuf, &err);
			(void) topo_prop_get_string(tn, TOPO_PGROUP_EXPANDER,
			    TOPO_PROP_EXPANDER_MODEL, &model, &err);

			(void) printf("  %-20s %s\n", "Node Type:",
			    "SAS Expander");
			(void) printf("  %-20s %s\n", "Manufacturer:",
			    manuf ? manuf : "Unknown");
			(void) printf("  %-20s %s\n", "Model:",
			    model ? model : "Unknown");
			(void) printf("\n");

			topo_hdl_strfree(thp, manuf);
			topo_hdl_strfree(thp, model);
		} else if (strcmp(name, TOPO_VTX_TARGET) == 0) {
			char *location = NULL, *manuf = NULL, *model = NULL;
			char *ctdname = NULL;

			(void) topo_prop_get_string(tn, TOPO_PGROUP_TARGET,
			    TOPO_PROP_TARGET_LABEL, &location, &err);
			(void) topo_prop_get_string(tn, TOPO_PGROUP_TARGET,
			    TOPO_PROP_TARGET_LOGICAL_DISK, &ctdname, &err);
			(void) topo_prop_get_string(tn, TOPO_PGROUP_TARGET,
			    TOPO_PROP_TARGET_MANUF, &manuf, &err);
			(void) topo_prop_get_string(tn, TOPO_PGROUP_TARGET,
			    TOPO_PROP_TARGET_MODEL, &model, &err);

			(void) printf("  %-20s %s\n", "Node Type:",
			    "SAS Target");
			(void) printf("  %-20s %s\n", "Location:",
			    location ? location : "Unknown");
			(void) printf("  %-20s %s\n", "Logical Disk:",
			    ctdname ? ctdname : "Unknown");
			(void) printf("  %-20s %s\n", "Manufacturer:",
			    manuf ? manuf : "Unknown");
			(void) printf("  %-20s %s\n", "Model:",
			    model ? model : "Unknown");
			(void) printf("\n");

			topo_hdl_strfree(thp, location);
			topo_hdl_strfree(thp, ctdname);
			topo_hdl_strfree(thp, manuf);
			topo_hdl_strfree(thp, model);
		}
	}
	(void) printf("\n");
}

static int
vertex_cb(topo_hdl_t *thp, topo_vertex_t *vtx, boolean_t last_vtx,
    void *arg)
{
	struct cb_arg *cbarg = arg;
	tnode_t *tn = topo_vertex_node(vtx);
	struct sastopo_vertex *sasvtx;

	if (!cbarg->do_paths)
		print_vertex(thp, vtx, cbarg);

	if (strcmp(topo_node_name(tn), TOPO_VTX_INITIATOR) != 0 &&
	    strcmp(topo_node_name(tn), TOPO_VTX_TARGET) != 0) {
		return (TOPO_WALK_NEXT);
	}
	if ((sasvtx = topo_hdl_zalloc(thp,
	    sizeof (struct sastopo_vertex))) == NULL) {
		return (TOPO_WALK_ERR);
	}
	sasvtx->vtx = vtx;

	if (strcmp(topo_node_name(tn), TOPO_VTX_INITIATOR) == 0) {
		topo_list_append(&cbarg->ini_list, sasvtx);
	} else if (strcmp(topo_node_name(tn), TOPO_VTX_TARGET) == 0) {
		topo_list_append(&cbarg->tgt_list, sasvtx);
	}
	return (TOPO_WALK_NEXT);
}

int
main(int argc, char *argv[])
{
	topo_hdl_t *thp = NULL;
	topo_digraph_t *tdg;
	char c, *root = "/", *xml_in = NULL, *buf, *snapuuid = NULL;
	boolean_t debug = B_FALSE, xml_out = B_FALSE;
	int err, fd, status = EXIT_FAILURE;
	struct stat statbuf = { 0 };
	struct cb_arg cbarg = { 0 };
	struct sastopo_vertex *ini, *tgt;

	pname = argv[0];

	if (getuid() != 0) {
		(void) fprintf(stderr, "This program must be run as root.\n");
		return (EXIT_FAILURE);
	}

	while (optind < argc) {
		while ((c = getopt(argc, argv, optstr)) != -1) {
			switch (c) {
			case 'C':
				(void) atexit(abort);
				break;
			case 'd':
				debug = B_TRUE;
				break;
			case 'f':
				xml_in = optarg;
				break;
			case 'h':
				usage();
				return (EXIT_USAGE);
			case 'p':
				cbarg.do_paths = B_TRUE;
				break;
			case 'l':
				cbarg.location = optarg;
				break;
			case 'R':
				root = optarg;
				break;
			case 'V':
				cbarg.verbose = B_TRUE;
				break;
			case 'x':
				xml_out = B_TRUE;
				break;
			default:
				usage();
				return (EXIT_USAGE);
			}
		}
		if (optind < argc) {
			if (cbarg.fmri_pattern != NULL) {
				usage();
				return (EXIT_USAGE);
			} else {
				cbarg.fmri_pattern = argv[optind++];
			}
		}
	}

	if (xml_out && cbarg.do_paths) {
		(void) fprintf(stderr, "-x and -p are mutually exclusive\n");
		usage();
		return (EXIT_USAGE);
	}

	if (debug) {
		if (putenv("TOPOSASDEBUG=1") != 0) {
			(void) fprintf(stderr, "Failed to set debug mode: "
			    "%s\n", strerror(errno));
			goto out;
		}
	}
	/*
	 * If we're loading in a serialized snapshot, then we need to tell the
	 * sas module not to construct a snapshot.  The tmo_enum entry
	 * point in the sas module will check for this environment variable
	 * and if found it will skip enumerating the actual SAS fabric.
	 */
	if (xml_in != NULL) {
		if (putenv("TOPO_SASNOENUM=1") != 0) {
			(void) fprintf(stderr, "Failed to set xml_in mode: "
			    "%s\n", strerror(errno));
			goto out;
		}
	}
	if ((thp = topo_open(TOPO_VERSION, root, &err)) == NULL) {
		(void) fprintf(stderr, "failed to get topo handle: %s\n",
		    topo_strerror(err));
		goto out;
	}
	if (debug)
		topo_debug_set(thp, "module", "stderr");

	if ((snapuuid = topo_snap_hold(thp, NULL, &err)) == NULL) {
		(void) fprintf(stderr, "failed to take topo snapshot: %s\n",
		    topo_strerror(err));
		goto out;
	}

	/*
	 * Either get a pointer to a rehydrated "sas" scheme digraph or get a
	 * pointer to the live "sas" scheme digraph.
	 */
	if (xml_in != NULL) {
		if ((fd = open(xml_in, O_RDONLY)) < 0) {
			(void) fprintf(stderr, "failed to open %s (%s)\n",
			    xml_in, strerror(errno));
			goto out;
		}
		if (fstat(fd, &statbuf) != 0) {
			(void) fprintf(stderr, "failed to stat %s (%s)\n",
			    xml_in, strerror(errno));
			(void) close(fd);
			goto out;
		}
		if ((buf = malloc(statbuf.st_size)) == NULL) {
			(void) fprintf(stderr, "failed to alloc read buffer: "
			    "(%s)\n", strerror(errno));
			(void) close(fd);
			goto out;
		}
		if (read(fd, buf, statbuf.st_size) != statbuf.st_size) {
			(void) fprintf(stderr, "failed to read file: "
			    "(%s)\n", strerror(errno));
			(void) close(fd);
			free(buf);
			goto out;
		}
		(void) close(fd);

		tdg = topo_digraph_deserialize(thp, buf, statbuf.st_size);
		free(buf);
	} else {
		tdg = topo_digraph_get(thp, FM_FMRI_SCHEME_SAS);
	}

	if (tdg == NULL) {
		(void) fprintf(stderr, "failed to get sas scheme digraph\n");
		goto out;
	}

	/*
	 * If -x was passed then we're just going to dump the serialized (XML)
	 * snapshot of the SAS topology and then exit.
	 */
	if (xml_out) {
		if (topo_digraph_serialize(thp, tdg, stdout) == 0)
			status = EXIT_SUCCESS;
		else
			(void) fprintf(stderr, "failed to serialize "
			    "topology\n");

		goto out;
	}

	/*
	 * Iterate through and print all of the vertices.  While iterating we
	 * also generate a list of initiators and a list of targets.
	 */
	if (topo_vertex_iter(thp, tdg, vertex_cb, &cbarg) != 0) {
		(void) fprintf(stderr, "failed to iterate vertices\n");
		goto out;
	}

	/*
	 * If -p was not specified in, then we're done.
	 */
	if (!cbarg.do_paths) {
		status = EXIT_SUCCESS;
		goto out;
	}

	/*
	 * If -p was specified, find and print all unique paths between the
	 * initiators and targets.
	 */
	for (ini = topo_list_next(&cbarg.ini_list); ini != NULL;
	    ini = topo_list_next(ini)) {
		for (tgt = topo_list_next(&cbarg.tgt_list); tgt != NULL;
		    tgt = topo_list_next(tgt)) {
			uint_t np;
			topo_path_t **paths;

			if (topo_digraph_paths(thp, tdg, ini->vtx, tgt->vtx,
			    &paths, &np) < 0) {
				(void) fprintf(stderr, "topo_digraph_paths "
				    "failed!\n");
				goto out;
			} else if (np == 0) {
				tnode_t *ti, *tt;

				ti = topo_vertex_node(ini->vtx);
				tt = topo_vertex_node(tgt->vtx);
				if (debug) {
					(void) fprintf(stderr, "failed to find "
					    "path between initiator=%" PRIx64
					    " and target=%" PRIx64 "\n",
					    topo_node_instance(ti),
					    topo_node_instance(tt));
				}
				continue;
			}
			for (uint_t i = 0; i < np; i++) {
				print_path(thp, paths[i], &cbarg);
				topo_path_destroy(thp, paths[i]);
			}
			topo_hdl_free(thp, paths, np * sizeof (topo_path_t *));
		}
	}
	ini = topo_list_next(&cbarg.ini_list);
	while (ini != NULL) {
		struct sastopo_vertex *tmp = ini;

		ini = topo_list_next(ini);
		topo_hdl_free(thp, tmp, sizeof (struct sastopo_vertex));
	}
	tgt = topo_list_next(&cbarg.tgt_list);
	while (tgt != NULL) {
		struct sastopo_vertex *tmp = tgt;

		tgt = topo_list_next(tgt);
		topo_hdl_free(thp, tmp, sizeof (struct sastopo_vertex));
	}
	status = EXIT_SUCCESS;

out:
	if (thp != NULL)  {
		topo_hdl_strfree(thp, snapuuid);
		topo_snap_release(thp);
		topo_close(thp);
	}
	return (status);
}
